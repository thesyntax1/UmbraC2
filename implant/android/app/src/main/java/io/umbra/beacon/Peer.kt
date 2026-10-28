package io.umbra.beacon

import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * The peer link: one beacon carrying a pivot for another.
 *
 * The link is a handshake, a key exchange and then the ordinary umbra
 * session, carried over a byte stream.  The messages of the handshake are
 * not umbra frames: the peer link runs over a stream that may be a tunnel,
 * a pipe or a socket, so they are length prefixed maps.
 *
 * ```
 * peer hello   {id, pub, nonce, mac}
 * peer ack     {id, pub, nonce, mac}
 * ```
 *
 * The hello proves that the sender owns the pre-shared key and the key it
 * claims.  The answer proves the same for the other side and covers *both*
 * hellos, so the transcript cannot be rearranged and neither half can be
 * replayed into another link.
 *
 * After the handshake the frames are the ordinary ones: a pivot stream is
 * asked for with `TUNNEL_OPEN` and the bytes travel in `TUNNEL_DATA`.  The
 * link rekeys on its own when it carried enough frames, so it does not
 * depend on the server to stay alive.
 */
object Peer {
    /** The largest handshake message that is accepted. */
    const val MAX_FRAME = 4096

    /** How long the peer waits for the target to accept. */
    private const val CONNECT_TIMEOUT = 15000

    /**
     * The tag of a peer hello.
     *
     * It binds the identity to the key and the nonce of the sender, so a
     * hello cannot be replayed into another link.
     */
    fun helloMac(psk: ByteArray, id: String, pub: ByteArray, nonce: ByteArray): ByteArray {
        val msg = "umbra/v1/p2p/hello".toByteArray() + id.toByteArray() + pub + nonce
        return Crypto.hmacSha256(psk, msg)
    }

    /**
     * The tag of the answer.
     *
     * It covers both hellos: the transcript cannot be rearranged, and the
     * answer cannot be replayed into another link.
     */
    fun ackMac(
        psk: ByteArray,
        helloId: String,
        helloPub: ByteArray,
        helloNonce: ByteArray,
        ackId: String,
        ackPub: ByteArray,
        ackNonce: ByteArray,
    ): ByteArray {
        val msg = "umbra/v1/p2p/ack".toByteArray() +
            helloId.toByteArray() + helloPub + helloNonce +
            ackId.toByteArray() + ackPub + ackNonce
        return Crypto.hmacSha256(psk, msg)
    }

    /** Write one length prefixed handshake message. */
    private fun writePeer(output: OutputStream, payload: ByteArray) {
        if (payload.isEmpty() || payload.size > MAX_FRAME) {
            throw SessionException("the peer hello has a bad size")
        }
        val head = ByteArray(4)
        val size = payload.size
        head[0] = ((size ushr 24) and 0xff).toByte()
        head[1] = ((size ushr 16) and 0xff).toByte()
        head[2] = ((size ushr 8) and 0xff).toByte()
        head[3] = (size and 0xff).toByte()
        output.write(head)
        output.write(payload)
        output.flush()
    }

    /** Read one length prefixed handshake message. */
    private fun readPeer(input: InputStream): Upk {
        val head = ByteArray(4)
        var read = 0
        while (read < 4) {
            val n = input.read(head, read, 4 - read)
            if (n < 0) throw SessionException("the peer closed the link during the handshake")
            read += n
        }
        val size = ((head[0].toInt() and 0xff) shl 24) or
            ((head[1].toInt() and 0xff) shl 16) or
            ((head[2].toInt() and 0xff) shl 8) or
            (head[3].toInt() and 0xff)
        if (size <= 0 || size > MAX_FRAME) {
            throw SessionException("the peer hello has a bad size")
        }
        val payload = ByteArray(size)
        var got = 0
        while (got < size) {
            val n = input.read(payload, got, size - got)
            if (n < 0) throw SessionException("the peer closed the link during the handshake")
            got += n
        }
        return Upk.decode(payload)
    }

    /** One half of the peer handshake. */
    private class Hello(val id: String, val pub: ByteArray, val nonce: ByteArray, val mac: ByteArray)

    private fun helloFrom(value: Upk): Hello {
        val id = value.field("id")?.text() ?: ""
        val pub = value.field("pub")?.bytes() ?: ByteArray(0)
        val nonce = value.field("nonce")?.bytes() ?: ByteArray(0)
        val mac = value.field("mac")?.bytes() ?: ByteArray(0)
        if (id.isEmpty() || pub.size != 32 || nonce.size != 16 || mac.size != 32) {
            throw SessionException("malformed peer hello")
        }
        return Hello(id, pub, nonce, mac)
    }

    private fun helloMap(hello: Hello): Upk = Upk.map(
        "id" to Upk.str(hello.id),
        "pub" to Upk.bin(hello.pub),
        "nonce" to Upk.bin(hello.nonce),
        "mac" to Upk.bin(hello.mac),
    )

    /**
     * Play the initiator of a peer link.
     *
     * The initiator speaks first.  Both sides derive the same session keys:
     * the shared secret of the exchange is mixed with the pre-shared key,
     * so the link is only as good as the key both beacons already hold.
     */
    fun connectPeer(
        host: String,
        port: Int,
        psk: ByteArray,
        agentId: String,
        log: (String) -> Unit,
    ) {
        val socket = Socket()
        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)
        socket.tcpNoDelay = true
        val input = BufferedInputStream(socket.getInputStream())
        val output = socket.getOutputStream()
        try {
            val ephemeral = Crypto.x25519Keypair()
            val nonce = Crypto.random(16)
            val hello = Hello(
                agentId, ephemeral.publicRaw, nonce,
                helloMac(psk, agentId, ephemeral.publicRaw, nonce),
            )
            writePeer(output, Upk.encode(helloMap(hello)))

            val ack = helloFrom(readPeer(input))
            val want = ackMac(
                psk, hello.id, hello.pub, hello.nonce, ack.id, ack.pub, ack.nonce,
            )
            if (!Crypto.ctEq(want, ack.mac)) {
                throw SessionException("the peer did not authenticate the transcript")
            }
            val shared = Crypto.x25519Shared(ephemeral.privateKey, ack.pub)
            val mixed = Crypto.hmacSha256(psk, shared)
            val (prk, km) = Crypto.deriveSession(mixed, nonce, ack.nonce)
            val session = Session(
                Wire.SUITE_AES256_GCM, isServer = false, bootstrap = false, material = km, prk = prk,
            )
            log("peer link open to ${Addr.hostPort(host, port)}")
            Tunnel.serveSession(session, input, output, log)
        } finally {
            try {
                socket.close()
            } catch (_: Throwable) {
            }
        }
    }

    /**
     * Play the responder of a peer link.
     *
     * The responder checks the hello before it answers: a stranger that
     * does not hold the key gets nothing.
     */
    fun acceptPeer(socket: Socket, psk: ByteArray, agentId: String, log: (String) -> Unit) {
        val input = BufferedInputStream(socket.getInputStream())
        val output = socket.getOutputStream()
        val hello = helloFrom(readPeer(input))
        val want = helloMac(psk, hello.id, hello.pub, hello.nonce)
        if (!Crypto.ctEq(want, hello.mac)) {
            throw SessionException("the peer did not authenticate")
        }
        val ephemeral = Crypto.x25519Keypair()
        val nonce = Crypto.random(16)
        val ack = Hello(
            agentId, ephemeral.publicRaw, nonce,
            ackMac(
                psk, hello.id, hello.pub, hello.nonce,
                agentId, ephemeral.publicRaw, nonce,
            ),
        )
        writePeer(output, Upk.encode(helloMap(ack)))

        val shared = Crypto.x25519Shared(ephemeral.privateKey, hello.pub)
        val mixed = Crypto.hmacSha256(psk, shared)
        val (prk, km) = Crypto.deriveSession(mixed, hello.nonce, nonce)
        val session = Session(
            Wire.SUITE_AES256_GCM, isServer = true, bootstrap = false, material = km, prk = prk,
        )
        log("peer link accepted from ${hello.id}")
        Tunnel.serveSession(session, input, output, log)
    }

    /**
     * Listen for peer connections and report the address that waits.
     *
     * The address travels in the handshake with the server: the operator
     * can then chain a pivot through this host.
     */
    fun listenPeer(bind: String, psk: ByteArray, agentId: String, log: (String) -> Unit): String {
        val server = ServerSocket()
        // The address may be an IPv6 literal in brackets: it is split
        // apart by the same rule the other implementations use.
        val (host, port) = Addr.splitHostPort(bind)
        server.reuseAddress = true
        server.bind(InetSocketAddress(host, port))
        // Android's ServerSocket knows the address it is bound to as
        // "inetAddress"; the JDK spelling ("localAddress") does not exist
        // in the platform library the phone compiles against.
        val address = Addr.hostPort(server.inetAddress?.hostAddress ?: host, server.localPort)
        log("peer listener on $address")
        val thread = Thread({
            while (true) {
                val socket = try {
                    server.accept()
                } catch (t: Throwable) {
                    continue
                }
                val worker = Thread({
                    try {
                        acceptPeer(socket, psk, agentId, log)
                    } catch (t: Throwable) {
                        log("the peer link failed: ${t.message}")
                    } finally {
                        try {
                            socket.close()
                        } catch (_: Throwable) {
                        }
                    }
                }, "umbra-peer")
                worker.isDaemon = true
                worker.start()
            }
        }, "umbra-peer-listener")
        thread.isDaemon = true
        thread.start()
        return address
    }
}
