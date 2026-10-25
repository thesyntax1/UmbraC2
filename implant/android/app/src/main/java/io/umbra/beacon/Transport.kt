package io.umbra.beacon

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/** A transport carries whole umbra/v1 frames. */
interface Channel {
    fun writeFrame(frame: ByteArray)
    fun readFrame(): ByteArray
    fun flush() {}
    fun close()
    fun setSessionId(sid: String) {}
}

/** Plain TCP: one connection per beacon cycle. */
class TcpChannel(private val host: String, private val port: Int) : Channel {
    private var socket: Socket? = null
    private var out: java.io.OutputStream? = null
    private var input: java.io.InputStream? = null

    fun connect() {
        val s = Socket()
        s.connect(InetSocketAddress(host, port), 15000)
        s.soTimeout = 60000
        s.tcpNoDelay = true
        socket = s
        out = s.getOutputStream()
        input = BufferedInputStream(s.getInputStream())
    }

    override fun writeFrame(frame: ByteArray) {
        val o = out ?: throw TransportException("tcp not connected")
        Wire.writeFrame(o, frame)
    }

    override fun readFrame(): ByteArray {
        val i = input ?: throw TransportException("tcp not connected")
        return Wire.readFrame(i)
    }

    override fun close() {
        try {
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        out = null
        input = null
    }
}

/** HTTP beacon: frames travel inside POST bodies. */
class HttpChannel(
    private val baseUrl: String,
    private val path: String,
) : Channel {
    private var sid: String? = null
    private val pending = ArrayDeque<ByteArray>()
    private val outBuf = ByteArrayOutputStream()

    override fun writeFrame(frame: ByteArray) {
        outBuf.write(frame)
    }

    override fun readFrame(): ByteArray {
        if (pending.isEmpty()) {
            // An empty POST would be rejected by the server, so fail loudly
            // instead of stalling on a request that can never be answered.
            if (outBuf.size() == 0) throw TransportException("no frames to exchange")
            post(allowEmpty = false)
        }
        return pending.removeFirstOrNull() ?: throw TransportException("no frames available")
    }

    override fun flush() {
        if (outBuf.size() > 0) post(allowEmpty = true)
    }

    override fun close() {
        outBuf.reset()
        pending.clear()
    }

    override fun setSessionId(sid: String) {
        this.sid = sid
    }

    private fun target(): String {
        val suffix = sid?.let { "/$it" } ?: ""
        return baseUrl.trimEnd('/') + path + suffix
    }

    private fun post(allowEmpty: Boolean) {
        val body = outBuf.toByteArray()
        outBuf.reset()
        val conn = URL(target()).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 15000
            conn.readTimeout = 60000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/octet-stream")
            conn.setFixedLengthStreamingMode(body.size)
            conn.outputStream.use { it.write(body) }
            val status = conn.responseCode
            if (status != 200) throw TransportException("http status $status")
            val payload = conn.inputStream.use { it.readBytes() }
            val frames = Wire.splitFrames(payload)
            if (frames.isEmpty() && !allowEmpty) throw TransportException("empty response body")
            pending.addAll(frames)
        } finally {
            conn.disconnect()
        }
    }
}

class TransportException(message: String) : Exception(message)
