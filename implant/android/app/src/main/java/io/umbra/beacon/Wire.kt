package io.umbra.beacon

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/** Frame format and message registry of umbra/v1. */
object Wire {
    const val VERSION: Byte = 1
    const val PRELUDE_LEN = 12
    const val NONCE_LEN = 12
    const val TAG_LEN = 16
    const val HEADER_LEN = PRELUDE_LEN + NONCE_LEN
    const val MAX_BODY = 1 shl 20

    val MAGIC = byteArrayOf(0x55, 0x43)

    const val FLAG_BOOTSTRAP = 0x01.toByte()

    // message types
    const val MSG_HELLO = 0x01.toByte()
    const val MSG_HELLO_ACK = 0x02.toByte()
    const val MSG_CHECKIN = 0x10.toByte()
    const val MSG_TASK_BATCH = 0x11.toByte()
    const val MSG_RESULT = 0x12.toByte()
    const val MSG_CONFIG = 0x13.toByte()
    const val MSG_PING = 0x14.toByte()
    const val MSG_PONG = 0x15.toByte()
    const val MSG_REKEY = 0x16.toByte()
    const val MSG_KILL = 0x17.toByte()
    const val MSG_TASK_CANCEL = 0x18.toByte()
    const val MSG_BYE = 0x19.toByte()
    const val MSG_TUNNEL_OPEN = 0x1A.toByte()
    const val MSG_TUNNEL_DATA = 0x1B.toByte()
    const val MSG_TUNNEL_CLOSE = 0x1C.toByte()
    const val MSG_PADDING = 0x1E.toByte()
    const val MSG_ERROR = 0x1F.toByte()

    const val MARKER_HELLO = 0x01.toByte()
    const val MARKER_HELLO_ACK = 0x02.toByte()

    const val SUITE_AES256_GCM = 1

    class Header(
        val flags: Int,
        val type: Int,
        val suite: Int,
        val length: Int,
    )

    fun makeNonce(prefix: ByteArray, counter: Long): ByteArray {
        require(prefix.size == 4) { "nonce prefix must be 4 bytes" }
        return prefix + Crypto.longToBe(counter)
    }

    fun buildHeader(flags: Int, msgType: Int, suite: Int, plaintextLen: Int): ByteArray {
        require(plaintextLen <= MAX_BODY) { "body too large" }
        val p = ByteArray(PRELUDE_LEN)
        p[0] = MAGIC[0]
        p[1] = MAGIC[1]
        p[2] = VERSION
        p[3] = flags.toByte()
        p[4] = msgType.toByte()
        p[5] = suite.toByte()
        // 6..7 reserved
        p[8] = ((plaintextLen ushr 24) and 0xFF).toByte()
        p[9] = ((plaintextLen ushr 16) and 0xFF).toByte()
        p[10] = ((plaintextLen ushr 8) and 0xFF).toByte()
        p[11] = (plaintextLen and 0xFF).toByte()
        return p
    }

    fun parseHeader(data: ByteArray): Header {
        if (data.size < PRELUDE_LEN) throw WireException("truncated prelude")
        if (data[0] != MAGIC[0] || data[1] != MAGIC[1]) throw WireException("bad magic")
        if (data[2] != VERSION) throw WireException("unsupported version ${data[2]}")
        if (data[6].toInt() != 0 || data[7].toInt() != 0) throw WireException("reserved bytes set")
        val suite = data[5].toInt() and 0xFF
        if (suite != SUITE_AES256_GCM) throw WireException("unsupported suite $suite")
        val length = ((data[8].toInt() and 0xFF) shl 24) or
            ((data[9].toInt() and 0xFF) shl 16) or
            ((data[10].toInt() and 0xFF) shl 8) or
            (data[11].toInt() and 0xFF)
        if (length > MAX_BODY) throw WireException("frame too large")
        return Header(data[3].toInt() and 0xFF, data[4].toInt() and 0xFF, suite, length)
    }

    fun frameLength(bodyLen: Int): Int = HEADER_LEN + bodyLen + TAG_LEN

    /** Read exactly one complete frame from a stream. */
    fun readFrame(input: InputStream): ByteArray {
        val prelude = readExact(input, PRELUDE_LEN)
        val header = parseHeader(prelude)
        val rest = readExact(input, NONCE_LEN + header.length + TAG_LEN)
        return prelude + rest
    }

    fun readExact(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var read = 0
        while (read < n) {
            val got = input.read(out, read, n - read)
            if (got <= 0) throw EOFException("stream closed")
            read += got
        }
        return out
    }

    fun writeFrame(output: OutputStream, frame: ByteArray) {
        output.write(frame)
        output.flush()
    }

    /** Split a buffer that may contain several concatenated frames. */
    fun splitFrames(buf: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var pos = 0
        while (pos < buf.size) {
            if (pos + PRELUDE_LEN > buf.size) throw WireException("truncated prelude")
            val header = parseHeader(buf.copyOfRange(pos, pos + PRELUDE_LEN))
            val total = frameLength(header.length)
            if (pos + total > buf.size) throw WireException("truncated frame")
            out.add(buf.copyOfRange(pos, pos + total))
            pos += total
        }
        return out
    }
}

class WireException(message: String) : Exception(message)
