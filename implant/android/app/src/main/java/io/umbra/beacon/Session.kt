package io.umbra.beacon

/** Encrypted session state machine (mirror of server/internal/session). */
class Session(
    val suite: Int,
    val isServer: Boolean,
    val bootstrap: Boolean,
    material: Crypto.KeyMaterial,
    private var prk: ByteArray?,
) {
    companion object {
        const val REKEY_AFTER = 1L shl 20

        fun fromBootstrap(psk: ByteArray, suite: Int, isServer: Boolean): Session {
            val km = Crypto.KeyMaterial(
                c2sKey = Crypto.deriveBootstrapKey(psk, "c2s", suite),
                s2cKey = Crypto.deriveBootstrapKey(psk, "s2c", suite),
                c2sPrefix = ByteArray(0),
                s2cPrefix = ByteArray(0),
            )
            return Session(suite, isServer, true, km, null)
        }
    }

    private class Direction(var key: ByteArray, var prefix: ByteArray) {
        var counter = 0L
        var frames = 0L

        fun nonce(): ByteArray = Wire.makeNonce(prefix, counter)

        fun advance() {
            counter++
            frames++
        }

        fun rotate(newKey: ByteArray, newPrefix: ByteArray) {
            key = newKey
            prefix = newPrefix
            counter = 0
            frames = 0
        }
    }

    private val flags: Int = if (bootstrap) Wire.FLAG_BOOTSTRAP.toInt() else 0
    private val send: Direction
    private val recv: Direction

    init {
        val c2sPrefix = if (bootstrap && material.c2sPrefix.isEmpty()) {
            Crypto.bootstrapNoncePrefix(material.c2sKey)
        } else material.c2sPrefix
        val s2cPrefix = if (bootstrap && material.s2cPrefix.isEmpty()) {
            Crypto.bootstrapNoncePrefix(material.s2cKey)
        } else material.s2cPrefix
        if (isServer) {
            send = Direction(material.s2cKey, s2cPrefix)
            recv = Direction(material.c2sKey, c2sPrefix)
        } else {
            send = Direction(material.c2sKey, c2sPrefix)
            recv = Direction(material.s2cKey, s2cPrefix)
        }
    }

    @Synchronized
    fun seal(msgType: Byte, plaintext: ByteArray): ByteArray {
        if (plaintext.size > Wire.MAX_BODY) throw SessionException("body too large")
        val prelude = Wire.buildHeader(flags, msgType.toInt(), suite, plaintext.size)
        val nonce = send.nonce()
        val sealed = Crypto.encrypt(send.key, nonce, prelude, plaintext)
        send.advance()
        return prelude + nonce + sealed
    }

    fun sealValue(msgType: Byte, value: Upk): ByteArray = seal(msgType, Upk.encode(value))

    @Synchronized
    fun open(frame: ByteArray): Pair<Byte, ByteArray> {
        if (frame.size < Wire.HEADER_LEN) throw SessionException("frame too short")
        val header = Wire.parseHeader(frame)
        if (frame.size != Wire.frameLength(header.length)) throw SessionException("frame size mismatch")
        if (header.flags != flags) throw SessionException("unexpected frame flags")
        if (header.suite != suite) throw SessionException("unexpected suite")
        val expected = recv.nonce()
        val actual = frame.copyOfRange(Wire.PRELUDE_LEN, Wire.HEADER_LEN)
        if (!Crypto.ctEq(expected, actual)) throw SessionException("nonce mismatch (replay or desync)")
        val plaintext = try {
            Crypto.decrypt(
                recv.key,
                expected,
                frame.copyOfRange(0, Wire.PRELUDE_LEN),
                frame.copyOfRange(Wire.HEADER_LEN, frame.size),
            )
        } catch (e: Exception) {
            throw SessionException("frame authentication failed")
        }
        if (plaintext.size != header.length) throw SessionException("length mismatch")
        recv.advance()
        return header.type.toByte() to plaintext
    }

    fun openValue(frame: ByteArray): Pair<Byte, Upk> {
        val (t, body) = open(frame)
        return t to Upk.decode(body)
    }

    fun needsRekey(): Boolean = send.frames >= REKEY_AFTER || recv.frames >= REKEY_AFTER

    fun applyRekey(seed: ByteArray) {
        val current = prk ?: throw SessionException("session has no PRK")
        val (newPrk, km) = Crypto.deriveRekey(current, seed)
        prk = newPrk
        if (isServer) {
            send.rotate(km.s2cKey, km.s2cPrefix)
            recv.rotate(km.c2sKey, km.c2sPrefix)
        } else {
            send.rotate(km.c2sKey, km.c2sPrefix)
            recv.rotate(km.s2cKey, km.s2cPrefix)
        }
    }
}

class SessionException(message: String) : Exception(message)
