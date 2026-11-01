package io.umbra.beacon

import java.math.BigInteger
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.ProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.XECPublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Key schedule and AEAD layer, mirroring server/internal/crypt.
 *
 * Note: X25519 uses the platform XDH provider (Android 13 / API 33+).
 * Everything else (HKDF-SHA256, HMAC, AES-256-GCM) is available on every
 * Android version that supports AES-GCM ciphers.
 */
object Crypto {
    const val ROLE_AGENT = 1
    const val ROLE_OPERATOR = 2

    val LABEL_BOOTSTRAP = "umbra/v1/bootstrap".toByteArray()
    val LABEL_SESSION = "umbra/v1/session".toByteArray()
    val LABEL_REKEY = "umbra/v1/rekey".toByteArray()

    /** The label of the attestation: a signature over a report is not a
     *  signature over a frame. */
    val LABEL_ATTEST = "umbra/w1/attest".toByteArray()

    private val rng = SecureRandom()
    private val xdhParams = NamedParameterSpec("X25519")

    // ---- randomness ----------------------------------------------------
    fun random(n: Int): ByteArray {
        val out = ByteArray(n)
        rng.nextBytes(out)
        return out
    }

    // ---- hashes / MAC / KDF -------------------------------------------
    fun sha256(data: ByteArray): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest(data)
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray = hmacSha256(salt, ikm)

    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length > 0 && length <= 255 * 32) { "invalid hkdf length" }
        val out = ByteArray(length)
        var prev = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(prev)
            mac.update(info)
            mac.update(byteArrayOf(counter.toByte()))
            prev = mac.doFinal()
            val take = minOf(prev.size, length - offset)
            System.arraycopy(prev, 0, out, offset, take)
            offset += take
            counter++
        }
        return out
    }

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray =
        hkdfExpand(hkdfExtract(salt, ikm), info, length)

    // ---- key material --------------------------------------------------
    class KeyMaterial(
        val c2sKey: ByteArray,
        val s2cKey: ByteArray,
        val c2sPrefix: ByteArray,
        val s2cPrefix: ByteArray,
    )

    private fun normalisePsk(psk: ByteArray, suite: Int): ByteArray =
        hkdfSha256(psk, LABEL_BOOTSTRAP + "/psk".toByteArray(), "suite:".toByteArray() + suite.toByte(), 32)

    fun deriveBootstrapKey(psk: ByteArray, direction: String, suite: Int): ByteArray {
        val info = String(LABEL_BOOTSTRAP) + "/" + direction
        return hkdfSha256(normalisePsk(psk, suite), LABEL_BOOTSTRAP, info.toByteArray(), 32)
    }

    fun bootstrapNoncePrefix(key: ByteArray): ByteArray =
        hkdfSha256(key, LABEL_BOOTSTRAP, "nonce-prefix".toByteArray(), 4)

    fun deriveSession(shared: ByteArray, clientNonce: ByteArray, serverNonce: ByteArray): Pair<ByteArray, KeyMaterial> {
        require(clientNonce.size == 16 && serverNonce.size == 16) { "nonces must be 16 bytes" }
        val salt = sha256(LABEL_SESSION + clientNonce + serverNonce)
        val prk = hkdfExtract(salt, shared)
        val okm = hkdfExpand(prk, LABEL_SESSION + "/keys".toByteArray(), 72)
        return prk to materialFromOkm(okm)
    }

    fun deriveRekey(prk: ByteArray, seed: ByteArray): Pair<ByteArray, KeyMaterial> {
        require(seed.size == 32) { "rekey seed must be 32 bytes" }
        val newPrk = hkdfExtract(seed, prk)
        val okm = hkdfExpand(newPrk, LABEL_REKEY + "/keys".toByteArray(), 72)
        return newPrk to materialFromOkm(okm)
    }

    private fun materialFromOkm(okm: ByteArray): KeyMaterial = KeyMaterial(
        c2sKey = okm.copyOfRange(0, 32),
        s2cKey = okm.copyOfRange(32, 64),
        c2sPrefix = okm.copyOfRange(64, 68),
        s2cPrefix = okm.copyOfRange(68, 72),
    )

    // ---- handshake transcript -----------------------------------------
    fun helloAuth(
        psk: ByteArray,
        role: Int,
        ident: ByteArray,
        clientPub: ByteArray,
        clientNonce: ByteArray,
        timestamp: Long,
        suite: Int,
    ): ByteArray {
        require(ident.size <= 255) { "identity too long" }
        val msg = LABEL_BOOTSTRAP + "/auth/hello".toByteArray() +
            byteArrayOf(role.toByte(), ident.size.toByte()) +
            ident + clientPub + clientNonce + longToBe(timestamp) + suite.toByte()
        return hmacSha256(psk, msg)
    }

    fun ackAuth(
        psk: ByteArray,
        ident: ByteArray,
        clientPub: ByteArray,
        serverPub: ByteArray,
        clientNonce: ByteArray,
        serverNonce: ByteArray,
        sessionId: ByteArray,
        suite: Int,
    ): ByteArray {
        require(ident.size <= 255) { "identity too long" }
        val msg = LABEL_BOOTSTRAP + "/auth/ack".toByteArray() +
            byteArrayOf(ident.size.toByte()) +
            ident + clientPub + serverPub + clientNonce + serverNonce + sessionId + suite.toByte()
        return hmacSha256(psk, msg)
    }

    // ---- X25519 --------------------------------------------------------
    class Ephemeral(val privateKey: PrivateKey, val publicRaw: ByteArray)

    fun x25519Keypair(): Ephemeral {
        val kpg = KeyPairGenerator.getInstance("XDH")
        // Android's own provider refused the named spec on API 33 and API 34:
        // "No AlgorithmParameterSpec classes are supported" (emulator run of
        // d9b4c44, the application's own notification).  The curve the
        // generator builds is X25519 either way, so the spec is offered first
        // and the generator's default is used when the platform refuses it.
        // A default that is not X25519 is caught below by the size of the
        // public key, not assumed away.
        try {
            kpg.initialize(xdhParams)
        } catch (_: InvalidAlgorithmParameterException) {
            // the default of the XDH generator is X25519
        } catch (_: ProviderException) {
            // some providers wrap the refusal in an unchecked exception
        }
        val kp = kpg.generateKeyPair()
        val pub = kp.public as XECPublicKey
        if (pub.u.bitLength() > 256) {
            throw CryptoException("the platform built a key that is not X25519")
        }
        return Ephemeral(kp.private, bigIntToLe32(pub.u))
    }

    fun x25519Shared(privateKey: PrivateKey, peerRaw: ByteArray): ByteArray {
        require(peerRaw.size == 32) { "peer public key must be 32 bytes" }
        val kf = KeyFactory.getInstance("XDH")
        val peer: PublicKey = kf.generatePublic(XECPublicKeySpec(xdhParams, le32ToBigInt(peerRaw)))
        val ka = KeyAgreement.getInstance("XDH")
        ka.init(privateKey)
        ka.doPhase(peer, true)
        val shared = ka.generateSecret()
        if (shared.all { it == 0.toByte() }) throw CryptoException("invalid x25519 shared secret")
        return shared
    }

    private fun bigIntToLe32(u: BigInteger): ByteArray {
        val be = u.toByteArray()
        var start = 0
        while (start < be.size - 1 && be[start] == 0.toByte()) start++
        val magnitude = be.copyOfRange(start, be.size)
        if (magnitude.size > 32) throw CryptoException("x25519 public key too large")
        val out = ByteArray(32)
        for (i in magnitude.indices) out[i] = magnitude[magnitude.size - 1 - i]
        return out
    }

    private fun le32ToBigInt(raw: ByteArray): BigInteger {
        val be = ByteArray(32)
        for (i in 0 until 32) be[31 - i] = raw[i]
        return BigInteger(1, be)
    }

    // ---- AEAD (AES-256-GCM) -------------------------------------------
    fun encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12) { "bad key/nonce length" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12) { "bad key/nonce length" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    // ---- helpers -------------------------------------------------------
    fun longToBe(value: Long): ByteArray {
        val out = ByteArray(8)
        for (i in 0 until 8) out[i] = ((value ushr (56 - 8 * i)) and 0xFF).toByte()
        return out
    }

    fun longFromBeBytes(data: ByteArray, offset: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (data[offset + i].toLong() and 0xFF)
        return v
    }

    /** Constant-time comparison. */
    fun ctEq(a: ByteArray?, b: ByteArray?): Boolean {
        if (a == null || b == null || a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun hex(data: ByteArray): String = data.joinToString("") { "%02x".format(it) }

    fun unhex(text: String): ByteArray {
        val clean = text.trim()
        require(clean.length % 2 == 0) { "hex string must have even length" }
        return ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[i * 2], 16) shl 4) or Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
    }
}

class CryptoException(message: String) : Exception(message)
