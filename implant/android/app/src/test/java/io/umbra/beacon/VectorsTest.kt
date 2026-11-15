package io.umbra.beacon

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The shared conformance vectors, read by the Android implementation.
 *
 * `contracts/vectors.json` is the artefact the Python, Go and Rust tests read.
 * Before this file the Kotlin port was the only implementation that never
 * ran them: `docs/TRANSPORT-PARSER.md` and the Go/Rust/Python suites could
 * all be green while `Upk.kt` decoded a value differently, and nothing in CI
 * would say so.  These tests close that: they take the *same bytes* and put
 * them through the code the beacon actually runs.
 */
class VectorsTest {
    private val vectors: Map<String, Any?> by lazy { loadVectors() }

    @Suppress("UNCHECKED_CAST")
    private fun loadVectors(): Map<String, Any?> {
        val stream = javaClass.classLoader?.getResourceAsStream("vectors.json")
            ?: throw IllegalStateException(
                "vectors.json is not on the test classpath: check the test resources srcDirs",
            )
        val text = stream.use { it.readBytes().toString(Charsets.UTF_8) }
        return Json.parse(text) as Map<String, Any?>
    }

    private fun hex(value: Any?): ByteArray =
        hexToBytes(value as? String ?: throw IllegalArgumentException("expected a hex string"))

    @Suppress("UNCHECKED_CAST")
    private fun upkCases(): List<Map<String, Any?>> = vectors["upk"] as List<Map<String, Any?>>

    @Suppress("UNCHECKED_CAST")
    private fun rejectCases(): Map<String, Any?> = vectors["rejects"] as Map<String, Any?>

    @Test
    fun everyUpkVectorEncodesToTheSameBytes() {
        var checked = 0
        for (case in upkCases()) {
            val name = case["name"] as String
            if (name == "uint-max") continue // covered by uintMaxIsRefusedByThisModel
            assertEquals("encode $name", case["hex"], Upk.encode(jsonToUpk(case["json"])).toHex())
            checked++
        }
        assertEquals("the vector count changed under the test", upkCases().size - 1, checked)
    }

    @Test
    fun everyUpkVectorDecodesAndReEncodesToItself() {
        for (case in upkCases()) {
            val name = case["name"] as String
            if (name == "uint-max") continue // covered by uintMaxIsRefusedByThisModel
            val raw = hex(case["hex"])
            assertEquals("re-encode $name", case["hex"], Upk.encode(Upk.decode(raw)).toHex())
        }
    }

    /**
     * `uint-max` is 2⁶⁴−1, and Kotlin's `Upk.Num` holds a `Long`.
     *
     * The reference (Python, Go, Rust) decodes it and re-encodes the same
     * bytes.  This port refuses it -- loudly, which is the right failure --
     * but the refusal is a divergence from the protocol's own table
     * (`docs/PROTOCOL.md` §3: uvarint, < 2⁶⁴).  The test pins the divergence
     * so it cannot change silently, and `docs/SCHEMA-CONFORMANCE.md` records
     * it as open.
     */
    @Test
    fun uintMaxIsRefusedByThisModel() {
        val case = upkCases().first { it["name"] == "uint-max" }
        try {
            Upk.decode(hex(case["hex"]))
            fail("the Android decoder accepted a u64 above Long.MAX_VALUE")
        } catch (e: UpkException) {
            assertTrue("unexpected message: ${e.message}", e.message!!.contains("uint out of range"))
        }
    }

    @Test
    fun everyUpkRejectVectorIsRefused() {
        var checked = 0
        for ((name, raw) in rejectCases()) {
            if (!name.startsWith("upk_")) continue
            try {
                Upk.decode(hex(raw))
                fail("the Android decoder accepted the reject vector $name")
            } catch (_: UpkException) {
                checked++
            }
        }
        assertTrue("no upk reject vectors were checked", checked >= 8)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun theFrameConstantsAreTheOnesInTheVectors() {
        val meta = vectors["meta"] as Map<String, Any?>
        val frame = meta["frame"] as Map<String, Any?>
        assertEquals((frame["version"] as BigInteger).toInt(), Wire.VERSION.toInt())
        assertEquals((frame["prelude_len"] as BigInteger).toInt(), Wire.PRELUDE_LEN)
        assertEquals((frame["nonce_len"] as BigInteger).toInt(), Wire.NONCE_LEN)
        assertEquals((frame["tag_len"] as BigInteger).toInt(), Wire.TAG_LEN)
        assertEquals((frame["header_len"] as BigInteger).toInt(), Wire.HEADER_LEN)
        assertEquals((frame["max_body"] as BigInteger).toInt(), Wire.MAX_BODY)
        assertEquals(frame["magic"], Wire.MAGIC.toHex())
    }

    /**
     * Every frame vector's prelude, read the way the beacon reads it.
     *
     * One of the shared frames is sealed with suite 2 (ChaCha20-Poly1305).
     * This port speaks suite 1 only -- `tools/check_consistency.py` has no
     * Kotlin constant for suite 2, and the platform makes no promise about a
     * ChaCha provider -- so it must *refuse that frame at the prelude*, which
     * is what the test asserts.  The refusal is a real limitation of the
     * Android build and it is recorded in `docs/SCHEMA-CONFORMANCE.md`; what
     * would be wrong is skipping the vector and letting the limitation look
     * like agreement.
     */
    @Test
    @Suppress("UNCHECKED_CAST")
    fun everyFrameVectorPreludeIsReadOrRefusedAsThisPortCanSpeakIt() {
        val frames = vectors["frames"] as List<Map<String, Any?>>
        assertTrue("the frame vectors are missing", frames.isNotEmpty())
        var parsed = 0
        var refused = 0
        for (entry in frames) {
            val raw = hex(entry["frame_hex"])
            val suite = (entry["suite"] as BigInteger).toInt()
            val prelude = raw.copyOfRange(0, Wire.PRELUDE_LEN)
            if (suite != Wire.SUITE_AES256_GCM) {
                try {
                    Wire.parseHeader(prelude)
                    fail("a suite $suite frame was accepted by a port that speaks suite 1")
                } catch (e: WireException) {
                    assertTrue("unexpected message: ${e.message}", e.message!!.contains("unsupported suite"))
                    refused++
                }
                continue
            }
            val header = Wire.parseHeader(prelude)
            val plaintext = hex(entry["plaintext_hex"])
            assertEquals("type", (entry["type"] as BigInteger).toInt(), header.type)
            assertEquals("suite", suite, header.suite)
            assertEquals("length", plaintext.size, header.length)
            assertEquals("flags", 0, header.flags)
            parsed++
        }
        assertTrue("no suite 1 frame was parsed", parsed >= 2)
        assertTrue("the suite 2 frame is no longer in the vectors: the test and the file disagree", refused >= 1)
    }

    @Test
    fun aPreludeThatIsNotAFrameIsRefused() {
        val bad = hex(rejectCases()["bad_magic"])
        try {
            Wire.parseHeader(bad.copyOfRange(0, Wire.PRELUDE_LEN))
            fail("a prelude with the wrong magic was accepted")
        } catch (e: WireException) {
            assertEquals("bad magic", e.message)
        }
    }

    @Test
    fun theReservedBytesAndTheSuiteAreChecked() {
        val good = Wire.buildHeader(0, Wire.MSG_CHECKIN.toInt(), Wire.SUITE_AES256_GCM, 0)
        assertNotNull(Wire.parseHeader(good))

        val reserved = good.copyOf()
        reserved[6] = 1.toByte()
        try {
            Wire.parseHeader(reserved)
            fail("a set reserved byte was accepted")
        } catch (e: WireException) {
            assertEquals("reserved bytes set", e.message)
        }

        val suite = good.copyOf()
        suite[5] = 9.toByte()
        try {
            Wire.parseHeader(suite)
            fail("an unknown suite was accepted")
        } catch (e: WireException) {
            assertTrue(e.message!!.contains("unsupported suite"))
        }

        val big = Wire.buildHeader(0, Wire.MSG_CHECKIN.toInt(), Wire.SUITE_AES256_GCM, 0)
        big[8] = 0x7f.toByte() // a length the receiver must refuse before allocating
        try {
            Wire.parseHeader(big)
            fail("a body over MAX_BODY was accepted")
        } catch (e: WireException) {
            assertEquals("frame too large", e.message)
        }
    }

    @Test
    fun aTruncatedPreludeIsRefused() {
        try {
            Wire.parseHeader(ByteArray(Wire.PRELUDE_LEN - 1))
            fail("a short prelude was accepted")
        } catch (e: WireException) {
            assertEquals("truncated prelude", e.message)
        }
    }
}

internal fun ByteArray.toHex(): String = joinToString("") { b ->
    val v = b.toInt() and 0xff
    "0123456789abcdef"[v ushr 4].toString() + "0123456789abcdef"[v and 0x0f].toString()
}
