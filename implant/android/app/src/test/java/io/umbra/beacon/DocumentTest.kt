package io.umbra.beacon

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Document-level conformance: the maps the protocol defines, read by the code
 * the beacon runs.
 *
 * `VectorsTest` proves the encoders agree on *values*.  A protocol is a set of
 * *documents* built from those values, and a document can diverge without any
 * value diverging: a field renamed, a type quietly coerced, a missing field
 * read as a default.  The same bytes are read here by
 * `Peer.helloFrom` (the Kotlin port), `tunnel::parse_peer_hello` (Rust) and
 * `PeerHello.from_map` (Python), and `contracts/vectors.json`
 * (`documents`) says what each case must do.
 */
class DocumentTest {
    private val documents: Map<String, Any?> by lazy {
        val stream = javaClass.classLoader?.getResourceAsStream("vectors.json")
            ?: throw IllegalStateException("vectors.json is not on the test classpath")
        val text = stream.use { it.readBytes().toString(Charsets.UTF_8) }
        @Suppress("UNCHECKED_CAST")
        val all = Json.parse(text) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        all["documents"] as Map<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    private fun peerCases(): List<Map<String, Any?>> =
        documents["peer_hello"] as List<Map<String, Any?>>

    @Suppress("UNCHECKED_CAST")
    private fun resultVector(name: String): Map<String, Any?> =
        documents[name] as Map<String, Any?>

    @Test
    fun everyPeerHelloVectorIsReadAsTheSchemaSays() {
        var accepted = 0
        var refused = 0
        for (case in peerCases()) {
            val name = case["name"] as String
            val value = Upk.decode(hexToBytes(case["hex"] as String))
            when (case["expect"] as String) {
                "accept" -> {
                    val hello = Peer.helloFrom(value)
                    assertEquals("id of $name", "beacon-a", hello.id)
                    assertEquals("pub of $name", 32, hello.pub.size)
                    accepted++
                }
                "reject" -> {
                    try {
                        Peer.helloFrom(value)
                        fail("the peer parser accepted $name")
                    } catch (_: SessionException) {
                        refused++
                    }
                }
                else -> fail("unknown expectation in the vector $name")
            }
        }
        assertTrue("no vector was accepted", accepted >= 2)
        assertTrue("no vector was refused", refused >= 2)
    }

    @Test
    fun theResultDocumentIsTheSharedOne() {
        val case = resultVector("result")
        val outcome = TaskRunner.Outcome(0L, "hi".toByteArray(), "")
        assertEquals(
            case["hex"],
            Upk.encode(outcome.toValue(case["task_id"] as String)).toHex(),
        )
        // ... and the fields come back with the types the schema names.
        val decoded = Upk.decode(hexToBytes(case["hex"] as String))
        assertEquals("t-1", decoded.field("id")?.text())
        assertEquals(0L, decoded.field("code")?.long())
        assertEquals("hi", decoded.field("out")?.bytes()?.toString(Charsets.UTF_8))
        assertEquals("", decoded.field("err")?.text())
    }

    @Test
    fun theErrorResultDocumentIsTheSharedOne() {
        val case = resultVector("result_error")
        val outcome = TaskRunner.Outcome(125L, ByteArray(0), "cancelled before execution")
        assertEquals(
            case["hex"],
            Upk.encode(outcome.toValue(case["task_id"] as String)).toHex(),
        )
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun theBatchCadenceIsReadAsTheSchemaSays() {
        val cases = documents["batch_policy"] as List<Map<String, Any?>>
        assertTrue("the policy vectors are missing", cases.isNotEmpty())
        for (case in cases) {
            val name = case["name"] as String
            val base = case["base"] as Map<String, Any?>
            val baseSleep = (base["sleep"] as BigInteger).toLong()
            val baseJitter = (base["jitter"] as BigInteger).toInt()
            val body = Upk.decode(hexToBytes(case["hex"] as String))
            val (sleep, jitter) = policyFrom(body, baseSleep, baseJitter)
            val expect = case["expect"] as Map<String, Any?>
            assertEquals("$name: sleep", (expect["sleep"] as BigInteger).toLong(), sleep)
            assertEquals("$name: jitter", (expect["jitter"] as BigInteger).toInt(), jitter)
        }
    }

    @Test
    fun aBatchThatIsNotAMapIsRefused() {
        val case = documents["batch_not_a_map"] as Map<String, Any?>
        assertEquals("reject", case["expect"])
        val body = Upk.decode(hexToBytes(case["hex"] as String))
        try {
            taskBatch(body)
            fail("a batch whose body is an array was accepted")
        } catch (e: SessionException) {
            assertEquals("TASK_BATCH is not a map", e.message)
        }
        // ... and a real batch is untouched by the rule.
        val batch = taskBatch(Upk.map("tasks" to Upk.Arr(emptyList())))
        assertEquals(1, batch.entries.size)
        assertEquals(0, (batch.entries["tasks"] as Upk.Arr).items.size)
    }

    @Test
    fun anUnknownFieldIsIgnoredAndNotReEncoded() {
        // Forward compatibility: a document with a field this build does not
        // know is read, and the unknown field is simply not part of the
        // model.  Re-encoding therefore drops it -- which is why the beacon
        // never re-encodes a document it received.
        val case = peerCases().first { it["name"] == "extra-field" }
        val decoded = Upk.decode(hexToBytes(case["hex"] as String))
        assertEquals("blue", decoded.field("colour")?.text())
        val hello = Peer.helloFrom(decoded)
        assertEquals("beacon-a", hello.id)
        val again = Upk.encode(
            Upk.map(
                "id" to Upk.str(hello.id),
                "pub" to Upk.bin(hello.pub),
                "nonce" to Upk.bin(hello.nonce),
                "mac" to Upk.bin(hello.mac),
            ),
        ).toHex()
        val withoutExtra = peerCases().first { it["name"] == "valid" }
        assertEquals("re-encoding drops the unknown field", withoutExtra["hex"], again)
    }
}
