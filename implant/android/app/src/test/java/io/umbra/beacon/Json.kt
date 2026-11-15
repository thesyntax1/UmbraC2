package io.umbra.beacon

import java.math.BigInteger

/**
 * A minimal JSON reader, for the shared conformance vectors.
 *
 * The beacon has no runtime dependencies and this stage does not add one for
 * a test: `contracts/vectors.json` is small, and the subset of JSON it uses
 * is objects, arrays, strings, integers and booleans.  Numbers come back as
 * [BigInteger] rather than `Long` on purpose -- one of the vectors
 * (`upk` case `uint-max`) is 2⁶⁴−1, and a reader that silently overflowed it
 * would make the test agree with a truncation it is supposed to catch.
 */
internal class Json private constructor(private val text: String) {
    private var pos = 0

    companion object {
        fun parse(text: String): Any? = Json(text).document()
    }

    private fun document(): Any? {
        val value = value()
        skipSpace()
        if (pos != text.length) fail("trailing bytes at $pos")
        return value
    }

    private fun fail(what: String): Nothing = throw IllegalArgumentException("json: $what")

    private fun skipSpace() {
        while (pos < text.length) {
            val c = text[pos]
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') pos++ else return
        }
    }

    private fun value(): Any? {
        skipSpace()
        if (pos >= text.length) fail("unexpected end")
        return when (text[pos]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> string()
            't' -> literal("true", true)
            'f' -> literal("false", false)
            'n' -> literal("null", null)
            else -> number()
        }
    }

    private fun literal(word: String, result: Any?): Any? {
        if (!text.startsWith(word, pos)) fail("expected $word")
        pos += word.length
        return result
    }

    private fun obj(): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        pos++ // {
        skipSpace()
        if (pos < text.length && text[pos] == '}') {
            pos++
            return out
        }
        while (true) {
            skipSpace()
            val key = string()
            skipSpace()
            if (pos >= text.length || text[pos] != ':') fail("expected :")
            pos++
            out[key] = value()
            skipSpace()
            if (pos >= text.length) fail("unterminated object")
            when (text[pos]) {
                ',' -> pos++
                '}' -> {
                    pos++
                    return out
                }
                else -> fail("expected , or }")
            }
        }
    }

    private fun arr(): List<Any?> {
        val out = ArrayList<Any?>()
        pos++ // [
        skipSpace()
        if (pos < text.length && text[pos] == ']') {
            pos++
            return out
        }
        while (true) {
            out.add(value())
            skipSpace()
            if (pos >= text.length) fail("unterminated array")
            when (text[pos]) {
                ',' -> pos++
                ']' -> {
                    pos++
                    return out
                }
                else -> fail("expected , or ]")
            }
        }
    }

    private fun string(): String {
        if (pos >= text.length || text[pos] != '"') fail("expected a string")
        pos++
        val sb = StringBuilder()
        while (true) {
            if (pos >= text.length) fail("unterminated string")
            val c = text[pos++]
            when {
                c == '"' -> return sb.toString()
                c == '\\' -> {
                    if (pos >= text.length) fail("unterminated escape")
                    when (val e = text[pos++]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000c')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            if (pos + 4 > text.length) fail("short \\u escape")
                            sb.append(text.substring(pos, pos + 4).toInt(16).toChar())
                            pos += 4
                        }
                        else -> fail("bad escape \\$e")
                    }
                }
                else -> sb.append(c)
            }
        }
    }

    private fun number(): Any {
        val start = pos
        if (pos < text.length && (text[pos] == '-' || text[pos] == '+')) pos++
        while (pos < text.length && text[pos].isDigit()) pos++
        var float = false
        if (pos < text.length && text[pos] == '.') {
            float = true
            pos++
            while (pos < text.length && text[pos].isDigit()) pos++
        }
        if (pos < text.length && (text[pos] == 'e' || text[pos] == 'E')) {
            float = true
            pos++
            if (pos < text.length && (text[pos] == '-' || text[pos] == '+')) pos++
            while (pos < text.length && text[pos].isDigit()) pos++
        }
        if (pos == start) fail("expected a value")
        val raw = text.substring(start, pos)
        return if (float) raw.toDouble() else BigInteger(raw)
    }
}

/** A hex string to bytes; the vectors spell every binary field this way. */
internal fun hexToBytes(text: String): ByteArray {
    require(text.length % 2 == 0) { "odd hex length" }
    val out = ByteArray(text.length / 2)
    for (i in out.indices) out[i] = text.substring(2 * i, 2 * i + 2).toInt(16).toByte()
    return out
}

/**
 * The JSON spelling of a value to the value the encoder should produce.
 *
 * A binary value is `{"$bin": "<hex>"}`, which is the convention the Rust,
 * Go and Python tests share.
 */
internal fun jsonToUpk(value: Any?): Upk = when (value) {
    null -> Upk.Null
    is Boolean -> Upk.bool(value)
    is BigInteger -> {
        require(value >= BigInteger.valueOf(Long.MIN_VALUE) && value <= BigInteger.valueOf(Long.MAX_VALUE)) {
            "$value does not fit the Kotlin model (see uintMaxIsRefusedByThisModel)"
        }
        Upk.num(value.toLong())
    }
    is Double -> Upk.F64(value)
    is String -> Upk.str(value)
    is List<*> -> Upk.Arr(value.map { jsonToUpk(it) })
    is Map<*, *> -> {
        if (value.size == 1 && value.containsKey("\$bin")) {
            Upk.bin(hexToBytes(value["\$bin"] as String))
        } else {
            val entries = value.entries.map { (k, v) -> (k as String) to jsonToUpk(v) }
            Upk.map(*entries.toTypedArray())
        }
    }
    else -> throw IllegalArgumentException("unexpected json value: ${value::class}")
}
