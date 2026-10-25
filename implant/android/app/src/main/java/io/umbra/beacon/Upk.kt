package io.umbra.beacon

import java.io.ByteArrayOutputStream
import java.util.TreeMap

/**
 * Umbra Pack (upk) -- Kotlin port of the canonical umbra/v1 encoding.
 *
 * Byte-for-byte compatible with operator/umbra_cli/upk.py,
 * server/internal/upk and implant/rust/src/upk.rs (contracts/vectors.json).
 *
 * Non-negative numbers use uvarint, negative numbers use zigzag svarint, which
 * is what all the other implementations canonicalise to as well.
 */
sealed class Upk {
    object Null : Upk()
    data class Bool(val value: Boolean) : Upk()
    data class Num(val value: Long) : Upk()
    data class F64(val value: Double) : Upk()
    data class Str(val value: String) : Upk()
    data class Bin(val value: ByteArray) : Upk() {
        override fun equals(other: Any?): Boolean = other is Bin && value.contentEquals(other.value)
        override fun hashCode(): Int = value.contentHashCode()
    }
    data class Arr(val items: List<Upk>) : Upk()
    data class MapV(val entries: TreeMap<String, Upk>) : Upk()

    companion object {
        const val MAX_DEPTH = 16
        const val MAX_ITEMS = 1 shl 20
        const val MAX_STRING = 1 shl 20
        const val MAX_TOTAL = 4 shl 20

        private const val T_NULL = 0x00
        private const val T_FALSE = 0x01
        private const val T_TRUE = 0x02
        private const val T_UINT = 0x03
        private const val T_INT = 0x04
        private const val T_F64 = 0x05
        private const val T_STR = 0x06
        private const val T_BIN = 0x07
        private const val T_ARR = 0x08
        private const val T_MAP = 0x09

        // ---- builders --------------------------------------------------
        fun map(vararg pairs: Pair<String, Upk>): MapV {
            val t = TreeMap<String, Upk>()
            pairs.forEach { (k, v) -> t[k] = v }
            return MapV(t)
        }

        fun str(value: String): Str = Str(value)
        fun bin(value: ByteArray): Bin = Bin(value)
        fun num(value: Long): Num = Num(value)
        fun bool(value: Boolean): Bool = Bool(value)

        // ---- encoder ---------------------------------------------------
        fun encode(value: Upk): ByteArray {
            val out = ByteArrayOutputStream(64)
            write(value, out, 0)
            if (out.size() > MAX_TOTAL) throw UpkException("value exceeds limit")
            return out.toByteArray()
        }

        private fun write(value: Upk, out: ByteArrayOutputStream, depth: Int) {
            if (depth > MAX_DEPTH) throw UpkException("nesting too deep")
            when (value) {
                is Null -> out.write(T_NULL)
                is Bool -> out.write(if (value.value) T_TRUE else T_FALSE)
                is Num -> {
                    if (value.value >= 0) {
                        out.write(T_UINT)
                        writeUvarint(value.value.toULong(), out)
                    } else {
                        out.write(T_INT)
                        writeUvarint(zigzag(value.value), out)
                    }
                }
                is F64 -> {
                    out.write(T_F64)
                    writeLongBE(value.value.toRawBits(), out)
                }
                is Str -> {
                    val raw = value.value.toByteArray(Charsets.UTF_8)
                    if (raw.size > MAX_STRING) throw UpkException("string too long")
                    out.write(T_STR)
                    writeUvarint(raw.size.toULong(), out)
                    out.write(raw)
                }
                is Bin -> {
                    if (value.value.size > MAX_STRING) throw UpkException("binary too long")
                    out.write(T_BIN)
                    writeUvarint(value.value.size.toULong(), out)
                    out.write(value.value)
                }
                is Arr -> {
                    if (value.items.size > MAX_ITEMS) throw UpkException("array too long")
                    out.write(T_ARR)
                    writeUvarint(value.items.size.toULong(), out)
                    value.items.forEach { write(it, out, depth + 1) }
                }
                is MapV -> {
                    if (value.entries.size > MAX_ITEMS) throw UpkException("map too large")
                    out.write(T_MAP)
                    writeUvarint(value.entries.size.toULong(), out)
                    // TreeMap iterates in byte-wise ascending UTF-8 key order
                    value.entries.forEach { (k, v) ->
                        val raw = k.toByteArray(Charsets.UTF_8)
                        if (raw.size > MAX_STRING) throw UpkException("map key too long")
                        out.write(T_STR)
                        writeUvarint(raw.size.toULong(), out)
                        out.write(raw)
                        write(v, out, depth + 1)
                    }
                }
            }
        }

        private fun writeUvarint(value: ULong, out: ByteArrayOutputStream) {
            var n = value
            while (true) {
                val b = (n and 0x7FuL).toInt()
                n = n shr 7
                if (n != 0uL) out.write(b or 0x80) else {
                    out.write(b)
                    return
                }
            }
        }

        private fun writeLongBE(value: Long, out: ByteArrayOutputStream) {
            for (shift in 56 downTo 0 step 8) out.write(((value ushr shift) and 0xFF).toInt())
        }

        private fun zigzag(n: Long): ULong = ((n shl 1) xor (n shr 63)).toULong()

        // ---- decoder ---------------------------------------------------
        fun decode(data: ByteArray): Upk {
            val reader = Reader(data)
            val v = reader.readValue(0)
            if (reader.pos != data.size) throw UpkException("trailing bytes after value")
            return v
        }

        private class Reader(val buf: ByteArray) {
            var pos = 0

            fun need(n: Int) {
                if (n < 0 || pos + n > buf.size) throw UpkException("truncated input")
            }

            fun uvarint(): ULong {
                var result = 0uL
                var shift = 0
                for (i in 0 until 10) {
                    need(1)
                    val b = buf[pos++].toInt() and 0xFF
                    if (shift == 63 && b > 1) throw UpkException("uvarint overflow")
                    result = result or ((b and 0x7F).toULong() shl shift)
                    if (b and 0x80 == 0) {
                        if (i > 0 && b == 0) throw UpkException("non-minimal uvarint")
                        return result
                    }
                    shift += 7
                }
                throw UpkException("uvarint too long")
            }

            fun readValue(depth: Int): Upk {
                if (depth > MAX_DEPTH) throw UpkException("nesting too deep")
                need(1)
                val tag = buf[pos++].toInt() and 0xFF
                return when (tag) {
                    T_NULL -> Null
                    T_FALSE -> Bool(false)
                    T_TRUE -> Bool(true)
                    T_UINT -> Num(uvarint().toLong())
                    T_INT -> {
                        val z = uvarint().toLong()
                        Num((z ushr 1) xor -(z and 1L))
                    }
                    T_F64 -> {
                        need(8)
                        var bits = 0L
                        for (i in 0 until 8) bits = (bits shl 8) or (buf[pos + i].toLong() and 0xFF)
                        pos += 8
                        F64(Double.fromBits(bits))
                    }
                    T_STR -> {
                        val n = uvarint().toInt()
                        if (n > MAX_STRING) throw UpkException("string too long")
                        need(n)
                        val s = String(buf, pos, n, Charsets.UTF_8)
                        pos += n
                        Str(s)
                    }
                    T_BIN -> {
                        val n = uvarint().toInt()
                        if (n > MAX_STRING) throw UpkException("binary too long")
                        need(n)
                        val out = buf.copyOfRange(pos, pos + n)
                        pos += n
                        Bin(out)
                    }
                    T_ARR -> {
                        val n = uvarint()
                        if (n > MAX_ITEMS.toULong()) throw UpkException("array too long")
                        val items = ArrayList<Upk>(minOf(n.toInt(), 64))
                        repeat(n.toInt()) { items.add(readValue(depth + 1)) }
                        Arr(items)
                    }
                    T_MAP -> {
                        val n = uvarint()
                        if (n > MAX_ITEMS.toULong()) throw UpkException("map too large")
                        val map = TreeMap<String, Upk>()
                        var prev: String? = null
                        repeat(n.toInt()) {
                            need(1)
                            if ((buf[pos++].toInt() and 0xFF) != T_STR) {
                                throw UpkException("map key must be a string")
                            }
                            val klen = uvarint().toInt()
                            if (klen > MAX_STRING) throw UpkException("map key too long")
                            need(klen)
                            val key = String(buf, pos, klen, Charsets.UTF_8)
                            pos += klen
                            prev?.let { p -> if (key <= p) throw UpkException("map keys not ascending") }
                            prev = key
                            map[key] = readValue(depth + 1)
                        }
                        MapV(map)
                    }
                    else -> throw UpkException("unknown type tag 0x%02x".format(tag))
                }
            }
        }
    }
}

class UpkException(message: String) : Exception(message)

// ---------------------------------------------------------------------------
// Accessors
//
// These are deliberately *top-level* extensions, not members of the companion
// object: a member extension is only callable inside the declaring scope, so
// `frame.field("sid")` from Beacon/TaskRunner would not resolve. In this
// package they are visible everywhere without an import.
// ---------------------------------------------------------------------------

fun Upk.field(key: String): Upk? = (this as? Upk.MapV)?.entries?.get(key)

fun Upk.text(): String? = (this as? Upk.Str)?.value

fun Upk.bytes(): ByteArray? = when (this) {
    is Upk.Bin -> value
    is Upk.Str -> value.toByteArray(Charsets.UTF_8)
    else -> null
}

fun Upk.long(): Long? = (this as? Upk.Num)?.value

fun Upk.list(): List<Upk> = (this as? Upk.Arr)?.items ?: emptyList()
