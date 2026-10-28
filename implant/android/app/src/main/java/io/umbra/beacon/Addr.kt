package io.umbra.beacon

/**
 * Addresses with a family.
 *
 * An IPv6 literal carries a port in brackets ("[::1]:8443"), because
 * "host:port" is ambiguous otherwise: the literal itself has colons in
 * it. The code that splits a pair apart splits on the *last* colon and
 * removes the brackets, and the code that writes a pair puts the
 * brackets back. The two directions are the same rule, so they live
 * together here.
 */
object Addr {
    /**
     * Split "host:port" into its two parts.
     *
     * The brackets of an IPv6 literal are removed; a value without a
     * port gives the port zero.
     */
    fun splitHostPort(value: String): Pair<String, Int> {
        val trimmed = value.trim()
        if (trimmed.startsWith("[")) {
            val close = trimmed.indexOf(']')
            if (close > 0) {
                val host = trimmed.substring(1, close)
                val port = trimmed.substring(close + 1).removePrefix(":").trim()
                return Pair(host, port.toIntOrNull() ?: 0)
            }
        }
        val colon = trimmed.lastIndexOf(':')
        if (colon < 0) return Pair(trimmed, 0)
        val host = trimmed.substring(0, colon).trim()
        val port = trimmed.substring(colon + 1).trim()
        return Pair(host, port.toIntOrNull() ?: 0)
    }

    /**
     * Write a host and a port as one address.
     *
     * An IPv6 literal is bracketed, so the result can be split again by
     * [splitHostPort] and by every other tool that reads "host:port".
     */
    fun hostPort(host: String, port: Int): String {
        val bare = host.trim().removePrefix("[").removeSuffix("]")
        return if (bare.contains(':')) "[$bare]:$port" else "$bare:$port"
    }
}
