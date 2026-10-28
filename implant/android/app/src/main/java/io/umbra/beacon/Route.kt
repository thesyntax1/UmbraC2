package io.umbra.beacon

/**
 * The route of the agent: which transport it speaks, in which order it may
 * fall back, and the front domain it hides behind.
 *
 * The operator knows the network of the target: this one only speaks DNS,
 * that one goes through a front domain, the third one sits behind a proxy
 * that reads the traffic.  The server pushes the route with the task batch,
 * so the beacon follows it without being reconfigured.
 */
data class Route(
    /** The transport the beacon uses first. */
    val primary: String,
    /** The order the beacon tries when the primary fails. */
    val fallback: List<String> = emptyList(),
    /** The domain the beacon puts in the Host header. */
    val front: String = "",
    /** The proxy in front of the beacon reads the traffic. */
    val inspect: Boolean = false,
) {
    /**
     * The transports the beacon tries, in order.
     *
     * The route of the server wins over the compiled-in transport; the
     * fallback of the route comes after the primary.  A transport that is
     * named twice is only tried once.
     */
    fun transports(compiled: String): List<String> {
        val out = LinkedHashSet<String>()
        for (name in listOf(primary) + fallback) {
            val clean = name.trim().lowercase()
            if (clean.isNotEmpty()) out.add(clean)
        }
        if (out.isEmpty()) out.add(compiled.lowercase())
        return out.toList()
    }
}
