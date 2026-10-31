package io.umbra.beacon

import java.io.File
import java.security.MessageDigest

/**
 * The baseline of a host: the paths the team watches and what the last
 * look saw of them.
 *
 * A hunt looks for the indicators of somebody else.  A baseline asks a
 * different question: is this phone the phone we saw yesterday?  The
 * team names the paths that matter -- the configuration of the
 * service, the script that starts it, the key that opens it -- and the
 * implant reads each of them and reports the size, the time of the
 * last change and the digest.
 *
 * The rules are the same as everywhere else:
 *
 *   * **the baseline only reads.**  A baseline that rewrote the file
 *     it watches would destroy the very thing it is watching;
 *   * **what is not there is a finding.**  A path that is gone is
 *     reported as gone, because "no file" is what the team wanted to
 *     be told;
 *   * **the findings travel with the answer.**  The snapshots travel
 *     in the metadata of the answer as one short JSON string, so the
 *     ledger of the server and the answer the operator reads cannot
 *     disagree.
 *
 * The look is signed like every other report of the engagement: a look
 * that goes into the evidence file has to be provable.
 */
object Baseline {

    /** One look at one path. */
    data class Snapshot(
        val path: String,
        val size: Long,
        val mtime: Long,
        val sha256: String,
        val exists: Boolean,
    )

    /** What the look at the paths found. */
    data class Report(
        val snaps: List<Snapshot>,
        val text: String,
        val gone: Long,
        val error: String = "",
    )

    /**
     * Look at the paths the server named and say what is there.
     */
    fun look(args: Upk): Report {
        val paths = wanted(args)
        if (paths.isEmpty()) {
            return Report(emptyList(), "", 0, "baseline.look: no path was named")
        }
        val snaps = paths.map { snap(it) }
        val gone = snaps.count { !it.exists }.toLong()
        val lines = mutableListOf<String>()
        for (snap in snaps) {
            val note = if (snap.exists) {
                "${snap.size} bytes, digest ${snap.sha256}"
            } else {
                "the file is gone"
            }
            lines.add(String.format("  %-48s %s", snap.path, if (snap.exists) "present" else "missing"))
            lines.add("    $note")
        }
        val text = buildString {
            append("baseline.look: ${paths.size} paths looked at, $gone of them are gone\\n")
            for (line in lines) append(line).append("\\n")
        }
        return Report(snaps, text, gone)
    }

    /**
     * The paths the server asked about.
     */
    fun wanted(args: Upk): List<String> {
        val out = mutableListOf<String>()
        val items = args.field("paths")
        when (items) {
            is Upk.Arr -> for (item in items.items) {
                val path = item.text()?.trim()
                if (!path.isNullOrEmpty() && !out.contains(path)) out.add(path)
            }
            is Upk.Str -> for (line in items.value.split("\\n")) {
                // A single string of paths, one per line: a console
                // that does not carry a list can still name the
                // paths.
                val path = line.trim()
                if (path.isNotEmpty() && !out.contains(path)) out.add(path)
            }
            else -> {}
        }
        return out.sorted()
    }

    /**
     * One look at one path, from the disk of the phone.
     */
    private fun snap(path: String): Snapshot {
        val file = File(path)
        if (!file.exists()) {
            return Snapshot(path, 0, 0, "", false)
        }
        val data = try {
            file.readBytes()
        } catch (e: Exception) {
            return Snapshot(path, file.length(), file.lastModified(), "", false)
        }
        return Snapshot(
            path,
            file.length(),
            file.lastModified(),
            sha256(data),
            true,
        )
    }

    /** The digest of a piece of data, as the lower case hex of the bytes. */
    private fun sha256(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) sb.append("%02x".format(b.toInt() and 0xff))
        return sb.toString()
    }

    /**
     * The snapshots as one short JSON string, the way the answer
     * carries them and the way the server reads them.
     */
    fun renderSnaps(snaps: List<Snapshot>): String {
        val sb = StringBuilder(snaps.size * 96)
        sb.append("[")
        for ((i, snap) in snaps.withIndex()) {
            if (i > 0) sb.append(",")
            sb.append("{")
            sb.append("\"path\":").append(escape(snap.path)).append(",")
            sb.append("\"size\":").append(snap.size).append(",")
            sb.append("\"mtime\":").append(snap.mtime).append(",")
            sb.append("\"sha256\":").append(escape(snap.sha256)).append(",")
            sb.append("\"exists\":").append(snap.exists)
            sb.append("}")
        }
        sb.append("]")
        return sb.toString()
    }

    /** A piece of text inside JSON: quoted, with the escapes. */
    private fun escape(text: String): String {
        val sb = StringBuilder(text.length + 2)
        sb.append("\"")
        for (ch in text) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (ch.code < 0x20) {
                    sb.append(String.format("\\u%04x", ch.code))
                } else {
                    sb.append(ch)
                }
            }
        }
        sb.append("\"")
        return sb.toString()
    }
}
