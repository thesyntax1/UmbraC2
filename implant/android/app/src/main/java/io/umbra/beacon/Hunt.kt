package io.umbra.beacon

import java.io.File
import java.security.MessageDigest

/**
 * The hunt: the indicators of the team, looked for on this phone.
 *
 * A wipe takes the traces of the engagement away; a hunt looks for the
 * traces of somebody else.  The team keeps a catalogue of indicators --
 * a hash, a path, a process -- and asks every host of the fleet whether
 * it carries one of them.
 *
 * The rules of the module are the rules of the engagement:
 *
 *   * **the hunt never changes the phone.**  It reads, it reports, and
 *     the operator decides what to do with what it found.  An implant
 *     that removes a file while it hunts is an implant that destroys
 *     evidence;
 *   * **an indicator is matched exactly.**  A "possible match" is a
 *     finding the operator cannot act on;
 *   * **a limit is reported as a limit.**  The number of files that are
 *     hashed is bounded, and when the bound is reached the report says
 *     so: a hunt that silently looked at half the disk is a hunt that
 *     says "not found" when it means "not looked at".
 *
 * The kinds of indicator the module understands:
 *
 * | kind      | what it is                                 |
 * |-----------|--------------------------------------------|
 * | `path`    | a path on the phone                        |
 * | `hash`    | the SHA-256 of a file                      |
 * | `process` | the name of a process                      |
 *
 * The kinds of windows -- a mutex, a registry key, a certificate -- do
 * not exist on a phone, and the report says that instead of pretending
 * the phone was checked.
 */
object Hunt {
    /** How many files are hashed in one hunt. */
    const val MAX_HASHED_FILES = 20_000L

    /** How many bytes are hashed in one hunt. */
    const val MAX_HASHED_BYTES = 256L * 1024L * 1024L

    /** How deep the walk goes. */
    const val MAX_DEPTH = 24

    /** How many files are visited in one hunt. */
    const val MAX_VISITED_FILES = 200_000L

    /** One indicator of the catalogue. */
    data class Indicator(
        val id: String,
        val kind: String,
        val value: String,
        val label: String,
    )

    /** One finding: an indicator that is on this phone. */
    data class Finding(
        val id: String,
        val kind: String,
        val value: String,
        val label: String,
        val place: String,
        val note: String,
    )

    /** The result of one hunt. */
    data class Report(
        val findings: List<Finding>,
        /** The indicators that do not apply to this phone. */
        val skipped: List<Pair<String, String>>,
        val visited: Long,
        val hashed: Long,
        val bytes: Long,
        /** The limits that were reached. */
        val limits: List<String>,
        val roots: List<String>,
    )

    /**
     * Read the indicators of a task.
     *
     * The server sends the catalogue the operator chose and nothing
     * else: the note and the source of an indicator stay on the server,
     * because they are the words of the team and the phone has no
     * business reading them.
     */
    fun indicators(args: Upk): List<Indicator> {
        val items = args.field("indicators")?.list() ?: return emptyList()
        val out = mutableListOf<Indicator>()
        for (item in items) {
            val kind = item.field("kind")?.text()?.lowercase() ?: continue
            val value = item.field("value")?.text()?.trim() ?: continue
            if (value.isEmpty()) continue
            out.add(
                Indicator(
                    id = item.field("id")?.text() ?: "",
                    kind = kind,
                    value = value,
                    label = item.field("label")?.text() ?: "",
                )
            )
        }
        return out
    }

    /**
     * The roots the hunt walks.
     *
     * Without a root the hunt looks in the storage of the application
     * and in the temporary directory of the phone.  The whole of the
     * filesystem is a decision the operator has to make explicitly: it
     * is slow, and it reads the material of the user.
     */
    fun roots(args: Upk): List<File> {
        val out = mutableListOf<File>()
        val named = args.field("roots")?.list()?.mapNotNull { it.text()?.trim() }
        if (!named.isNullOrEmpty()) {
            for (root in named) {
                if (root.isNotEmpty()) out.add(File(root))
            }
            return out
        }
        val external = System.getenv("EXTERNAL_STORAGE")
        if (!external.isNullOrEmpty()) out.add(File(external))
        out.add(File(System.getProperty("java.io.tmpdir") ?: "/tmp"))
        return out
    }

    /** Look for every indicator of the catalogue on this phone. */
    fun scan(args: Upk): Report {
        val items = indicators(args)
        val roots = roots(args)
        val findings = mutableListOf<Finding>()
        val skipped = mutableListOf<Pair<String, String>>()
        val limits = mutableListOf<String>()
        var visited = 0L
        var hashed = 0L
        var bytes = 0L

        for (ind in items) {
            when (ind.kind) {
                "path" -> {
                    val file = File(ind.value)
                    if (file.exists()) {
                        val size = if (file.isFile) file.length() else 0L
                        findings.add(
                            Finding(
                                id = ind.id,
                                kind = ind.kind,
                                value = ind.value,
                                label = ind.label,
                                place = ind.value,
                                note = if (file.isDirectory) {
                                    "the path is a directory of this phone"
                                } else {
                                    "the path is a file of this phone, $size bytes"
                                },
                            )
                        )
                    }
                }
                "process" -> {
                    val seen = processNames()
                    if (seen.isEmpty()) {
                        limits.add("the process table of this phone is restricted by the platform")
                    } else if (seen.any { it.equals(ind.value, ignoreCase = true) }) {
                        findings.add(
                            Finding(
                                id = ind.id,
                                kind = ind.kind,
                                value = ind.value,
                                label = ind.label,
                                place = "the process table",
                                note = "the process ${ind.value} is running on this phone",
                            )
                        )
                    }
                }
                "hash" -> Unit
                "mutex", "registry", "certificate" -> {
                    skipped.add(
                        ind.id to "the kind \"${ind.kind}\" is a concept of windows, and a phone does not have it"
                    )
                }
                else -> {
                    skipped.add(ind.id to "the kind \"${ind.kind}\" is not one this implant knows")
                }
            }
        }

        // The hashes are the expensive ones: every file under the roots
        // is hashed and compared.
        val hashes = items.filter { it.kind == "hash" }
        if (hashes.isNotEmpty()) {
            for (root in roots) {
                val walk = walk(root, 0, hashes, findings, limits)
                visited += walk.visited
                hashed += walk.hashed
                bytes += walk.bytes
                if (walk.stopped) break
            }
        }

        return Report(
            findings = findings,
            skipped = skipped,
            visited = visited,
            hashed = hashed,
            bytes = bytes,
            limits = limits,
            roots = roots.map { it.path },
        )
    }

    /** The counters of one walk. */
    private data class Walked(
        val visited: Long,
        val hashed: Long,
        val bytes: Long,
        val stopped: Boolean,
    )

    /** Walk a tree and hash the files, looking for the hash indicators. */
    private fun walk(
        dir: File,
        depth: Int,
        hashes: List<Indicator>,
        findings: MutableList<Finding>,
        limits: MutableList<String>,
    ): Walked {
        var visited = 0L
        var hashed = 0L
        var bytes = 0L
        if (depth > MAX_DEPTH) {
            limits.add("the tree below ${dir.path} is deeper than $MAX_DEPTH levels")
            return Walked(visited, hashed, bytes, true)
        }
        val children = dir.listFiles() ?: return Walked(visited, hashed, bytes, false)
        for (child in children) {
            if (child.isDirectory) {
                val walk = walk(child, depth + 1, hashes, findings, limits)
                visited += walk.visited
                hashed += walk.hashed
                bytes += walk.bytes
                if (walk.stopped) return Walked(visited, hashed, bytes, true)
                continue
            }
            if (!child.isFile) continue
            visited += 1
            if (visited > MAX_VISITED_FILES) {
                limits.add("the hunt stopped after $MAX_VISITED_FILES files")
                return Walked(visited, hashed, bytes, true)
            }
            if (hashed >= MAX_HASHED_FILES) {
                limits.add("the hunt hashed $MAX_HASHED_FILES files and stopped")
                return Walked(visited, hashed, bytes, true)
            }
            if (bytes + child.length() > MAX_HASHED_BYTES) {
                limits.add("the hunt hashed $MAX_HASHED_BYTES bytes and stopped")
                return Walked(visited, hashed, bytes, true)
            }
            val data = try {
                child.readBytes()
            } catch (_: Throwable) {
                continue
            }
            hashed += 1
            bytes += data.size.toLong()
            val hex = sha256Hex(data)
            for (ind in hashes) {
                if (ind.value.equals(hex, ignoreCase = true)) {
                    findings.add(
                        Finding(
                            id = ind.id,
                            kind = ind.kind,
                            value = ind.value,
                            label = ind.label,
                            place = child.path,
                            note = "the file carries the hash, ${data.size} bytes",
                        )
                    )
                }
            }
        }
        return Walked(visited, hashed, bytes, false)
    }

    /**
     * The names of the processes of the phone, best effort.
     *
     * Android restricts `/proc` to the application on the modern
     * releases, so the list is often empty and the caller says so.
     */
    private fun processNames(): List<String> {
        return try {
            val proc = File("/proc")
            val pids = proc.listFiles { f -> f.name.all { it.isDigit() } } ?: return emptyList()
            val out = mutableListOf<String>()
            for (pid in pids.mapNotNull { it.name.toIntOrNull() }.sorted()) {
                val cmdline = try {
                    File("/proc/$pid/cmdline").readBytes()
                        .toString(Charsets.UTF_8)
                        .replace(' ', ' ')
                        .trim()
                } catch (_: Throwable) {
                    ""
                }
                if (cmdline.isEmpty()) continue
                out.add(cmdline.substringBefore(' '))
            }
            out
        } catch (_: Throwable) {
            emptyList()
        }
    }

    /** The digest of a buffer, in hex. */
    fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) sb.append("%02x".format(b.toInt() and 0xff))
        return sb.toString()
    }

    /**
     * Render the report of the hunt.
     *
     * The format is the format of the other reports of the implant: one
     * line per finding, and the limits at the end.
     */
    fun render(report: Report, items: List<Indicator>): String {
        val sb = StringBuilder()
        sb.append(
            "hunt.scan: %d indicators, %d found on this phone%n".format(
                items.size, report.findings.size
            )
        )
        for (f in report.findings) {
            val label = if (f.label.isEmpty()) "" else " (${f.label})"
            sb.append("  %-10s %-40s %s%s%n".format(f.kind, f.value, f.place, label))
            if (f.note.isNotEmpty()) sb.append("             ${f.note}%n".format())
        }
        for ((id, why) in report.skipped) {
            sb.append("  skipped    %-10s %s%n".format(id, why))
        }
        for (limit in report.limits) {
            sb.append("  limit      $limit%n".format())
        }
        sb.append(
            "hunt.scan: %d files visited, %d hashed, %d bytes read%n".format(
                report.visited, report.hashed, report.bytes
            )
        )
        return sb.toString()
    }
}
