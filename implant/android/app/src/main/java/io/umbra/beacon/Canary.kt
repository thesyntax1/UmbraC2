package io.umbra.beacon

import java.io.File
import java.security.MessageDigest

/**
 * The tripwires of the engagement: small files that nobody touches.
 *
 * A canary is a small file with a secret in it.  The implant plants it
 * in a place where nothing of the engagement belongs, and nobody knows
 * that it is there -- so nobody touches it.  When the file changes or
 * disappears, somebody else was on the phone, and the operator learns
 * about it while the engagement is still running.
 *
 * The rules of the module are three:
 *
 *   * **the implant remembers what it planted.**  The size, the time
 *     of the last change and the digest of the file are written next
 *     to the canary, because the implant is the only one that knows
 *     what it wrote;
 *   * **the check never changes the phone.**  It reads the file and
 *     says whether it is as it was planted; a check that repairs the
 *     canary would hide the very thing it is looking for;
 *   * **the verdict travels with the answer.**  The states of the
 *     canaries travel in the metadata of the answer as one short
 *     string ("c-0001=intact;c-0002=changed"), so the ledger of the
 *     server and the answer the operator reads cannot disagree.
 *
 * The states are the three a tripwire can be in:
 *
 * | state     | what it means                        |
 * |-----------|--------------------------------------|
 * | `intact`  | the file is as it was planted         |
 * | `changed` | the file was touched                 |
 * | `missing` | the file is gone                     |
 */
object Canary {
    /** The state of a canary that is as it was planted. */
    const val STATE_INTACT = "intact"

    /** The state of a canary that was touched. */
    const val STATE_CHANGED = "changed"

    /** The state of a canary that is gone. */
    const val STATE_MISSING = "missing"

    /** The name of the directory where the canaries and their facts live. */
    const val STATE_DIR = "canaries"

    /**
     * The facts of one canary: what the implant wrote and where.
     *
     * The phone keeps them next to the canary, because the phone is the
     * only one that knows what it wrote.
     */
    data class Facts(
        val id: String,
        val path: String,
        val size: Long,
        val mtime: Long,
        val sha256: String,
    )

    /** What happened when a canary was planted. */
    data class Planted(
        val id: String,
        val path: String,
        val text: String,
        val error: String = "",
    )

    /** What the look at the canaries found. */
    data class Checked(
        val states: String,
        val text: String,
        val checked: Long,
        val touched: Long,
        val error: String = "",
    )

    /**
     * Plant one canary on this phone.
     *
     * The file carries the token of the canary and nothing else.  The
     * facts of it are written next to it, so the check knows what to
     * compare against.
     */
    fun plant(args: Upk, stateDir: String): Planted {
        val id = args.field("id")?.text()?.trim() ?: ""
        if (id.isEmpty()) {
            return Planted("", "", "", "canary.plant: the canary has no id")
        }
        val token = args.field("token")?.text()?.trim() ?: ""
        if (token.isEmpty()) {
            return Planted("", "", "", "canary.plant: the canary has no token")
        }
        if (stateDir.isEmpty()) {
            return Planted("", "", "", "canary.plant: the phone has no place to keep the canary")
        }
        val label = args.field("label")?.text() ?: ""
        val dir = File(stateDir, STATE_DIR)
        if (!dir.exists() && !dir.mkdirs()) {
            return Planted(id, "", "", "canary.plant: ${dir.path} could not be made")
        }
        // The operator may name the place of the canary; without a name
        // the canary goes into the state of the implant, which is a
        // place where nothing of the engagement belongs.
        val named = args.field("path")?.text()?.trim() ?: ""
        val file = if (named.isEmpty()) File(dir, "$id.dat") else File(named)
        val parent = file.parentFile
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return Planted(id, file.path, "", "canary.plant: ${parent.path} could not be made")
        }
        val bytes = token.toByteArray(Charsets.UTF_8)
        try {
            file.writeBytes(bytes)
        } catch (e: Exception) {
            return Planted(id, file.path, "", "canary.plant: ${file.path} could not be written")
        }
        val facts = Facts(
            id = id,
            path = file.path,
            size = bytes.size.toLong(),
            mtime = file.lastModified(),
            sha256 = sha256(bytes),
        )
        val state = factsFile(stateDir, id)
        try {
            state.writeText(renderFacts(facts))
        } catch (e: Exception) {
            return Planted(id, file.path, "", "canary.plant: ${state.path} could not be written")
        }
        val sb = StringBuilder()
        sb.append("canary.plant: $id is planted\n")
        if (label.isNotEmpty()) sb.append("  the label is $label\n")
        sb.append("  the file is ${file.path}\n")
        sb.append("  ${facts.size} bytes, written at ${facts.mtime}, digest ${facts.sha256}\n")
        return Planted(id, file.path, sb.toString())
    }

    /**
     * Look at the canaries of this phone and say whether they are as
     * they were planted.
     *
     * The check reads and reads only.
     */
    fun check(args: Upk, stateDir: String): Checked {
        val ids = wanted(args)
        if (ids.isEmpty()) {
            return Checked("", "", 0, 0, "canary.check: no canary was named")
        }
        if (stateDir.isEmpty()) {
            return Checked("", "", 0, 0, "canary.check: the phone has no place to keep the facts")
        }
        val verdicts = mutableListOf<String>()
        val lines = mutableListOf<String>()
        var touched = 0L
        for (id in ids) {
            val verdict = look(stateDir, id)
            if (verdict.first == STATE_CHANGED || verdict.first == STATE_MISSING) {
                touched++
            }
            verdicts.add("$id=${verdict.first}:${verdict.second}")
            lines.add(String.format("  %-10s %-8s %s", id, verdict.first, verdict.second))
        }
        val sb = StringBuilder()
        sb.append(
            "canary.check: ${ids.size} canaries looked at, $touched of them are not as they were\n",
        )
        for (line in lines) sb.append(line).append("\n")
        return Checked(verdicts.joinToString(";"), sb.toString(), ids.size.toLong(), touched)
    }

    /**
     * The canaries the server asked about.
     */
    fun wanted(args: Upk): List<String> {
        val out = mutableListOf<String>()
        val items = args.field("canaries")?.list() ?: return out
        for (item in items) {
            val id = item.field("id")?.text()?.trim() ?: continue
            if (id.isEmpty() || out.contains(id)) continue
            out.add(id)
        }
        return out
    }

    /**
     * Look at one canary and say what state it is in.
     */
    fun look(stateDir: String, id: String): Pair<String, String> {
        val facts = readFacts(stateDir, id)
            ?: return Pair(STATE_MISSING, "the implant does not know this canary")
        val file = File(facts.path)
        if (!file.exists()) {
            return Pair(STATE_MISSING, "the file of the canary is gone")
        }
        val data = try {
            file.readBytes()
        } catch (e: Exception) {
            return Pair(STATE_MISSING, "the file of the canary could not be read")
        }
        if (data.size.toLong() != facts.size) {
            return Pair(STATE_CHANGED, "the file of the canary is ${data.size} bytes now")
        }
        if (sha256(data) != facts.sha256) {
            return Pair(STATE_CHANGED, "the file of the canary was touched")
        }
        // The content is the same.  The time of the last change is not
        // part of the verdict, but it is worth saying: a file that was
        // written again with the same content was written again.
        val mtime = file.lastModified()
        if (mtime != facts.mtime) {
            return Pair(
                STATE_INTACT,
                "the file is as it was planted but it was written again at $mtime",
            )
        }
        return Pair(STATE_INTACT, "the file is as it was planted")
    }

    /**
     * The facts of one canary, as they are written on the disk.
     */
    private fun renderFacts(facts: Facts): String {
        val sb = StringBuilder()
        sb.append("id=${facts.id}\n")
        sb.append("path=${facts.path}\n")
        sb.append("size=${facts.size}\n")
        sb.append("mtime=${facts.mtime}\n")
        sb.append("sha256=${facts.sha256}\n")
        return sb.toString()
    }

    /**
     * The file where the facts of one canary are kept.
     */
    private fun factsFile(stateDir: String, id: String): File =
        File(File(stateDir, STATE_DIR), "$id.state")

    /**
     * Read the facts of one canary.
     */
    private fun readFacts(stateDir: String, id: String): Facts? {
        val file = factsFile(stateDir, id)
        if (!file.exists()) return null
        val raw = try {
            file.readText()
        } catch (e: Exception) {
            return null
        }
        var facts = Facts(id, "", 0, 0, "")
        for (line in raw.lines()) {
            val split = line.indexOf('=')
            if (split <= 0) continue
            val key = line.substring(0, split).trim()
            val value = line.substring(split + 1).trim()
            when (key) {
                "id" -> facts = facts.copy(id = value)
                "path" -> facts = facts.copy(path = value)
                "size" -> facts = facts.copy(size = value.toLongOrNull() ?: 0L)
                "mtime" -> facts = facts.copy(mtime = value.toLongOrNull() ?: 0L)
                "sha256" -> facts = facts.copy(sha256 = value)
            }
        }
        if (facts.path.isEmpty()) return null
        return facts
    }

    /**
     * The digest of a piece of data, as the lower case hex of the bytes.
     */
    private fun sha256(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) sb.append("%02x".format(b.toInt() and 0xff))
        return sb.toString()
    }
}
