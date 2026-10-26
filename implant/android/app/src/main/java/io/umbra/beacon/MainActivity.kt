package io.umbra.beacon

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * Minimal consent + control UI.
 *
 * The implant only runs after the device owner taps "Start"; there is no
 * silent auto-start. That is a deliberate guardrail, not a limitation of the
 * protocol implementation.
 */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private var logLines = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setTitle(R.string.app_name)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            setBackgroundColor(Color.WHITE)
        }

        val notice = TextView(this).apply {
            text = getString(R.string.consent_notice)
            textSize = 15f
            setTextColor(Color.DKGRAY)
        }

        val info = TextView(this).apply {
            val cfg = RemoteConfig.load()
            text = if (cfg == null) {
                "No configuration baked into this build (UMBRA_PSK missing)."
            } else {
                "server   : ${cfg.host}:${cfg.port}\n" +
                    "transport: ${cfg.transport}\n" +
                    "agent id : ${cfg.agentId}\n" +
                    "beacon   : ${cfg.sleepSec}s ± ${cfg.jitterPercent}%"
            }
            textSize = 14f
            setPadding(0, 32, 0, 32)
        }

        status = TextView(this).apply {
            text = "status: idle"
            textSize = 14f
            setTextColor(Color.BLACK)
        }

        val logView = TextView(this).apply {
            textSize = 12f
            setTextColor(Color.DKGRAY)
            setPadding(0, 24, 0, 0)
        }

        val start = Button(this).apply {
            text = "Start beacon"
            setOnClickListener {
                RemoteConfig.load()?.let {
                    BeaconService.start(this@MainActivity)
                    status.text = "status: running"
                    append("beacon started")
                } ?: run { status.text = "status: no configuration" }
            }
        }

        val stop = Button(this).apply {
            text = "Stop beacon"
            setOnClickListener {
                BeaconService.stop(this@MainActivity)
                status.text = "status: stopped"
                append("beacon stopped")
            }
        }

        val scroll = ScrollView(this).apply {
            addView(logView)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }
        appendLine = { line ->
            logLines.append(line).append('\n')
            if (logLines.length > 8000) logLines = StringBuilder(logLines.substring(logLines.length - 4000))
            logView.text = logLines.toString()
        }

        root.addView(notice)
        root.addView(info)
        root.addView(status)
        root.addView(start)
        root.addView(stop)
        root.addView(scroll)
        setContentView(root)

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
        }
        if (BeaconService.isActive()) status.text = "status: running"
    }

    private var appendLine: (String) -> Unit = {}

    private fun append(line: String) = appendLine(line)
}
