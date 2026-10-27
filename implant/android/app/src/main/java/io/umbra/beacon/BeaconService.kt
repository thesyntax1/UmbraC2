package io.umbra.beacon

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground service that keeps the beacon alive.
 *
 * Android requires a visible notification for long-running background work, so
 * this service is deliberately honest about what it is: it is meant for
 * authorised lab devices and internal red-team engagements.
 */
class BeaconService : Service(), Beacon.Listener {
    companion object {
        const val CHANNEL_ID = "umbra-beacon"
        const val NOTIFICATION_ID = 4711
        const val ACTION_STOP = "io.umbra.beacon.STOP"
        private val active = AtomicBoolean(false)

        fun isActive(): Boolean = active.get()

        fun start(context: Context) {
            val intent = Intent(context, BeaconService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /**
         * Ask the service to stop.
         *
         * `startService` throws IllegalStateException once the app is in the
         * background on API 26+, so fall back to a plain stopService: that skips
         * onStartCommand but still runs onDestroy, which stops the beacon.
         */
        fun stop(context: Context) {
            val intent = Intent(context, BeaconService::class.java)
            intent.action = ACTION_STOP
            try {
                context.startService(intent)
            } catch (_: IllegalStateException) {
                context.stopService(Intent(context, BeaconService::class.java))
            }
        }
    }

    private var beacon: Beacon? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIFICATION_ID, notification("starting…"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopBeacon()
            return START_NOT_STICKY
        }
        if (beacon == null) startBeacon()
        return START_STICKY
    }

    private fun startBeacon() {
        val cfg = RemoteConfig.load(this)
        if (cfg == null) {
            notify("configuration missing (UMBRA_PSK)")
            stopBeacon()
            return
        }
        acquireWakeLock()
        active.set(true)
        val b = Beacon(cfg, this)
        beacon = b
        b.start()
        notify("beacon running -> ${cfg.host}:${cfg.port}")
    }

    private fun stopBeacon() {
        beacon?.stop()
        beacon = null
        active.set(false)
        releaseWakeLock()
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        beacon?.stop()
        active.set(false)
        releaseWakeLock()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // -- Beacon.Listener ------------------------------------------------
    override fun onLog(message: String) {
        notify(message)
    }

    override fun onStopped() {
        releaseWakeLock()
        active.set(false)
    }

    // -- notification / wake lock ---------------------------------------
    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.description = getString(R.string.notification_channel_description)
        mgr.createNotificationChannel(channel)
    }

    private fun notification(text: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(true)
            .build()
    }

    private fun notify(text: String) {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.notify(NOTIFICATION_ID, notification(text))
    }

    private fun acquireWakeLock() {
        if (wakeLock != null) return
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "umbra:beacon").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) it.release()
        }
        wakeLock = null
    }
}
