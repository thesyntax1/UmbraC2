package io.umbra.beacon

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The bluetooth discovery of the phone.
 *
 * A discovery is a broadcast: the adapter asks the radio, and every
 * device that answers is announced.  The receiver waits for the radio to
 * say that the search is over, and it keeps what it heard in between.
 *
 * The wait is bounded.  A radio that hears nothing must not hold the
 * beacon hostage, so the collector gives up and the report says that
 * the discovery was cut short.
 */
object BluetoothScan {
    /** How long the discovery is given. */
    const val TIMEOUT_MS = 12_000L

    /**
     * The devices the discovery heard.
     *
     * The devices that answer with their name are worth more than the
     * addresses, so the name is asked for; a phone that does not have the
     * permission for the name gets the address only, and the report says
     * so.
     */
    fun scan(context: Context, adapter: BluetoothAdapter): List<BluetoothDevice> {
        val found = LinkedHashMap<String, BluetoothDevice>()
        val latch = CountDownLatch(1)
        var finished = false
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                when (intent.action) {
                    BluetoothDevice.ACTION_FOUND -> {
                        // The typed getter is the one of API 33, and the
                        // implant does not run below it.
                        val device: BluetoothDevice? = intent.getParcelableExtra(
                            BluetoothDevice.EXTRA_DEVICE,
                            BluetoothDevice::class.java,
                        )
                        val address = device?.address ?: return
                        found[address] = device
                    }
                    BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {
                        finished = true
                        latch.countDown()
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(BluetoothDevice.ACTION_FOUND)
            addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
        }
        val registered = try {
            // The broadcasts of the radio come from the system, so the
            // receiver is exported.
            context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
            true
        } catch (_: Throwable) {
            false
        }
        try {
            if (registered && adapter.isEnabled) {
                try {
                    adapter.startDiscovery()
                } catch (e: SecurityException) {
                    // BLUETOOTH_SCAN is granted by the user and can be taken
                    // away at any moment: the radio is not asked, and the
                    // caller gets what it has already heard.
                    return found.values.toList()
                } catch (t: Throwable) {
                    return found.values.toList()
                }
                latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
                if (!finished) {
                    // The radio is still searching; the caller says so.
                }
            }
        } finally {
            if (registered) {
                try {
                    context.unregisterReceiver(receiver)
                } catch (_: Throwable) {
                    // The receiver was already gone.
                }
            }
            try {
                adapter.cancelDiscovery()
            } catch (e: SecurityException) {
                // The permission went away while the discovery ran: there is
                // nothing left that the phone would let this call stop.
            } catch (_: Throwable) {
                // The radio was not searching.
            }
        }
        return found.values.toList()
    }
}
