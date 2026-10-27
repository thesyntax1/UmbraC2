package io.umbra.beacon

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Wakes the beacon service when the system killed it.
 *
 * The alarm is the second persistence technique: it is armed with an exact
 * alarm that survives Doze, and it brings the service back when the phone
 * has been idle for hours.  The pending intent is the one the persistence
 * manager arms, so the two agree on the request code.
 */
class AlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        BeaconService.start(context)
    }
}
