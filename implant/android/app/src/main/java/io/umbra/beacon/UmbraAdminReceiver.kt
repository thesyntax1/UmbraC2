package io.umbra.beacon

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent

/**
 * The device administrator of the implant.
 *
 * A phone that is enrolled to a device owner cannot be wiped by the user,
 * and the enrolment survives everything a normal application survives.  It
 * is the most extreme technique of the catalogue: the operator has to know
 * that the phone is no longer a personal device.
 *
 * The enrolment is only possible when the application was pushed to the
 * phone as the device owner candidate, so the implant asks the system and
 * reports what the system answered.
 */
class UmbraAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        // The administrator is active: the implant may be enrolled.
    }

    override fun onDisabled(context: Context, intent: Intent) {
        // The administrator was taken away.
    }

    companion object {
        /** The component the operator enrols. */
        const val COMPONENT = "io.umbra.beacon/.UmbraAdminReceiver"
    }
}
