# The Android lint findings, one at a time

> Lint reported **22 errors and 30 warnings** on `1aac1a9`, the commit where
> `assembleDebug` first succeeded.  The errors are closed — CI's `lintDebug`
> reports **0 errors and 29 warnings** on `e751792` — and this page is the
> record of what each one was, what was done about it, and what is still only
> a reading of the code rather than an observation of a phone.
>
> **What this page is not.**  It is not a security audit, and "0 errors" is not
> "0 problems".  Lint sees calls and manifests; it does not see whether a
> permission is granted at run time, whether the operator's sentence is the
> right one, or whether the phone restarts a service.  Every row below says
> which kind of evidence it has.

## 1. The method

For every `MissingPermission` finding the same five questions were asked, in
this order, before anything was changed:

1. **Which permission does the API demand, and is it really that one?**  The
   answer comes from the platform's own manifest (`frameworks/base/core/res/
   AndroidManifest.xml`) and the API reference, not from lint's message.
2. **What is its protection level?**  A `dangerous` permission is granted by
   the user at run time and can be taken away; a `normal` one is granted at
   install and cannot be refused; `signature|privileged` cannot be held by an
   application a user installs, at all.
3. **Can this application ever hold it?**  If not, the call is not guarded — it
   is removed, because a call that can only throw is not a feature.
4. **What happens when it is refused?**  The answer has to be a sentence the
   operator reads, in the report of the collector, and it has to be true.
5. **Can `SecurityException` still fire despite a check?**  Yes: a permission
   can be revoked between the check and the call.  Every call site therefore
   names `SecurityException` in its own handler, even where a check precedes
   it.

No rule was disabled, no `@SuppressLint`, no baseline file, no `lint.xml`
entry, and no manifest permission was removed to make a message go away.

## 2. The fifteen `MissingPermission` findings

Commits: `ae7b744` (the guards), `2915e19` (the alarm and the manifest),
`4b33576` (the indentation).  CI: `lintDebug` green from `e751792` on.

| # | Call site | Permission | Protection | Held by a user-installed app? | What happens on refusal | Where the refusal is caught |
|---|---|---|---|---|---|---|
| 1 | `Sense.kt` `getLastKnownLocation` (GPS + network provider) | `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION` | dangerous | only if the user grants it | the note *"the last known position of $provider is refused"* and the row is omitted — the collector continues with the other provider | check at the top of `location()`, plus `catch (SecurityException)` around each call |
| 2 | `Sense.kt` `getCurrentLocation` (the bounded wait for a fresh fix) | same two | dangerous | as above | the note *"the position of $provider is refused"*, `return null`, and the caller says *"no fresh fix"* | `catch (SecurityException)` in `freshFix` |
| 3 | `Sense.kt` `scanResults` | `ACCESS_FINE_LOCATION` (a scan result is a location) | dangerous | only if granted | the note *"the scan results are refused: the location permission is not granted"* | `catch (SecurityException)` |
| 4 | `Sense.kt` `configuredNetworks` | `ACCESS_FINE_LOCATION`; since Android 10 the platform also hides the list from anything that is not the profile owner | dangerous | rarely, even when granted | the note *"the saved networks are refused"*, and an empty list says the platform hides them | `catch (SecurityException)` + an explicit empty-list note |
| 5 | `Sense.kt` `bondedDevices` | `BLUETOOTH_CONNECT` | dangerous | only if granted | the note *"the paired devices are refused: the bluetooth connect permission is not granted"* | `catch (SecurityException)` around the loop |
| 6 | `Sense.kt` `device.name`, `device.type` (paired loop) | `BLUETOOTH_CONNECT` | dangerous | only if granted | the same note; the row is dropped rather than filled with a guess | the loop's handler |
| 7 | `Sense.kt` `device.name`, `device.type` (discovery loop) | `BLUETOOTH_CONNECT` | dangerous | only if granted | the note *"the devices the discovery heard are refused"* | the loop's handler |
| 8 | `BluetoothScan.kt` `startDiscovery` | `BLUETOOTH_SCAN` | dangerous | only if granted | the scan returns what it has already heard and stops asking — it does not pretend a scan happened | `catch (SecurityException)` with an early return |
| 9 | `BluetoothScan.kt` `cancelDiscovery` | `BLUETOOTH_SCAN` | dangerous | only if granted | nothing to cancel: the permission that started the scan is gone | `catch (SecurityException)` in the `finally` block |
| 10 | `Lab.kt` `line1Number` | `READ_PHONE_STATE` | dangerous | only if granted | `sensors["line1"] = "unknown"`; the report's permission map already says which permission is missing | `catch (SecurityException)` returning `null` |
| 11 | `Lab.kt` `getSubscriberId` | `READ_PRIVILEGED_PHONE_STATE` | signature\|privileged | **never** | — the call is **removed**: `sensors["subscriber"] = "unknown"`, which is what the call produced anyway | no call, so nothing to catch |
| 12 | `Media.kt` `openCamera` | `CAMERA` | dangerous | only if granted | `failure = "the camera permission is not granted: …"`, and the caller returns that sentence instead of an empty frame | `catch (SecurityException)` |
| 13 | `Forensics.kt` `PackageInstaller.uninstall` | `DELETE_PACKAGES` (signature\|privileged) **or** `REQUEST_DELETE_PACKAGES` (normal) | mixed | `REQUEST_DELETE_PACKAGES` yes, `DELETE_PACKAGES` no | the branch is entered only when the phone is the device owner; the platform exempts the owner in `PackageInstallerService.uninstall`, so this is the sanctioned path, and the handler says so if the check and the call ever disagree | `catch (SecurityException)` with the sentence *"only the device owner or the installer of record may remove a package"* |

Findings 1–12 are twelve rows of the table for fifteen lint findings: lint
counts the two `device.name`/`device.type` reads in each of the two loops
separately, which is why `Sense.kt` alone carries nine of them.

### The one that was not a guard

`getSubscriberId` is the interesting one, and the only place where the answer
was *not* a check.  `READ_PRIVILEGED_PHONE_STATE` is `signature|privileged`:
the platform grants it to applications signed with the platform key or living
in the privileged partition.  Nothing a user installs can hold it, so the call
could only ever throw, and the code already wrote `unknown` when it did.  The
call is gone and the field still says `unknown` — the same answer, without the
throw.  A guard here would have been a lie in the shape of a check.

## 3. `ScheduleExactAlarm`

`setExactAndAllowWhileIdle` throws `SecurityException` when the phone has taken
the exact-alarm capability away, and since Android 14 the capability is
*denied by default* for applications that target 33 and above.  The arm now
asks `AlarmManager.canScheduleExactAlarms()` and falls back to
`setAndAllowWhileIdle`, which is inexact but still wakes the service:

```kotlin
if (canScheduleExact(context)) {
    manager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pending)
} else {
    manager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pending)
}
```

and the report says which of the two the phone got rather than claiming the
exact one:

> *"the alarm: installed; the phone denied exact alarms, so the alarm is
> inexact"*

The exact alarm is not necessary for the beacon to survive — the job scheduler,
the boot receiver and the accessibility service are the other three
techniques — so the fallback keeps the technique installed and tells the truth
about it instead of failing the whole installation.

## 4. The four manifest findings

`PermissionImpliesUnsupportedChromeOsHardware` is lint saying that
`READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS` and `CAMERA` imply telephony and
camera hardware, and that a device without either would be filtered out of the
store.  The manifest now states what the code already assumed:

```xml
<uses-feature android:name="android.hardware.telephony" android:required="false" />
<uses-feature android:name="android.hardware.camera" android:required="false" />
<uses-feature android:name="android.hardware.camera.any" android:required="false" />
```

`required="false"` is a claim the code backs: a phone with no radio answers
*"the phone has no camera"* / *"the phone has no telephony"* from the
collectors, which is a sentence, not a crash.  No permission was removed, and
nothing was added to the manifest to make a message disappear.

## 5. The two `SuspiciousIndentation` findings

```kotlin
return try {
    val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler
        scheduler != null && scheduler.allPendingJobs.any { it.id == UmbraJobService.JOB_ID }
} catch …
```

Kotlin parses the second line as a new statement either way (a binary operator
cannot continue the line above it), so the value of the block was already the
expression; the indentation said otherwise.  De-indented, no other change, same
behaviour — `4b33576`.

## 6. What is still only a reading

The fixes are compiled and lint-clean, and **not one of the refusal paths has
been executed on a device**.  The emulator stage (`docs/EMULATOR-SMOKE.md`)
executes the ones that need no server: the notification permission dialog and
its refusal.  The location, camera, Bluetooth, SMS and exact-alarm refusals are
reached from a task, and this programme does not execute tasks — so they stay
**code-only evidence** until a synthetic test drives the collectors with the
permission revoked, which is a later stage.

## 7. The twenty-nine warnings, classified

Zero errors is not zero problems, and a warning is a finding somebody decided
not to act on.  They are grouped here by what would happen if nobody acted,
which is the only ranking that matters.  None of them is disabled, and none is
suppressed.

### Tier 1 — correctness or security, to be fixed

| Finding | Count | Where | Why it matters |
|---|---|---|---|
| `StaticFieldLeak` | 3 | `Overlay.kt:16`, `Overlay.kt:53`, `TaskRunner.kt:91` | a static reference to a `Context`/`View` outlives the activity that made it: a leaked window, and on a phone that runs for weeks, an out-of-memory exit that looks like the phone killing the beacon |
| `WakelockTimeout` | 1 | `BeaconService.kt:211` | `acquire()` without a timeout holds a partial wake lock until the process dies; a bug in the loop turns into a flat battery, which is the loudest possible way for an implant to be noticed |
| `QueryPermissionsNeeded` | 1 | `Desktop.kt:116` | the app-list query returns only the visible packages on Android 11+; the report may be quietly incomplete rather than empty, which is worse |
| `DataExtractionRules` | 1 | `AndroidManifest.xml` | `allowBackup="false"` is deprecated on 12+: without `dataExtractionRules` the *device transfer* path is not stated, and the implant's state file could be copied to another phone by the system |
| `HardwareIds` | 1 | `Lab.kt:222` | `line1Number` is not a device identifier and is empty on most modern SIMs; the check that uses it is decoration — it is honest, but it is not the emulator check it looks like |
| `DefaultLocale` | 1 | `Credentials.kt:133` | `String.format` without a locale on a phone set to Arabic or Turkish formats numbers differently, and one of those locale-specific results will eventually be parsed |
| `BatteryLife` | 1 | `Vendor.kt:182` | `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is a Play policy violation; for a lab build that is acceptable, for anything distributed it is not, and the report should say which |

### Tier 2 — dead code, to be removed when the module is touched

| Finding | Count | Where | Why it is only a warning |
|---|---|---|---|
| `ObsoleteSdkInt` | 11 | `BeaconService` (4), `Projection` (3), `Vendor` (2), `MainActivity`, `Wipe` | `minSdk` is 33, so `SDK_INT >= O` / `< Q` are constants; the branches are dead.  They are correct, and deleting them is a mechanical change that should not be mixed with a permission fix |

### Tier 3 — cosmetic, no behaviour

| Finding | Count | Where | Note |
|---|---|---|---|
| `SetTextI18n` | 7 | `MainActivity.kt` | the consent screen writes English literals into `TextView`s; the app has no translations and is not distributed through a store |
| `RedundantLabel` | 1 | `AndroidManifest.xml:83` | the activity repeats the application label |
| `MissingApplicationIcon` | 1 | `AndroidManifest.xml:73` | no `android:icon`: the launcher shows a default.  A deliberate omission — an implant with a memorable icon is a memorable implant — and it should be *stated* rather than linted at, which is why it stays a warning |

The order in which these are worth fixing is Tier 1, then the dead branches,
then nothing.  That order is the next stage's work, not this page's.
