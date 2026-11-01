# The emulator smoke test

> **What this page is.**  The procedure behind `.github/workflows/emulator.yml`
> and `implant/android/scripts/emulator-smoke.sh`: what is measured, what is
> deliberately *not* measured, and how to read a result.  The results
> themselves live on the `ci/log-emulator` branch, one directory per API
> level, with the raw command output beside them.

The Android implant had compiled and passed lint and had never started.  That
is a large distance: a compiler proves the source is well formed, a linter
proves the calls are shaped the way the platform documents them, and neither
proves that the application installs, launches, keeps a foreground service
alive, loads its native library on the ABI the device actually runs, or says
anything true when a permission is refused.

## 1. Where it runs, and what it is allowed to touch

| | |
|---|---|
| Host | GitHub Actions, `ubuntu-latest`, KVM |
| Device | Android emulator, `google_apis` (not `playstore`: the process map needs `adb root`) |
| API levels | 33 (the `minSdk` the app declares) and 34 (the `compileSdk`/`targetSdk`) |
| ABI | `x86_64`, chosen because the APK carries `lib/x86_64/libumbra.so`; an ARM library cannot load on an x86_64 emulator and expecting otherwise would be the classic self-deception |
| APK | the artefact `ci.yml` produced for **the same commit**, downloaded, hashed on both sides |
| Network | one loopback socket on the runner, mapped into the emulator with `adb reverse`; it speaks no protocol |
| Server | none |
| Task | none.  No command is queued and nothing is executed |

The APK is built with `UMBRA_HOST=127.0.0.1`, `UMBRA_PORT=4001` and the CI's
test PSK.  Inside the emulator that address is the emulator itself, and the
`adb reverse` maps it to a `nc -lk` on the runner that accepts a connection and
answers nothing.  The socket exists for one reason: the beacon's handshake path
is what builds the metadata dictionary, which is what initialises `SysInfo`,
which is what calls `System.loadLibrary("umbra")`.  Without a listening socket
the beacon fails at `connect()` and the native library is never loaded, so the
library check could not be performed at all.

## 2. What is measured

Each line of the report is one command whose output was kept.

| Check | The question | How it is answered |
|---|---|---|
| `environment` | is this the API level the job asked for? | `getprop ro.build.version.sdk` against the matrix entry |
| `apk-integrity` | is the file installed the file that was built? | `sha256sum` on the runner and inside the device |
| `abi-match` | does the APK carry the ABI of the emulator? | `lib/` entries in the APK against `ro.product.cpu.abilist` |
| `install` | did `adb install` succeed? | its exit code and the word `Success` |
| `package-manager` | does the package exist afterwards? | `pm list packages`, `dumpsys package` |
| `launch` | does the consent screen start? | `am start -W` and a live pid |
| `launch-crash` | did it crash or ANR? | `FATAL EXCEPTION` / `ANR in io.umbra.beacon` |
| `notif-dialog` | does the app ask for `POST_NOTIFICATIONS` itself? | the platform dialog on the screen |
| `notif-denial` | is the refusal recorded as a refusal? | the permission state in `dumpsys package` after tapping *Don't allow* |
| `service-start` | does the foreground service start? | a `ServiceRecord` in `dumpsys activity services` |
| `service-foreground` | is it *foreground*? | `isForeground=true` in that record |
| `service-crash` | does starting it kill the process? | the pid, and the log |
| `notification-suppressed` | is the notification off the screen while the permission is refused? | `dumpsys notification` for the package |
| `notification` | is it on the screen once the permission is granted? | the same, after `pm grant` and a second start |
| `native-load` | did the library load? | `libumbra.so` in `/proc/<pid>/maps` |
| `native-abi` | is it the build for the device's ABI? | the path in the map is `lib/x86_64/` |
| `kill-restart` | does a SIGKILLed process come back? | 60 s of watching `pidof` |
| `service-restart` | does the *service* come back, not only the process? | the service record again |
| `stop` / `stop-notification` | can the consent screen stop it? | the record is gone; the notification is gone |
| `logcat` | any fatal record in the whole run? | the kept log |

## 3. What is deliberately not measured

These are written as `NOT VERIFIED` in every report, with the reason, because
silence would read as a pass.

* **The location permissions.**  `Sense.kt` is reached from a task, and this
  stage executes no task.  The guard exists in code and has been read; it has
  not been run.
* **The exact-alarm fallback.**  `Persistence.kt` arms its alarm from a task
  for the same reason.  The `canScheduleExactAlarms()` branch and the
  "the phone denied exact alarms, so the alarm is inexact" sentence have not
  been executed on a device.
* **The notification-refusal sentence.**  The implant has no sentence of its
  own for a refused `POST_NOTIFICATIONS`: it lets the platform be silent.  That
  is a finding about the code, not a test result, and it is recorded as such.
* **Any physical phone.**  An emulator is not a phone.  OEM battery managers,
  vendor service restrictions and real hardware are outside this stage, and a
  green run here is not evidence about them.
* **Tasks, transports, protocol.**  Nothing operational happens here.  The
  beacon's ability to run a command is a later stage and is tested against a
  synthetic server with fixed messages, without executing anything.

## 4. How to read a result

A run is **PASS** when every executed check is `PASS`; `FAIL` when any check is
`FAIL`; `NOT VERIFIED` is not a failure and does not make a run green — it is a
check that could not be performed, and the report says why.  The workflow goes
red on any `FAIL` and keeps the report either way (`ci/log-emulator`, plus the
job summary).

The rule the whole stage is built around:

> A behaviour that was not observed on the emulator is not PASS.  Compiling,
> packaging, linting and reading the code are four separate kinds of evidence
> and none of them is a runtime result.

## 5. Reproducing it by hand

```bash
# 1. the APK of a commit whose ci.yml run succeeded
gh run list --workflow=ci.yml --limit 5 --json databaseId,headSha,conclusion
gh run download <run-id> -n umbra-debug-apk -D apk
sha256sum apk/app-debug.apk

# 2. an emulator that allows adb root
sdkmanager "system-images;android-34;google_apis;x86_64"
avdmanager create avd -n umbra-34 -k "system-images;android-34;google_apis;x86_64" --device pixel_5
emulator -avd umbra-34 -no-window -gpu swiftshader_indirect -noaudio -no-boot-anim &
adb wait-for-device

# 3. the loopback socket the app is allowed to reach, and the mapping
nc -lk 127.0.0.1 4001 > /tmp/nc.log &
adb reverse tcp:4001 tcp:4001

# 4. the test
bash implant/android/scripts/emulator-smoke.sh --apk apk/app-debug.apk --out results/api-34 --api 34
```

Everything the run learned is in `results/api-34/`: `result.md` (the table),
`result.json` (the same, for a script), `environment.md`, `apk.txt`, and
`raw/` — every command's output, including the UI dumps that prove which screen
was on the device when a tap was sent.
