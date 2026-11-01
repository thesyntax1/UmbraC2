#!/usr/bin/env bash
# Boot an Android emulator and run the smoke test on it.
#
# The third-party action this replaces hides its failure in a job log that
# lives on a blob host this repository cannot read: a red dot and an exit
# code.  Here every step writes into the report directory instead -- the SDK
# install, the AVD creation, the emulator's own output, the boot loop -- so a
# failure is a file in the artefact rather than a guess.
#
#   bash emulator-boot.sh --api 34 --apk <path> --out <dir>
#
# Exit codes: 0 the smoke test passed, 1 it failed, 2 the emulator never came
# up (which is a failure of the harness, and is reported as such).

set -u

API=""
APK=""
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --api) API="$2"; shift 2 ;;
        --apk) APK="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [ -z "$API" ] || [ -z "$APK" ] || [ -z "$OUT" ]; then
    echo "usage: emulator-boot.sh --api <level> --apk <path> --out <dir>" >&2
    exit 2
fi

mkdir -p "$OUT"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ] || [ ! -d "$SDK" ]; then
    echo "no Android SDK: ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-unset} ANDROID_HOME=${ANDROID_HOME:-unset}" | tee "$OUT/harness-error.txt"
    exit 2
fi
export ANDROID_SDK_ROOT="$SDK"
export ANDROID_HOME="$SDK"
export PATH="$SDK/platform-tools:$SDK/emulator:$SDK/cmdline-tools/latest/bin:$PATH"

# The AVD lives in a directory this script owns.  The runner image sets its
# own ANDROID_*_HOME, and a check against $HOME/.android found nothing while
# the AVD had been created somewhere else: the test then reported "the AVD
# could not be created" about an AVD that existed.
# Not inside $OUT: the report directory is uploaded as an artefact, and an AVD
# is four gigabytes of disk image.  The first attempt put it there and the
# artefact was 822 MB, which no one can download and which the results branch
# must never see.
SCRATCH="${RUNNER_TEMP:-/tmp}/umbra-avd"
export ANDROID_AVD_HOME="$SCRATCH/avd"
export ANDROID_EMULATOR_HOME="$SCRATCH/emulator-home"
rm -rf "$SCRATCH"
mkdir -p "$ANDROID_AVD_HOME" "$ANDROID_EMULATOR_HOME"

IMAGE="system-images;android-$API;google_apis;x86_64"
AVD="umbra-api$API"

{
    echo "sdk:      $SDK"
    echo "image:    $IMAGE"
    echo "avd:      $AVD"
    echo "java:     $(java -version 2>&1 | head -1)"
    echo "sdkmanager: $(command -v sdkmanager || echo missing)"
    echo "avdmanager: $(command -v avdmanager || echo missing)"
    echo "emulator:   $(command -v emulator || echo missing)"
    echo "adb:        $(command -v adb || echo missing)"
    echo "kvm:        $(ls -l /dev/kvm 2>&1)"
    echo "pulse:      $(ldconfig -p 2>/dev/null | grep -c libpulse || echo 0) libpulse entries"
    nproc
    free -g | head -2
} >"$OUT/harness.txt" 2>&1

# 1. the system image
yes | sdkmanager --licenses >"$OUT/sdk-licenses.log" 2>&1 || true
if ! sdkmanager --install "$IMAGE" "emulator" "platform-tools" >>"$OUT/sdk-install.log" 2>&1; then
    echo "sdkmanager could not install $IMAGE (see sdk-install.log)" | tee -a "$OUT/harness.txt"
    exit 2
fi

# 2. the device
echo no | avdmanager create avd --force --name "$AVD" --package "$IMAGE" --device "pixel_5" \
    >"$OUT/avd-create.log" 2>&1
avd_listed=0
"$SDK/emulator/emulator" -list-avds >"$OUT/avd-list.txt" 2>&1 || true
if ! grep -qx "$AVD" "$OUT/avd-list.txt"; then
    echo no | avdmanager create avd --force --name "$AVD" --package "$IMAGE" \
        >>"$OUT/avd-create.log" 2>&1
    "$SDK/emulator/emulator" -list-avds >"$OUT/avd-list.txt" 2>&1 || true
fi
grep -qx "$AVD" "$OUT/avd-list.txt" && avd_listed=1
{
    echo "avd home: $ANDROID_AVD_HOME"
    ls -la "$ANDROID_AVD_HOME" 2>&1
    echo "--- emulator -list-avds:"
    cat "$OUT/avd-list.txt" 2>&1
} >>"$OUT/avd-create.log" 2>&1
if [ "$avd_listed" != "1" ]; then
    echo "the AVD could not be created (see avd-create.log)" | tee -a "$OUT/harness.txt"
    exit 2
fi

# 3. the emulator
{
    echo "emulator: $("$SDK/emulator/emulator" -version 2>&1 | head -3)"
    echo "accepted-licenses: $(ls "$SDK/licenses" 2>/dev/null | tr '\n' ' ')"
} >>"$OUT/harness.txt" 2>&1
"$SDK/emulator/emulator" -avd "$AVD" \
    -no-window -no-audio -no-boot-anim -no-snapshot \
    -gpu swiftshader_indirect -accel on -memory 2048 \
    -camera-back none -camera-front none \
    -netdelay none -netspeed full \
    >"$OUT/emulator.log" 2>&1 &
EMULATOR_PID=$!

cleanup() {
    adb emu kill >/dev/null 2>&1 || true
    kill "$EMULATOR_PID" 2>/dev/null || true
    wait "$EMULATOR_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 4. the boot, watched
adb start-server >/dev/null 2>&1
booted=0
for _ in $(seq 1 140); do
    if ! kill -0 "$EMULATOR_PID" 2>/dev/null; then
        echo "the emulator process exited before the boot finished (see emulator.log)" | tee -a "$OUT/harness.txt"
        tail -20 "$OUT/emulator.log" >>"$OUT/harness.txt" 2>/dev/null || true
        exit 2
    fi
    if [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
        booted=1
        break
    fi
    sleep 3
done
if [ "$booted" != "1" ]; then
    echo "the emulator never reported sys.boot_completed=1" | tee -a "$OUT/harness.txt"
    tail -20 "$OUT/emulator.log" >>"$OUT/harness.txt" 2>/dev/null || true
    exit 2
fi
# A booted system is not yet a system that can install: wait for the package
# manager to answer before the test starts talking to it.
for _ in $(seq 1 60); do
    if adb shell pm path android >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
adb shell settings put global window_animation_scale 0 >/dev/null 2>&1 || true
adb shell settings put global transition_animation_scale 0 >/dev/null 2>&1 || true
adb shell settings put global animator_duration_scale 0 >/dev/null 2>&1 || true
adb shell input keyevent 82 >/dev/null 2>&1 || true   # dismiss the lock screen
sleep 2

# 5. the test
#
# The harness has its own timeout: an adb call against a wedged emulator blocks
# forever, and a job that hits the 60 minute limit publishes nothing at all.
timeout 1500 bash "$(dirname "$0")/emulator-smoke.sh" --apk "$APK" --out "$OUT/report" --api "$API" \
    >"$OUT/smoke.log" 2>&1
rc=$?
if [ "$rc" = "124" ]; then
    echo "the smoke test did not finish within 25 minutes" | tee -a "$OUT/harness.txt"
fi
cat "$OUT/smoke.log"
exit $rc
