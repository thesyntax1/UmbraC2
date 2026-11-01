#!/usr/bin/env bash
# The emulator smoke test of the Android implant.
#
# It answers one question and only one: does the APK that CI built start on an
# Android emulator, keep its foreground service alive long enough to be
# observed, load its native library on the ABI the emulator provides, and keep
# working when the phone refuses a permission?  It answers nothing about a real
# phone, about any manufacturer's battery manager, or about whether the beacon
# can run a task -- no task is ever executed here.
#
# Every check writes one line into records.tsv and one file into raw/.  A check
# that could not be performed is NOT VERIFIED and says why; it is never
# silently PASS.  A check that was performed and went wrong is FAIL and is
# never retried to green.
#
#   bash emulator-smoke.sh --apk <path> --out <dir> [--api 33]
#
# Exit codes: 0 every check PASS (or NOT VERIFIED with a reason), 1 something
# FAILed, 2 the harness itself could not run (no adb, no device, no APK).

set -u

APK=""
OUT=""
API="${API_LEVEL:-unknown}"
while [ $# -gt 0 ]; do
    case "$1" in
        --apk) APK="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --api) API="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$APK" ] || [ -z "$OUT" ]; then
    echo "usage: emulator-smoke.sh --apk <path> --out <dir> [--api 33]" >&2
    exit 2
fi
if [ ! -f "$APK" ]; then
    echo "no APK at $APK" >&2
    exit 2
fi

PKG="io.umbra.beacon"
ACTIVITY="$PKG/.MainActivity"
SERVICE_COMPONENT="$PKG/.BeaconService"
NOTIFICATION_ID=4711
CHANNEL_ID="umbra-beacon"

mkdir -p "$OUT/raw"
RECORDS="$OUT/records.tsv"
: > "$RECORDS"

# record <id> <status> <title> <evidence>
#
# The status word is the whole vocabulary: PASS, FAIL, NOT VERIFIED,
# NOT APPLICABLE.  Anything else is a bug in this script.
record() {
    local id="$1" status="$2" title="$3" evidence="$4"
    case "$status" in
        PASS|FAIL|"NOT VERIFIED"|"NOT APPLICABLE") ;;
        *) echo "bad status: $status" >&2; exit 2 ;;
    esac
    printf '%s\t%s\t%s\t%s\n' "$id" "$status" "$title" "$evidence" >> "$RECORDS"
    printf '%-14s %-8s %s\n' "$id" "$status" "$title"
    [ -n "$evidence" ] && printf '                  %s\n' "$evidence"
    return 0
}

# capture <name> <command...>: run an adb shell command, keep the output.
capture() {
    local name="$1"; shift
    adb shell "$@" >"$OUT/raw/$name.txt" 2>&1
    return $?
}

# hold <name> <file>: keep a copy of a file produced on the host.
hold() { cp "$2" "$OUT/raw/$1" 2>/dev/null || true; }

# tap_text <text> [index]: tap the centre of the first node whose text is
# exactly <text>.  The dump is kept: it is the evidence that the screen was
# what the test believed it was.
tap_text() {
    local text="$1" index="${2:-0}" xml coords
    xml="$OUT/raw/ui-$(echo "$text" | tr -c 'a-zA-Z0-9' '_')-$index.xml"
    adb shell uiautomator dump /sdcard/window_dump.xml >/dev/null 2>&1
    adb exec-out cat /sdcard/window_dump.xml >"$xml" 2>/dev/null
    coords=$(python3 - "$xml" "$text" "$index" <<'PY'
import re, sys
path, want, index = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    data = open(path, encoding="utf-8", errors="replace").read()
except OSError:
    sys.exit(1)
found = []
for node in re.finditer(r'<node[^>]*>', data):
    tag = node.group(0)
    text = re.search(r'text="([^"]*)"', tag)
    bounds = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', tag)
    if not text or not bounds:
        continue
    if text.group(1) != want:
        continue
    x1, y1, x2, y2 = (int(v) for v in bounds.groups())
    found.append(((x1 + x2) // 2, (y1 + y2) // 2))
if index >= len(found):
    sys.exit(1)
print(found[index][0], found[index][1])
PY
)
    if [ -z "$coords" ]; then
        return 1
    fi
    adb shell input tap $coords >/dev/null 2>&1
    return 0
}

# has_text <text>: is a node with this exact text on the screen?
has_text() {
    local text="$1" xml="$OUT/raw/ui-has-$(echo "$1" | tr -c 'a-zA-Z0-9' '_').xml"
    adb shell uiautomator dump /sdcard/window_dump.xml >/dev/null 2>&1
    adb exec-out cat /sdcard/window_dump.xml >"$xml" 2>/dev/null
    grep -q "text=\"$text\"" "$xml" 2>/dev/null
}

# service_state: what the activity manager says about BeaconService, or empty.
service_state() {
    adb shell dumpsys activity services "$PKG" 2>/dev/null | tr -d '\r'
}

# notification_state: what the notification manager says about our id.
notification_state() {
    adb shell dumpsys notification --noredact 2>/dev/null | tr -d '\r'
}

# crash_lines: the fatal records of the log, if there are any.
crash_lines() {
    adb logcat -d -v brief 2>/dev/null | tr -d '\r' \
        | grep -E "FATAL EXCEPTION|ANR in $PKG|Process: $PKG" || true
}

command -v adb >/dev/null 2>&1 || { echo "no adb on PATH" >&2; exit 2; }

# Every adb call gets a ceiling.  A wedged emulator answers nothing and an
# unanswered `adb shell` blocks until the job's own timeout, which is how the
# first version of this test produced no report at all.
adb() { timeout 120 command adb "$@"; }

# ---------------------------------------------------------------------------
# 0. the device
# ---------------------------------------------------------------------------

adb start-server >/dev/null 2>&1
if ! adb wait-for-device; then
    echo "no device" >&2
    exit 2
fi

booted=0
for _ in $(seq 1 180); do
    if [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
        booted=1
        break
    fi
    sleep 2
done
if [ "$booted" != "1" ]; then
    echo "the emulator never finished booting" >&2
    exit 2
fi

sdk=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
release=$(adb shell getprop ro.build.version.release | tr -d '\r')
fingerprint=$(adb shell getprop ro.build.fingerprint | tr -d '\r')
abi=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
abilist=$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')
model=$(adb shell getprop ro.product.model | tr -d '\r')
qemu=$(adb shell getprop ro.kernel.qemu | tr -d '\r')

{
    echo "# The emulator"
    echo
    echo "| value | setting |"
    echo "|---|---|"
    echo "| API level asked for | $API |"
    echo "| SDK reported by the device | $sdk |"
    echo "| Android release | $release |"
    echo "| build fingerprint | \`$fingerprint\` |"
    echo "| product model | $model |"
    echo "| primary ABI | $abi |"
    echo "| ABI list | $abilist |"
    echo "| ro.kernel.qemu (this is an emulator) | $qemu |"
    echo "| emulator binary | $(${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/nonexistent}}/emulator/emulator -version 2>/dev/null | head -1 || echo 'not found') |"
    echo "| adb | $(adb version 2>/dev/null | head -1) |"
    echo "| java | $(java -version 2>&1 | head -1) |"
    echo "| Android SDK | ${ANDROID_SDK_ROOT:-${ANDROID_HOME:-unset}} |"
} >"$OUT/environment.md"
hold environment.md "$OUT/environment.md"

if [ "$sdk" != "$API" ]; then
    record environment FAIL "the emulator is the API level the job asked for" \
        "asked for $API, the device reports $sdk"
else
    record environment PASS "the emulator is the API level the job asked for" \
        "API $sdk, $release, $abilist, qemu=$qemu"
fi

# ---------------------------------------------------------------------------
# 1. the APK: the same bytes on both sides of the wire
# ---------------------------------------------------------------------------

host_sha=$(sha256sum "$APK" | awk '{print $1}')
echo "$host_sha  $(basename "$APK")" >"$OUT/apk.txt"
unzip -l "$APK" 2>/dev/null | grep -E 'lib/.*\.so' >>"$OUT/apk.txt" || true
hold apk.txt "$OUT/apk.txt"

adb push "$APK" /data/local/tmp/umbra-debug.apk >"$OUT/raw/adb-push.txt" 2>&1
device_sha=$(adb shell sha256sum /data/local/tmp/umbra-debug.apk 2>/dev/null | awk '{print $1}' | tr -d '\r')
if [ "$host_sha" = "$device_sha" ]; then
    record apk-integrity PASS "the bytes that were installed are the bytes that were built" \
        "sha256 $host_sha on both sides"
else
    record apk-integrity FAIL "the bytes that were installed are the bytes that were built" \
        "host $host_sha, device ${device_sha:-nothing}"
fi

abis_in_apk=$(unzip -l "$APK" 2>/dev/null | grep -o 'lib/[^/]*/' | tr -d 'lib/' | tr -d '/' | sort -u | tr '\n' ' ')
case " $abilist " in
    *" $abi "*) abi_supported=yes ;;
    *) abi_supported=no ;;
esac
case " $abis_in_apk " in
    *" $abi "*) abi_packaged=yes ;;
    *) abi_packaged=no ;;
esac
if [ "$abi_packaged" = "yes" ] && [ "$abi_supported" = "yes" ]; then
    record abi-match PASS "the APK carries the ABI the emulator runs" \
        "device $abi (of $abilist), APK: $abis_in_apk"
else
    record abi-match FAIL "the APK carries the ABI the emulator runs" \
        "device $abi (of $abilist), APK: $abis_in_apk"
fi

# ---------------------------------------------------------------------------
# 2. install and launch
# ---------------------------------------------------------------------------

install_out=$(adb install -r /data/local/tmp/umbra-debug.apk 2>&1)
install_rc=$?
printf '%s\n' "$install_out" >"$OUT/raw/adb-install.txt"
if [ "$install_rc" -eq 0 ] && printf '%s' "$install_out" | grep -q 'Success'; then
    record install PASS "adb install says Success" "$(printf '%s' "$install_out" | tail -1)"
else
    record install FAIL "adb install says Success" "$(printf '%s' "$install_out" | tail -3 | tr '\n' ' ')"
fi

capture pm-list-packages pm list packages "$PKG"
if grep -q "package:$PKG" "$OUT/raw/pm-list-packages.txt"; then
    record package-manager PASS "the package manager lists the application" "$PKG"
else
    record package-manager FAIL "the package manager lists the application" "not in pm list packages"
fi

capture package-dump dumpsys package "$PKG"
version=$(grep -m1 'versionName=' "$OUT/raw/package-dump.txt" | tr -d '\r')
path=$(grep -m1 'codePath=' "$OUT/raw/package-dump.txt" | tr -d '\r')

# The permission state before anything is asked for: a fresh install has
# granted none of the runtime permissions, and the manifest's normal
# permissions are granted by the package manager.
pre_notifications=$(grep -A2 'POST_NOTIFICATIONS' "$OUT/raw/package-dump.txt" | tr -d '\r' | tr '\n' ' ')
echo "$pre_notifications" >"$OUT/raw/permission-before.txt"

adb logcat -c >/dev/null 2>&1

start_out=$(adb shell am start -W -n "$ACTIVITY" 2>&1)
printf '%s\n' "$start_out" >"$OUT/raw/am-start.txt"
sleep 3
pid=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
if printf '%s' "$start_out" | grep -q 'Status: ok' && [ -n "$pid" ]; then
    record launch PASS "the consent screen starts on API $sdk" \
        "$(printf '%s' "$start_out" | grep -E 'Status|TotalTime' | tr '\n' ' '), pid $pid, $version"
else
    record launch FAIL "the consent screen starts on API $sdk" \
        "$(printf '%s' "$start_out" | tail -3 | tr '\n' ' '), pid ${pid:-none}"
fi

sleep 2
crashes=$(crash_lines)
if [ -z "$crashes" ]; then
    record launch-crash PASS "no crash and no ANR during the launch" "logcat has no FATAL EXCEPTION for $PKG"
else
    record launch-crash FAIL "no crash and no ANR during the launch" "$(printf '%s' "$crashes" | head -3 | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
# 3. the permission the application asks for itself: POST_NOTIFICATIONS
#
# This is the only permission the implant requests at run time from its own
# code, and it asks on the consent screen.  The dialog is the real user path,
# so the denial is performed on the dialog, not by a shell command.
# ---------------------------------------------------------------------------

if has_text "Don't allow"; then
    record notif-dialog PASS "the application asks for POST_NOTIFICATIONS on first launch" \
        "the platform dialog is on the screen"
    tap_text "Don't allow" || true
    sleep 2
    capture package-dump-after-deny dumpsys package "$PKG"
    state=$(grep -A2 'POST_NOTIFICATIONS' "$OUT/raw/package-dump-after-deny.txt" | tr -d '\r' | tr '\n' ' ')
    echo "$state" >"$OUT/raw/permission-after-deny.txt"
    if printf '%s' "$state" | grep -q 'granted=false'; then
        record notif-denial PASS "the refusal of POST_NOTIFICATIONS is recorded as a refusal" \
            "$(printf '%s' "$state" | sed 's/  */ /g' | cut -c1-160)"
    else
        record notif-denial FAIL "the refusal of POST_NOTIFICATIONS is recorded as a refusal" \
            "the permission does not read as denied: $(printf '%s' "$state" | cut -c1-160)"
    fi
else
    record notif-dialog NOT VERIFIED "the application asks for POST_NOTIFICATIONS on first launch" \
        "no permission dialog was on the screen; the state before it may not have been a fresh install"
    record notif-denial NOT VERIFIED "the refusal of POST_NOTIFICATIONS is recorded as a refusal" \
        "the dialog never appeared, so there was nothing to refuse"
fi

# ---------------------------------------------------------------------------
# 4. the foreground service, started from the consent screen
#
# The permission is still refused here: a foreground service does not need
# POST_NOTIFICATIONS to run, it needs it for its notification to be seen.
# ---------------------------------------------------------------------------

if tap_text "Start beacon"; then
    sleep 6
    state=$(service_state)
    printf '%s\n' "$state" >"$OUT/raw/services-after-start.txt"
    if printf '%s' "$state" | grep -q "$SERVICE_COMPONENT"; then
        record service-start PASS "the foreground service starts from the consent screen" \
            "the activity manager holds a record for $SERVICE_COMPONENT"
    else
        record service-start FAIL "the foreground service starts from the consent screen" \
            "no ServiceRecord for $SERVICE_COMPONENT: $(printf '%s' "$state" | tail -3 | tr '\n' ' ')"
    fi
    if printf '%s' "$state" | grep -q 'isForeground=true'; then
        record service-foreground PASS "the service is in the foreground" "isForeground=true"
    else
        record service-foreground FAIL "the service is in the foreground" \
            "$(printf '%s' "$state" | grep -E 'isForeground|foregroundId' | tr -d '\r' | tr '\n' ' ')"
    fi
else
    record service-start FAIL "the foreground service starts from the consent screen" \
        "the button \"Start beacon\" could not be found on the screen"
    record service-foreground NOT VERIFIED "the service is in the foreground" "the service was never started"
fi

sleep 2
pid=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
crashes=$(crash_lines)
if [ -z "$crashes" ] && [ -n "$pid" ]; then
    record service-crash PASS "starting the service neither crashes nor kills the process" "pid $pid"
elif [ -n "$crashes" ]; then
    record service-crash FAIL "starting the service neither crashes nor kills the process" \
        "$(printf '%s' "$crashes" | head -4 | tr '\n' ' ')"
    adb logcat -d -v brief 2>/dev/null | grep -B2 -A12 "FATAL EXCEPTION" | head -60 >"$OUT/raw/crash-trace.txt" || true
else
    record service-crash FAIL "starting the service neither crashes nor kills the process" \
        "the process is gone and there is no FATAL EXCEPTION in the log"
fi

# With the permission refused the notification must not be on the screen.
# This is the platform's decision, not the application's, but it is the half
# of the story the operator would otherwise misread as "the service is silent".
notif=$(notification_state)
printf '%s\n' "$notif" >"$OUT/raw/notifications-denied.txt"
if printf '%s' "$notif" | grep -q "pkg=$PKG"; then
    record notification-suppressed FAIL "a refused POST_NOTIFICATIONS keeps the notification off the screen" \
        "a notification for $PKG is posted although the permission was refused"
else
    record notification-suppressed PASS "a refused POST_NOTIFICATIONS keeps the notification off the screen" \
        "no notification for $PKG while the permission is refused"
fi

# Now the permission is granted and the same start is repeated: this is the
# only way to tell "the notification is missing because the user said no"
# from "the notification is missing because the code never posts it".
adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1
grant_rc=$?
adb shell am force-stop "$PKG" >/dev/null 2>&1
sleep 2
adb shell am start -W -n "$ACTIVITY" >/dev/null 2>&1
sleep 3
if tap_text "Start beacon"; then
    sleep 6
else
    sleep 2
fi
notif=$(notification_state)
printf '%s\n' "$notif" >"$OUT/raw/notifications-granted.txt"
state=$(service_state)
printf '%s\n' "$state" >"$OUT/raw/services-after-grant.txt"
if [ "$grant_rc" -ne 0 ]; then
    record notification NOT VERIFIED "the foreground service posts its notification when it may" \
        "the permission could not be granted from the shell, so the second half of the test did not run"
elif printf '%s' "$notif" | grep -q "pkg=$PKG"; then
    if printf '%s' "$notif" | grep -q "$CHANNEL_ID"; then
        record notification PASS "the foreground service posts its notification when it may" \
            "channel $CHANNEL_ID, id $NOTIFICATION_ID, for $PKG"
    else
        record notification FAIL "the foreground service posts its notification when it may" \
            "a notification for $PKG exists, but not on channel $CHANNEL_ID"
    fi
else
    record notification FAIL "the foreground service posts its notification when it may" \
        "no notification for $PKG although the permission is granted and the service is \"$(printf '%s' "$state" | grep -o 'isForeground=[a-z]*' | head -1)\""
fi

# ---------------------------------------------------------------------------
# 5. the native library: loaded, on the ABI the device runs, or not at all
#
# The file being inside the APK is not a load.  The load is the library
# mapped into the running process, and the only place that is written down
# is /proc/<pid>/maps.
# ---------------------------------------------------------------------------

pid=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
maps=""
if [ -n "$pid" ]; then
    maps=$(adb shell run-as "$PKG" cat "/proc/$pid/maps" 2>/dev/null | tr -d '\r')
    if ! printf '%s' "$maps" | grep -q 'libumbra.so'; then
        if adb root >/dev/null 2>&1; then
            adb wait-for-device >/dev/null 2>&1
            sleep 3
        fi
        maps=$(adb shell cat "/proc/$pid/maps" 2>/dev/null | tr -d '\r')
    fi
fi
printf '%s\n' "$maps" >"$OUT/raw/proc-maps-libumbra.txt"
mapped=$(printf '%s' "$maps" | grep 'libumbra\.so' | head -3)
link_error=$(adb logcat -d -v brief 2>/dev/null | grep -E "UnsatisfiedLinkError|dlopen failed|couldn't find \"libumbra" | head -3)

if [ -n "$mapped" ]; then
    record native-load PASS "the native library is mapped into the running process" \
        "$(printf '%s' "$mapped" | head -1 | sed 's/  */ /g' | cut -c1-200)"
    if printf '%s' "$mapped" | grep -q "lib/$abi/"; then
        record native-abi PASS "the mapped library is the one built for the device ABI" \
            "lib/$abi/libumbra.so"
    else
        record native-abi FAIL "the mapped library is the one built for the device ABI" \
            "mapped: $(printf '%s' "$mapped" | head -1)"
    fi
elif [ -n "$link_error" ]; then
    record native-load FAIL "the native library is mapped into the running process" \
        "$(printf '%s' "$link_error" | head -2 | tr '\n' ' ')"
    record native-abi NOT APPLICABLE "the mapped library is the one built for the device ABI" \
        "nothing was loaded"
else
    record native-load NOT VERIFIED "the native library is mapped into the running process" \
        "the library was not found in /proc/${pid:-?}/maps and neither run-as nor adb root could read it"
    record native-abi NOT VERIFIED "the mapped library is the one built for the device ABI" \
        "no reading of the process map was possible"
fi

# ---------------------------------------------------------------------------
# 6. the process is killed under the service, and something is watched
#
# START_STICKY is a request, not a promise: what Android does with it is the
# question, and the only answer is what happens next.
# ---------------------------------------------------------------------------

pid=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
if [ -n "$pid" ]; then
    adb shell su 0 kill -9 "$pid" >/dev/null 2>&1 || adb shell run-as "$PKG" kill -9 "$pid" >/dev/null 2>&1 || adb shell kill -9 "$pid" >/dev/null 2>&1
    killed_at=$(date +%s)
    sleep 3
    killed_pid=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
    came_back=""
    for _ in $(seq 1 30); do
        new_pid=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
        if [ -n "$new_pid" ] && [ "$new_pid" != "$pid" ]; then
            came_back=$new_pid
            break
        fi
        sleep 2
    done
    state=$(service_state)
    printf '%s\n' "$state" >"$OUT/raw/services-after-kill.txt"
    if [ -n "$came_back" ]; then
        took=$(( $(date +%s) - killed_at ))
        record kill-restart PASS "the process comes back after a SIGKILL" \
            "the old pid $pid was killed, the new pid $came_back appeared after ${took}s; the service record is $(printf '%s' "$state" | grep -c "$SERVICE_COMPONENT")"
    else
        record kill-restart FAIL "the process comes back after a SIGKILL" \
            "the pid $pid never returned in 60s (pid after the kill: ${killed_pid:-none}); the sticky flag is a request and Android refused it"
    fi
    if [ -n "$came_back" ] && printf '%s' "$state" | grep -q "$SERVICE_COMPONENT"; then
        record service-restart PASS "the service, not only the process, is restored" \
            "ServiceRecord for $SERVICE_COMPONENT exists again"
    else
        record service-restart FAIL "the service, not only the process, is restored" \
            "the process is ${came_back:-gone} and the service record is missing"
    fi
else
    record kill-restart NOT VERIFIED "the process comes back after a SIGKILL" \
        "there was no process to kill"
    record service-restart NOT VERIFIED "the service, not only the process, is restored" \
        "there was no process to kill"
fi

# ---------------------------------------------------------------------------
# 7. the consent screen can stop it
# ---------------------------------------------------------------------------

if tap_text "Start beacon" 0 2>/dev/null; then
    : # the activity was restarted by the kill; the button is there
fi
adb shell am start -W -n "$ACTIVITY" >/dev/null 2>&1
sleep 2
if tap_text "Stop beacon"; then
    sleep 3
    state=$(service_state)
    printf '%s\n' "$state" >"$OUT/raw/services-after-stop.txt"
    if printf '%s' "$state" | grep -q "$SERVICE_COMPONENT"; then
        record stop FAIL "the service stops from the consent screen" \
            "the ServiceRecord for $SERVICE_COMPONENT is still there"
    else
        record stop PASS "the service stops from the consent screen" \
            "no ServiceRecord for $SERVICE_COMPONENT"
    fi
    notif=$(notification_state)
    if printf '%s' "$notif" | grep -q "pkg=$PKG"; then
        record stop-notification FAIL "the notification goes away with the service" \
            "a notification for $PKG is still posted"
    else
        record stop-notification PASS "the notification goes away with the service" \
            "no notification for $PKG"
    fi
else
    record stop NOT VERIFIED "the service stops from the consent screen" \
        "the button \"Stop beacon\" could not be found"
    record stop-notification NOT VERIFIED "the notification goes away with the service" \
        "the service was never stopped"
fi

# ---------------------------------------------------------------------------
# 8. the checks this stage cannot perform
#
# These are not skipped out of convenience: the code paths behind them run
# only when a task arrives from the server, and this stage executes no task.
# ---------------------------------------------------------------------------

record notif-denial-behaviour NOT VERIFIED "the refusal of POST_NOTIFICATIONS is answered truthfully by the application" \
    "the service must run without the permission and the code has no sentence of its own for that refusal; only the platform's silence was observed"
record location-denial NOT VERIFIED "a refused location permission produces the sentence the code has for it" \
    "Sense.kt is reached from a task, and no task is executed in this stage"
record alarm-denial NOT VERIFIED "a refused exact alarm produces the inexact alarm and the honest detail string" \
    "Persistence.kt arms an alarm from a task, and no task is executed in this stage"
record physical-device NOT APPLICABLE "a physical phone behaves the same way" \
    "no physical device was involved; manufacturer battery managers are out of scope"

# ---------------------------------------------------------------------------
# 9. the log, kept
# ---------------------------------------------------------------------------

adb logcat -d -v threadtime >"$OUT/raw/logcat-full.txt" 2>/dev/null
adb logcat -d -v threadtime 2>/dev/null | grep -E "io\.umbra\.beacon|AndroidRuntime|ActivityManager.*umbra" \
    >"$OUT/raw/logcat-app.txt" 2>/dev/null || true
fatal=$(grep -c "FATAL EXCEPTION" "$OUT/raw/logcat-full.txt" 2>/dev/null || echo 0)
anr=$(grep -c "ANR in $PKG" "$OUT/raw/logcat-full.txt" 2>/dev/null || echo 0)
echo "$fatal" >"$OUT/raw/fatal-count.txt"
echo "$anr" >"$OUT/raw/anr-count.txt"
if [ "$fatal" -eq 0 ] && [ "$anr" -eq 0 ]; then
    record logcat PASS "no FATAL EXCEPTION and no ANR in the whole run" "$fatal fatal, $anr ANR"
else
    record logcat FAIL "no FATAL EXCEPTION and no ANR in the whole run" "$fatal fatal, $anr ANR"
fi

# ---------------------------------------------------------------------------
# 10. the report
# ---------------------------------------------------------------------------

python3 - "$RECORDS" "$OUT" "$API" "$host_sha" <<'PY'
import json, sys

records_path, out, api, sha = sys.argv[1:5]
rows = []
with open(records_path, encoding="utf-8") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 4:
            continue
        rows.append({"id": parts[0], "status": parts[1], "title": parts[2], "evidence": parts[3]})

counts = {}
for row in rows:
    counts[row["status"]] = counts.get(row["status"], 0) + 1

with open(f"{out}/result.json", "w", encoding="utf-8") as handle:
    json.dump({"api": api, "apk_sha256": sha, "counts": counts, "checks": rows}, handle, indent=2)

lines = [
    f"# The emulator smoke test — API {api}",
    "",
    f"APK sha256 `{sha}`.  Every line below was produced by a command that ran",
    "on this emulator; a line that says NOT VERIFIED is a command that could",
    "not be run, and it says why.",
    "",
    "| check | result | what was asked | evidence |",
    "|---|---|---|---|",
]
for row in rows:
    evidence = row["evidence"].replace("|", "\\|")
    lines.append(f"| `{row['id']}` | **{row['status']}** | {row['title']} | {evidence} |")
lines += [
    "",
    "## Counts",
    "",
    *[f"* {status}: {count}" for status, count in sorted(counts.items())],
    "",
]
with open(f"{out}/result.md", "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines))
print("\n".join(lines))
PY

failures=$(awk -F'\t' '$2=="FAIL"' "$RECORDS" | wc -l | tr -d ' ')
if [ "$failures" -gt 0 ]; then
    echo "emulator-smoke: $failures check(s) FAILED on API $API" >&2
    exit 1
fi
echo "emulator-smoke: no FAIL on API $API"
exit 0
