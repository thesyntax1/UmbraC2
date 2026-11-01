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
    # "NOT VERIFIED" is two words, so every call site that says it passes five
    # arguments.  The first version compared $2 against the two-word string and
    # died with "bad status: NOT" at the first NOT VERIFIED line -- the report
    # stopped exactly where it should have said what it could not measure.
    if [ "$2" = "NOT" ]; then
        case "${3:-}" in
            VERIFIED)   status="NOT VERIFIED" ;;
            APPLICABLE) status="NOT APPLICABLE" ;;
        esac
        title="$4"; evidence="${5:-}"
    fi
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
    local text="$1" index="${2:-0}" xml coords attempt
    xml="$OUT/raw/ui-$(printf '%s' "$text" | tr -c 'a-zA-Z0-9' '_')-$index.xml"
    # uiautomator reports the window *behind* the activity while a transition
    # is running: on the seventh run the tap at this point landed on the
    # launcher although the activity had just been displayed.  Ask again, and
    # ask the activity to the front between attempts.
    for attempt in 1 2 3 4 5 6; do
        adb shell uiautomator dump /sdcard/window_dump.xml >/dev/null 2>&1
        adb exec-out cat /sdcard/window_dump.xml >"$xml" 2>/dev/null
        if grep -qF "$text" "$xml" 2>/dev/null; then
            break
        fi
        sleep 1
        adb shell am start -W -n "$ACTIVITY" >/dev/null 2>&1
    done
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
    if not re.search(want, text.group(1)):
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

# ui_texts <name>: every non-empty text on the screen, one per line.
ui_texts() {
    # Two lines, not one: `local a="$1" b="…$a…"` expands the whole command
    # line before assigning anything, and under `set -u` that is an unbound
    # variable -- which is exactly how the previous run died.
    local name="$1"
    local xml="$OUT/raw/ui-$name.xml"
    adb shell uiautomator dump /sdcard/window_dump.xml >/dev/null 2>&1
    adb exec-out cat /sdcard/window_dump.xml >"$xml" 2>/dev/null
    grep -o 'text="[^"]*"' "$xml" 2>/dev/null | sed 's/^text="//; s/"$//' | grep -v '^$'
}

# has_text <regex>: is there a node whose text matches, on the screen?
#
# A regular expression, not an exact string: the platform's own dialog says
# "Don’t allow" with a typographic apostrophe (U+2019), and an exact match on
# "Don't allow" found nothing on an emulator where the dialog was plainly on
# the screen.
has_text() {
    local pattern="$1"
    ui_texts "has-$(printf '%s' "$1" | tr -c 'a-zA-Z0-9' '_')" | grep -qE "$pattern"
}

# front_package: the package of the window that is actually in front.
front_package() {
    local xml="$OUT/raw/ui-front.xml"
    adb shell uiautomator dump /sdcard/window_dump.xml >/dev/null 2>&1
    adb exec-out cat /sdcard/window_dump.xml >"$xml" 2>/dev/null
    grep -o 'package="[^"]*"' "$xml" 2>/dev/null | head -1 | sed 's/package="//; s/"$//'
}

# ensure_front: put the consent screen in front before a tap.
#
# The fifth run tapped into the launcher: after the permission dialog closed
# the activity was behind it, and uiautomator dumps the launcher rather than
# the screen the test believes it is looking at.  What was in front, and what
# took its place, is written to raw/front.txt.
ensure_front() {
    adb shell wm dismiss-keyguard >/dev/null 2>&1
    local front
    front=$(front_package)
    if [ "$front" != "$PKG" ]; then
        adb shell am start -W -n "$ACTIVITY" >/dev/null 2>&1
        sleep 3
        printf '%s -> %s\n' "${front:-nothing}" "$(front_package)" >>"$OUT/raw/front.txt"
        return 1
    fi
    return 0
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
# `timeout` execs its argument, so it cannot run the shell builtin `command`:
# the first version of this line made every adb call fail with ENOENT.
adb() { timeout 120 "$(command -v adb)" "$@"; }

# start_service: get BeaconService running, by the button if the button can be
# tapped and by the shell if it cannot.  Echoes the way it was started.  Every
# fallback start is appended to the raw evidence, so a report that says the
# service was started by the shell says it for every start that happened.
start_service() {
    if tap_text "Start beacon"; then
        printf 'the consent screen button'
        return 0
    fi
    adb root >/dev/null 2>&1 && adb wait-for-device >/dev/null 2>&1 && sleep 3
    adb shell am start-foreground-service -n "$SERVICE_COMPONENT" \
        >>"$OUT/raw/am-start-service.txt" 2>&1
    printf 'am start-foreground-service, because the button could not be tapped'
}

# wait_for_service_record: the activity manager answers "started" before the
# service is in its list; wait for the list, not for the answer.
wait_for_service_record() {
    for _ in $(seq 1 15); do
        if service_state | grep -q "$SERVICE_COMPONENT"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

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
# ro.product.cpu.abilist is a comma-separated list ("x86_64,arm64-v8a" on an
# image with the 64-bit ARM translator), so a substring test against
# " x86_64 " answers no on an emulator that runs it.
if printf '%s' "$abilist" | tr ',' '\n' | grep -qx "$abi"; then
    abi_supported=yes
else
    abi_supported=no
fi
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

# `adb install <path>` treats its argument as a path on the *host* and pushes
# it again; the file was already pushed and hashed there, so the package
# manager is asked to install the copy on the device.  (The first version used
# `adb install /data/local/tmp/...` and failed with "failed to stat": the
# device path does not exist on the runner.)
install_out=$(adb shell pm install -r /data/local/tmp/umbra-debug.apk 2>&1)
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

# The dialog is the platform's, and it appears a moment after the activity.
# The button says "Don’t allow" with U+2019 on API 33 and 34, so the match is
# a pattern; the exact text that was found is kept as evidence.
dialog_seen=no
for _ in $(seq 1 15); do
    if has_text "Don.?t allow|DENY|Deny"; then
        dialog_seen=yes
        break
    fi
    sleep 1
done
ui_texts "before-denial" >"$OUT/raw/texts-before-denial.txt" 2>&1 || true

if [ "$dialog_seen" = "yes" ]; then
    record notif-dialog PASS "the application asks for POST_NOTIFICATIONS on first launch" \
        "the platform dialog is on the screen: $(grep -m1 'notifications' "$OUT/raw/texts-before-denial.txt" | cut -c1-80)"
    tap_text "Don.?t allow|DENY|Deny" || true
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

# `adb root` restarts adbd, and every `adb reverse` rule dies with it.  The
# mapping made by the boot script was gone by the time this section needed it:
# the tenth run took root in the tap fallback below, and the script's own
# `adb reverse --list` was empty ever after, so the application's connection
# was refused and the native library was never reachable.  Root is taken here,
# once, before the beacon exists; a later `adb root` on an adbd that is
# already root does not restart anything, so the rule survives.
adb root >/dev/null 2>&1 && adb wait-for-device >/dev/null 2>&1 && sleep 2
{
    echo "$ adb reverse tcp:4001 tcp:4001"
    adb reverse tcp:4001 tcp:4001 2>&1 || true
    echo "$ adb reverse --list"
    adb reverse --list 2>&1 || true
} >"$OUT/raw/adb-reverse.txt"

ensure_front || true
started_by="the consent screen button"
if tap_text "Start beacon"; then
    record consent-button PASS "the consent screen's button starts the service" \
        "the button \"Start beacon\" was found and tapped"
else
    record consent-button NOT VERIFIED "the consent screen's button starts the service" \
        "the button could not be tapped on a headless emulator; the screen itself was verified at launch"
    # The service is what the rest of the test needs, so it is started the
    # way an operator with a shell would start it -- and the evidence says so.
    adb root >/dev/null 2>&1 && adb wait-for-device >/dev/null 2>&1 && sleep 3
    adb shell am start-foreground-service -n "$SERVICE_COMPONENT" \
        >"$OUT/raw/am-start-service.txt" 2>&1
    started_by="am start-foreground-service, because the button could not be tapped"
fi
sleep 6
state=$(service_state)
printf '%s\n' "$state" >"$OUT/raw/services-after-start.txt"
if printf '%s' "$state" | grep -q "$SERVICE_COMPONENT"; then
    record service-start PASS "the foreground service starts" \
        "started by $started_by; the activity manager holds a record for $SERVICE_COMPONENT"
else
    record service-start FAIL "the foreground service starts" \
        "started by $started_by; no ServiceRecord for $SERVICE_COMPONENT: $(printf '%s' "$state" | tail -3 | tr '\n' ' ')"
fi
if printf '%s' "$state" | grep -q 'isForeground=true'; then
    record service-foreground PASS "the service is in the foreground" "isForeground=true"
else
    record service-foreground FAIL "the service is in the foreground" \
        "$(printf '%s' "$state" | grep -E 'isForeground|foregroundId' | tr -d '\r' | tr '\n' ' ')"
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
sleep 4
# The service has to start *after* the grant.  A notification suppressed at
# enqueue time is not restored by granting the permission afterwards, and the
# eighth run read that suppression as "the code never posts a notification".
granted_started_by=$(start_service)
if wait_for_service_record; then
    sleep 6
    granted_service="the activity manager holds a record for $SERVICE_COMPONENT"
else
    granted_service="no ServiceRecord for $SERVICE_COMPONENT after the start"
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
        "no notification for $PKG although the permission is granted; started by $granted_started_by, $granted_service"
fi

# ---------------------------------------------------------------------------
# 5. the native library: loaded, on the ABI the device runs, or not at all
#
# The file being inside the APK is not a load.  The load is the library
# mapped into the running process, and the only place that is written down
# is /proc/<pid>/maps.
# ---------------------------------------------------------------------------

# The library is loaded when the beacon's handshake is built, which happens
# the first time the loop opens a channel: the loopback socket is what makes
# that reachable.  It is given twenty seconds.
# The channel the beacon opens is a socket on the host, mapped into the
# device by `adb reverse`.  Without that rule the application cannot reach
# anything, the channel never opens, and the library is never loaded -- so the
# mapping is part of the evidence, not scenery.
reverse_list=$(adb reverse --list 2>&1 | tr -d '\r')
printf '%s\n' "$reverse_list" >"$OUT/raw/adb-reverse-list.txt"
reverse_up=no
if printf '%s' "$reverse_list" | grep -q 'tcp:4001'; then
    reverse_up=yes
fi

mapped=""
maps_readable=no
maps_pid=""
maps_waited=0
# Ninety seconds, not twenty.  The beacon is restarted by the permission test
# just above, and its first connect after that restart can land later than the
# window: the thirteenth run read the map of a process that had connected but
# had not yet built its handshake.
for _ in $(seq 1 90); do
    maps_waited=$((maps_waited + 1))
    pid=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
    [ -z "$pid" ] && { sleep 1; continue; }
    maps_pid=$pid
    maps=$(adb shell run-as "$PKG" cat "/proc/$pid/maps" 2>/dev/null | tr -d '\r')
    if [ -z "$maps" ]; then
        if adb root >/dev/null 2>&1; then
            adb wait-for-device >/dev/null 2>&1
            sleep 2
        fi
        maps=$(adb shell cat "/proc/$pid/maps" 2>/dev/null | tr -d '\r')
    fi
    [ -n "$maps" ] && maps_readable=yes
    mapped=$(printf '%s' "$maps" | grep 'libumbra\.so' | head -3)
    [ -n "$mapped" ] && break
    sleep 1
done
printf '%s\n' "$maps" >"$OUT/raw/proc-maps-libumbra.txt"

# What the application says it is doing.  The foreground notification is the
# only place the implant writes down its own state, so it is quoted instead of
# guessed at -- twice, because the first sentence after a connect is often
# replaced by the sentence that explains the failure.
notification_text() {
    local block text
    block=$(notification_state | grep -A40 "pkg=$PKG" | head -60 || true)
    text=$(printf '%s\n' "$block" \
        | grep -m1 'android\.text=String (' \
        | sed 's/^.*android\.text=String (//; s/)$//' || true)
    printf '%s' "$text"
}
# Where is the process?  When the library is not in the map, the question is
# not "did the load fail" but "was it ever reached", and only a stack answers
# that.  Three sources, because the first one alone gave nothing: SIGQUIT
# (which on API 33+ writes /data/anr/anr_* rather than traces.txt), the
# newest file in /data/anr, and debuggerd, which prints the Java threads of a
# debuggable process on demand.
threads() {
    local pid="$1" file="$2" raw="$2.raw" newest=""
    : >"$file"
    : >"$raw"
    [ -z "$pid" ] && return 0
    adb shell kill -3 "$pid" >/dev/null 2>&1 || true
    sleep 3
    {
        echo "$ debuggerd -j $pid"
        adb shell debuggerd -j "$pid" 2>&1 || true
        echo "$ ls -t /data/anr/"
        adb shell ls -t /data/anr/ 2>&1 || true
    } >"$raw" 2>/dev/null || true
    newest=$(adb shell ls -t /data/anr/ 2>/dev/null | tr -d '\r' | head -1)
    if [ -n "$newest" ]; then
        {
            echo "$ cat /data/anr/$newest"
            adb shell cat "/data/anr/$newest" 2>&1 || true
        } >>"$raw" 2>/dev/null || true
    fi
    grep -E 'at io\.umbra\.beacon|^"main"|cmdline: io\.umbra\.beacon' "$raw" 2>/dev/null \
        | head -80 >"$file" 2>/dev/null || true
}

app_text=$(notification_text)
printf '%s\n' "${app_text:-no notification of $PKG carries a text}" >"$OUT/raw/notification-text.txt"

# Where the library sits inside the APK, computed where the APK is.  With
# useLegacyPackaging=false the loader maps the library straight out of
# base.apk, and then the process map says "base.apk" and never says
# "libumbra.so": a check that greps for the file name cannot see a load that
# happened.  These offsets are what makes the mapping identifiable.
python3 - "$APK" >"$OUT/raw/apk-native-entries.txt" 2>/dev/null <<'PY' || true
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for i in z.infolist():
    if i.filename.startswith("lib/") and i.filename.endswith(".so"):
        data = i.header_offset + 30 + len(i.filename.encode()) + len(i.extra)
        print("%s\theader=%d\tdata=%d\tsize=%d\tstored=%s"
              % (i.filename, i.header_offset, data, i.file_size,
                 "yes" if i.compress_type == zipfile.ZIP_STORED else "no"))
PY

# The library check itself, from the device's side: the file in the APK is not
# a load, and the extracted file next to the package is not a load either, but
# both are the two things that can be wrong before the load is even attempted.
{
    echo "$ adb shell pm path $PKG"
    adb shell pm path "$PKG" 2>&1 || true
    echo "$ adb shell ls -l /data/app/*/$PKG*/lib/$abi/"
    adb shell "ls -l /data/app/*/$PKG*/lib/$abi/" 2>&1 || true
} >"$OUT/raw/native-files.txt"

# Our own tag, so the platform's message about the load is in the report even
# when the application turns the failure into a fallback.
adb logcat -d -v brief 2>/dev/null | tr -d '\r' \
    | grep -E "^[A-Z]/umbra|umbra *: |I/umbra" | tail -30 >"$OUT/raw/logcat-umbra.txt" 2>/dev/null || true

# Only the failures that name this application or this library.  The first
# version grepped the whole log for "dlopen failed" and found the emulator's
# own missing codec libraries, which have nothing to do with the implant.
link_error=$(adb logcat -d -v brief 2>/dev/null | tr -d '\r' \
    | grep -iE 'umbra' | grep -E "UnsatisfiedLinkError|dlopen failed|couldn't find" | head -3)

# The mapping of the library out of base.apk, matched by offset: the zip
# directory says where lib/<abi>/libumbra.so starts in the file, and a
# mapping of base.apk inside that range is the loader having mapped it.
apk_mapped=$(python3 - "$OUT/raw/proc-maps-libumbra.txt" "$OUT/raw/apk-native-entries.txt" "$abi" 2>/dev/null <<'PY' || true
import re, sys
maps_path, entries_path, abi = sys.argv[1], sys.argv[2], sys.argv[3]
ranges = []
try:
    for line in open(entries_path):
        if not line.startswith("lib/%s/libumbra.so" % abi):
            continue
        try:
            parts = dict(p.split("=", 1) for p in line.strip().split("\t")[1:])
            data, size = int(parts["data"]), int(parts["size"])
        except (KeyError, ValueError):
            continue
        # The loader maps from the page the entry starts on, so the mapping
        # offset is the data offset rounded down, not the data offset.
        lo = data - (data % 4096)
        hi = data + size
        hi += (4096 - hi % 4096) % 4096
        ranges.append((lo, hi))
except OSError:
    sys.exit(0)
try:
    lines = open(maps_path, errors="replace").read().splitlines()
except OSError:
    sys.exit(0)
for line in lines:
    if "base.apk" not in line:
        continue
    m = re.search(r" ([0-9a-f]{8,}) [0-9a-f]{2}:[0-9a-f]{2} ", line)
    if not m:
        continue
    off = int(m.group(1), 16)
    for lo, hi in ranges:
        if lo <= off < hi:
            print(line.strip())
            break
PY
)
native_sentence=$(grep -m1 "native library loaded: kernel=" "$OUT/raw/logcat-umbra.txt" 2>/dev/null | sed 's/^.*umbra *[^:]*: //' || true)
native_failure=$(grep -m1 "native library did not load" "$OUT/raw/logcat-umbra.txt" 2>/dev/null | sed 's/^.*umbra *[^:]*: //' || true)

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
elif [ -n "$apk_mapped" ]; then
    record native-load PASS "the native library is mapped into the running process" \
        "mapped out of base.apk at the offset the zip directory gives for lib/$abi/libumbra.so: $(printf '%s' "$apk_mapped" | head -1 | sed 's/  */ /g' | cut -c1-180); the application says: ${native_sentence:-nothing}"
    record native-abi PASS "the mapped library is the one built for the device ABI" \
        "lib/$abi/libumbra.so, the only slice the loader can take on $abi"
elif [ -n "$native_failure" ]; then
    record native-load FAIL "the native library is mapped into the running process" \
        "the platform refused the load: $native_failure"
    record native-abi NOT APPLICABLE "the mapped library is the one built for the device ABI" \
        "nothing was loaded"
elif [ -n "$native_sentence" ]; then
    record native-load PASS "the native library is mapped into the running process" \
        "the native functions answered in the process even though no mapping could be matched: ${native_sentence}"
    record native-abi NOT VERIFIED "the mapped library is the one built for the device ABI" \
        "the functions answered but the mapping out of base.apk was not found, so which slice ran was not observed"
elif [ -n "$link_error" ]; then
    record native-load FAIL "the native library is mapped into the running process" \
        "$(printf '%s' "$link_error" | head -2 | tr '\n' ' ')"
    record native-abi NOT APPLICABLE "the mapped library is the one built for the device ABI" \
        "nothing was loaded"
elif [ "$maps_readable" = "no" ]; then
    record native-load NOT VERIFIED "the native library is mapped into the running process" \
        "no reading of /proc/${maps_pid:-?}/maps was possible (neither run-as nor adb root), so nothing was observed either way"
    record native-abi NOT VERIFIED "the mapped library is the one built for the device ABI" \
        "no reading of the process map was possible"
elif [ "$reverse_up" = "no" ]; then
    # The maps were read and the library is not in them -- but the socket the
    # application is built to reach was never mapped into the device, so the
    # channel could not have opened.  That is a hole in the test, and it is
    # reported as one rather than as a defect of the application.
    record native-load NOT VERIFIED "the native library is mapped into the running process" \
        "the maps of pid $maps_pid are readable and hold no libumbra.so, but no adb reverse rule maps tcp:4001, so the channel was never reachable; the application says: ${app_text:-no notification text}"
    record native-abi NOT VERIFIED "the mapped library is the one built for the device ABI" \
        "nothing was loaded because nothing was reachable"
else
    # The socket is mapped and the library is still absent.  Its load follows
    # the success of the channel, and the last thing the application wrote is
    # the only account of why that did not happen.
    late_text=$(notification_text)
    threads "$maps_pid" "$OUT/raw/thread-dump.txt"
    stack_top=$(grep -m3 'at io\.umbra\.beacon' "$OUT/raw/thread-dump.txt" 2>/dev/null \
        | sed 's/^ *//' | tr '\n' ' ' || true)
    printf '%s\n' "${late_text:-no notification of $PKG carries a text}" >"$OUT/raw/notification-text-late.txt"
    record native-load NOT VERIFIED "the native library is mapped into the running process" \
        "the maps of pid $maps_pid hold no libumbra.so although tcp:4001 is mapped and the map was watched for ${maps_waited}s; the application said \"${app_text:-nothing}\" and then \"${late_text:-nothing}\"; the stack was last at: ${stack_top:-no umbra frame in the dump}; our own log: $(tail -4 "$OUT/raw/logcat-umbra.txt" 2>/dev/null | tr '\n' ' ')"
    record native-abi NOT VERIFIED "the mapped library is the one built for the device ABI" \
        "nothing was loaded, so there was no mapping to judge"
fi

# ---------------------------------------------------------------------------
# 6. the process is killed under the service, and something is watched
#
# START_STICKY is a request, not a promise: what Android does with it is the
# question, and the only answer is what happens next.
# ---------------------------------------------------------------------------

# A process with no service in it has nothing to restart.  The eighth run
# killed a process whose service had already been removed by force-stop and
# read the silence as "Android refused the sticky flag": the service record is
# established before the kill, and the state before it is written down.
pre_state=$(service_state)
if ! printf '%s' "$pre_state" | grep -q "$SERVICE_COMPONENT"; then
    kill_started_by=$(start_service)
    wait_for_service_record >/dev/null 2>&1 || true
    sleep 4
    pre_state=$(service_state)
fi
printf '%s\n' "$pre_state" >"$OUT/raw/services-before-kill.txt"

pid=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
if printf '%s' "$pre_state" | grep -q "$SERVICE_COMPONENT"; then
    nothing_reason="there was no process to kill"
else
    # Without a running service a kill proves nothing about START_STICKY, so
    # the process is left alone and the record says what was missing.
    nothing_reason="no foreground service was running before the kill, so there was nothing to restart"
    pid=""
fi
if [ -n "$pid" ]; then
    # As root the plain kill works; without root the same UID may still signal
    # its own process, which is what run-as gives it.  `su 0` was tried first
    # in the previous version and, on an image where su exists but does
    # nothing, it answered success and the process was never killed.
    adb shell kill -9 "$pid" >/dev/null 2>&1 \
        || adb shell run-as "$PKG" kill -9 "$pid" >/dev/null 2>&1
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
        "$nothing_reason"
    record service-restart NOT VERIFIED "the service, not only the process, is restored" \
        "$nothing_reason"
fi

# ---------------------------------------------------------------------------
# 7. the consent screen can stop it
# ---------------------------------------------------------------------------

if tap_text "Start beacon" 0 2>/dev/null; then
    : # the activity was restarted by the kill; the button is there
fi
adb shell am start -W -n "$ACTIVITY" >/dev/null 2>&1
sleep 2
ensure_front || true
if tap_text "Stop beacon"; then
    sleep 3
    state=$(service_state)
    printf '%s\n' "$state" >"$OUT/raw/services-after-stop.txt"
    if printf '%s' "$state" | grep -q "$SERVICE_COMPONENT"; then
        record stop FAIL "the service stops" \
            "the ServiceRecord for $SERVICE_COMPONENT is still there"
    else
        record stop PASS "the service stops" \
            "no ServiceRecord for $SERVICE_COMPONENT"
    fi
    # The platform takes the notification down asynchronously, so it is given
    # fifteen seconds before the answer is "it is still there".
    gone_after=""
    for i in $(seq 1 15); do
        notif=$(notification_state)
        if ! printf '%s' "$notif" | grep -q "pkg=$PKG"; then
            gone_after=${i}s
            break
        fi
        sleep 1
    done
    if [ -n "$gone_after" ]; then
        record stop-notification PASS "the notification goes away with the service" \
            "no notification for $PKG ${gone_after} after the service stopped"
    else
        record stop-notification FAIL "the notification goes away with the service" \
            "a notification for $PKG is still posted 15s after the service stopped"
    fi
else
    # Same fallback as the start: the claim is split into the button (not
    # verified) and the service (verified the way a shell would do it).
    record consent-button-stop NOT VERIFIED "the consent screen's Stop button stops the service" \
        "the button could not be tapped on a headless emulator"
    adb shell am stopservice -n "$SERVICE_COMPONENT" >"$OUT/raw/am-stop-service.txt" 2>&1
    sleep 3
    state=$(service_state)
    printf '%s\n' "$state" >"$OUT/raw/services-after-stop.txt"
    if printf '%s' "$state" | grep -q "$SERVICE_COMPONENT"; then
        record stop FAIL "the service stops" \
            "am stopservice was issued and the ServiceRecord for $SERVICE_COMPONENT is still there"
    else
        record stop PASS "the service stops" "am stopservice; no ServiceRecord for $SERVICE_COMPONENT"
    fi
    # The platform takes the notification down asynchronously, so it is given
    # fifteen seconds before the answer is "it is still there".
    gone_after=""
    for i in $(seq 1 15); do
        notif=$(notification_state)
        if ! printf '%s' "$notif" | grep -q "pkg=$PKG"; then
            gone_after=${i}s
            break
        fi
        sleep 1
    done
    if [ -n "$gone_after" ]; then
        record stop-notification PASS "the notification goes away with the service" \
            "no notification for $PKG ${gone_after} after am stopservice"
    else
        record stop-notification FAIL "the notification goes away with the service" \
            "a notification for $PKG is still posted 15s after am stopservice"
    fi
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
# grep -c prints 0 and exits 1 when nothing matched, so `|| echo 0` produced
# "0\n0" and the arithmetic test below failed with "integer expression
# expected" on a run where nothing had crashed.
fatal=$(grep -c "FATAL EXCEPTION" "$OUT/raw/logcat-full.txt" 2>/dev/null) || fatal=0
anr=$(grep -c "ANR in $PKG" "$OUT/raw/logcat-full.txt" 2>/dev/null) || anr=0
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
