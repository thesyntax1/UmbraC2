#!/bin/sh
# Run a command in CI and, if it fails, say *why* somewhere we can read.
#
# GitHub keeps the job log in blob storage and the API only hands back a
# redirect to it: from a network that cannot reach that host, a failed job is
# an exit code and nothing else.  Annotations come back through the API as
# text, so this helper lifts the interesting lines of the log into them.
#
# Usage:  sh scripts/ci_tail.sh cargo test --all-targets
#
# It prints the whole log as usual (a human reading the web UI still wants
# it), then, on failure, emits at most ten annotations, four log lines each:
#
#   * the Kotlin compiler's `e: file:line:col ...` lines, when there are any;
#   * otherwise the lines that start with `error`;
#   * otherwise the last ten lines of the output.
#
# A batch of four per annotation is deliberate: a Rust crate that has never
# compiled fails with dozens of errors, and eight annotations of one line
# would take five CI runs to see them all.
set -u

log=$(mktemp)
trap 'rm -f "$log"' EXIT

"$@" >"$log" 2>&1
rc=$?
cat "$log"

if [ "$rc" -ne 0 ]; then
    strip() {
        sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r'
    }
    picked=""
    if strip <"$log" | grep -q '^e: '; then
        picked=$(strip <"$log" | grep '^e: ' | head -40)
    elif strip <"$log" | grep -qE '^error|: error'; then
        picked=$(strip <"$log" | grep -E '^error|: error' | head -40)
    else
        picked=$(strip <"$log" | tail -20)
    fi

    printf '%s\n' "$picked" |
        awk 'NR % 4 == 1 { if (buf != "") print buf; buf = $0; next }
                      { buf = buf " | " $0 }
             END      { if (buf != "") print buf }' |
        head -10 |
        while IFS= read -r line; do
            echo "::error::$(printf '%s' "$line" | sed 's/%/%25/g; s/::/#/g')"
        done
    echo "::error::ci_tail: '$*' exited $rc"
fi

exit "$rc"
