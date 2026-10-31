#!/bin/sh
# Run a command in CI and, if it fails, say *why* somewhere we can read.
#
# GitHub keeps the job log in blob storage, and the API will only hand back a
# redirect to it: from a network that cannot reach that host, a failed job is
# an exit code and nothing else.  Annotations come through the API as text, so
# this helper lifts the interesting lines of the log into them.
#
# Usage:  sh scripts/ci_tail.sh cargo test --all-targets
#
# It prints the whole log as usual (the human reading the web UI still wants
# it), then, on failure, emits at most ten `::error::` lines: the first few
# compiler errors if the log has any, otherwise the tail of the output.
set -u

log=$(mktemp)
trap 'rm -f "$log"' EXIT

"$@" >"$log" 2>&1
rc=$?
cat "$log"

if [ "$rc" -ne 0 ]; then
    emitted=0
    if grep -q '^error' "$log"; then
        # Compiler output: the first error of each kind is the one that
        # explains the rest.
        grep -n '^error' "$log" | head -n 8 | while IFS= read -r line; do
            echo "::error::$(printf '%s' "$line" | sed 's/%/%25/g; s/::/#/g')"
        done
        emitted=8
    fi
    tail -n 10 "$log" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        echo "::error::$(printf '%s' "$line" | sed 's/%/%25/g; s/::/#/g')"
    done
    echo "::error::ci_tail: '$*' exited $rc"
fi

exit "$rc"
