#!/usr/bin/env bash
# Local development loop without building Go: mock server + fake agent + operator CLI.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PSK="$(python3 -c 'import os;print(os.urandom(32).hex())')"
TOKEN="$(python3 -c 'import os;print(os.urandom(32).hex())')"

echo "[dev] starting mock team server on 127.0.0.1:4002"
python3 tools/mock_server.py \
  --port 4002 \
  --psk "$PSK" \
  --operator "alice:$TOKEN" \
  --spawn-agent &
MOCK_PID=$!
trap 'kill $MOCK_PID 2>/dev/null || true' EXIT

sleep 1
echo "[dev] operator console (token in \$UMBRA_OPERATOR_TOKEN)"
echo
UMBRA_OPERATOR_TOKEN="$TOKEN" python3 -m umbra_cli --server 127.0.0.1:4002 --operator alice --watch "$@"
