#!/usr/bin/env bash
# Cross-compile the UmbraC2 beacon for every supported desktop target.
#
#   UMBRA_SERVER=10.0.0.5:4001 UMBRA_PSK=<hex> ./scripts/build-beacon.sh
#
# Configuration is baked in at compile time (that is how implants are usually
# delivered); pass the same variables at runtime to override them for testing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BEACON="$ROOT/implant/rust"
OUT="${OUT:-$ROOT/build/implant}"

: "${UMBRA_SERVER:?set UMBRA_SERVER (host:port of the team server)}"
: "${UMBRA_PSK:?set UMBRA_PSK (hex key from umbra-server -gen-psk)}"
export UMBRA_SERVER UMBRA_PSK
export UMBRA_AGENT_ID="${UMBRA_AGENT_ID:-}"
export UMBRA_TRANSPORT="${UMBRA_TRANSPORT:-tcp}"
export UMBRA_SLEEP="${UMBRA_SLEEP:-10}"
export UMBRA_JITTER="${UMBRA_JITTER:-25}"

mkdir -p "$OUT"

build() {
  local target="$1" name="$2" binary="$3"
  echo "==> $name ($target)"
  if ! rustup target list --installed | grep -qx "$target"; then
    rustup target add "$target"
  fi
  ( cd "$BEACON" && cargo build --release --target "$target" )
  install -m 0755 "$BEACON/target/$target/release/$binary" "$OUT/$name"
  ls -l "$OUT/$name"
}

build x86_64-unknown-linux-musl  umbra-beacon-linux-amd64   umbra-beacon
build aarch64-unknown-linux-musl umbra-beacon-linux-arm64   umbra-beacon
build x86_64-pc-windows-gnu      umbra-beacon-windows-x64.exe umbra-beacon.exe

if [[ "$(uname -s)" == "Darwin" ]]; then
  build x86_64-apple-darwin  umbra-beacon-macos-amd64 umbra-beacon
  build aarch64-apple-darwin umbra-beacon-macos-arm64 umbra-beacon
else
  echo "==> macOS targets need a macOS host (or osxcross); skipping"
fi

echo
echo "artifacts in $OUT:"
ls -lh "$OUT"
echo
echo "each beacon reports as agent id '${UMBRA_AGENT_ID:-<generated at runtime>}' to $UMBRA_SERVER"
