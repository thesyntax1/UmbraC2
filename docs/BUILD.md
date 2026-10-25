# Building and cross-compiling

Everything is reproducible with the Makefile, but each step is spelled out below
so you can run it by hand (or in CI) without the wrapper.

Prerequisites:

| Tool | Version | Used for |
|---|---|---|
| Go | 1.22+ | team server (no third-party modules) |
| Rust | 1.75+ (`rustup`) | beacon |
| Python | 3.9+ | operator console, tests, vectors |
| Android SDK/NDK | API 33+ / NDK r26+ | Android implant |
| make, bash | any recent | convenience targets |

---

## 1. Team server (Go)

The server has **zero third-party dependencies**, so it builds offline.

```bash
cd server
go build -trimpath -ldflags "-s -w" -o ../build/umbra-server ./cmd/umbra-server
./../build/umbra-server -version
```

Static binary (recommended for deployment):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -tags netgo -ldflags "-s -w -extldflags '-static'" \
  -o umbra-server-linux-amd64 ./cmd/umbra-server
```

Cross-compilation matrix (`CGO_ENABLED=0` is what makes this trivial):

```bash
for target in linux/amd64 linux/arm64 windows/amd64 darwin/arm64 darwin/amd64; do
  os=${target%/*}; arch=${target#*/}
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  echo ">> $os/$arch"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" \
    -o "../build/umbra-server-$os-$arch$ext" ./cmd/umbra-server
done
```

Developer conveniences:

```bash
go run ./cmd/umbra-server -gen-psk       # 32-byte hex PSK
go run ./cmd/umbra-server -gen-token     # 32-byte hex operator token
go run ./cmd/umbra-server -gen-config    # default JSON config on stdout
go vet ./... && go test ./...            # vet + unit + vector tests
```

---

## 2. Rust beacon

Configuration is baked in at compile time (one binary per engagement). The same
variables can be overridden at runtime for testing:

| Build-time variable | Meaning | Default |
|---|---|---|
| `UMBRA_SERVER` | `host:port` of the team server | `127.0.0.1:4001` |
| `UMBRA_PSK` | agent PSK (hex) | *(required)* |
| `UMBRA_AGENT_ID` | agent identity | random per run |
| `UMBRA_TRANSPORT` | `tcp` or `http` | `tcp` |
| `UMBRA_HTTP_PATH` | beacon path | `/api/v1/beacon` |
| `UMBRA_SLEEP` | base beacon interval (s) | `5` |
| `UMBRA_JITTER` | jitter percent (0–90) | `20` |

```bash
cd implant/rust

UMBRA_SERVER=10.10.14.7:4001 UMBRA_PSK=$UMBRA_AGENT_PSK UMBRA_AGENT_ID=web-01 \
  cargo build --release
ls -l target/release/umbra-beacon           # ~1-2 MB, stripped
./target/release/umbra-beacon --check       # print the effective config
./target/release/umbra-beacon --selftest    # offline upk/AEAD/session checks
```

Static, musl-based Linux builds (no glibc dependency):

```bash
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

Windows:

```bash
# GNU toolchain (needs mingw-w64: apt install gcc-mingw-w64-x86-64)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# or MSVC toolchain (build on Windows, or cross with cargo-xwin)
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

macOS (must run on macOS — Apple's SDK cannot be redistributed):

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin   # Apple silicon
cargo build --release --target x86_64-apple-darwin    # Intel
```

Optional ChaCha20-Poly1305 support (the beacon then offers it first and falls
back to AES-256-GCM if the server does not support it):

```bash
cargo build --release --features chacha
```

One-shot cross build of all desktop targets:

```bash
UMBRA_SERVER=10.0.0.5:4001 UMBRA_PSK=<hex> ./scripts/build-beacon.sh
# -> build/implant/umbra-beacon-{linux-amd64,linux-arm64,windows-x64.exe,...}
```

Size/perf knobs already set in `Cargo.toml`: `opt-level = "z"`, `lto = true`,
`codegen-units = 1`, `panic = "abort"`, `strip = true`.

---

## 3. Android implant

Requires JDK 17, Android SDK (platform 34) and NDK (r26+), plus
`ANDROID_HOME` / `ANDROID_NDK_HOME`.

```bash
cd implant/android

export UMBRA_HOST=10.0.2.2          # team server address reachable from the device
export UMBRA_PORT=4001
export UMBRA_PSK=<hex agent psk>
export UMBRA_AGENT_ID=pixel-7
export UMBRA_TRANSPORT=tcp          # or http
export UMBRA_HTTP_BASE=http://10.0.2.2:4003
export UMBRA_SLEEP=30
export UMBRA_JITTER=40

./gradlew assembleRelease            # if the wrapper is present (see below)
# app/build/outputs/apk/release/app-release-unsigned.apk
```

The Gradle wrapper jar is a binary and is not committed. Either generate it once

```bash
gradle wrapper --gradle-version 8.7   # creates gradlew + gradle-wrapper.jar
```

or just use the installed Gradle CLI — `make android-apk` picks whichever of the
two is available, and `make android-check` does a faster unsigned debug build.

Notes:

* `minSdk 33` — the implant uses the platform `XDH` provider for X25519.
* The APK is unsigned by default; sign it with `apksigner` and your own keystore
  if you need an installable artifact for a lab device.
* ABI filters: `arm64-v8a`, `armeabi-v7a`, `x86_64` (emulator + devices).
* The settings are compile-time constants (`BuildConfig`), so one APK per target —
  nothing is fetched from the network at start-up.

---

## 4. Operator console (Python)

```bash
python3 -m venv .venv
.venv/bin/pip install -e operator        # installs the `umbra` entry point
# or, without installing:
PYTHONPATH=operator python3 -m umbra_cli --help
```

Only runtime dependency: `cryptography` (X25519 + AES-GCM).

---

## 5. What is installed?

```bash
make doctor     # prints python/go/cargo/gradle versions and what is missing
```

Nothing in `make doctor` is fatal: `make check` (the static contract checks)
needs only Python, and `make test-py` needs Python plus `cryptography` and
`pytest`.

---

## 6. Tests and the protocol contract

```bash
make test                       # everything (needs Go + Rust + Python)
make test-go                    # go vet ./... && go test ./... -count=1
make test-rust                  # cargo test --all-targets
make test-py                    # pytest tests -q   (works with Python only)

# static checks that need no toolchain at all (run in review and in CI):
make check                      # both of the below
make check-vectors              # every language agrees on every wire constant
make check-symbols              # every cross-package Go/Rust reference resolves
```

`make check-vectors` compares the *tables* (message ids, limits, domain labels,
task kinds vs `docs/PROTOCOL.md`, operator RPC commands) rather than behaviour,
which is what catches the "one language still uses `0x1A`" class of bug.
`make check-symbols` exists because the review environment has no Go or Rust
compiler: it resolves every `pkg.Symbol` / `module::item` reference statically, so
a rename that misses one call site fails before a build is attempted.

The three suites all read `contracts/vectors.json`:

* `server/internal/upk/upk_test.go`, `crypt_test.go`, `session_test.go`;
* `implant/rust/tests/vectors.rs`;
* `tests/test_protocol.py`.

If you change anything in the encoding, key schedule, transcript or frame layout,
regenerate the vectors and re-run all three suites:

```bash
make vectors        # rewrites contracts/vectors.json from the Python reference
make test
```

The Go integration test (`server/internal/link/e2e_test.go`) starts a real server
on `127.0.0.1:0`, performs a full handshake as an agent and as an operator, and
verifies check-in → task → result → notification.

The Python end-to-end test drives the mock server, the reference agent and the
operator client together, which is also how `scripts/dev-up.sh` works.

---

## 7. Reproducible development environment

```bash
# Go/Rust/Python versions used by CI
go version          # go1.22 or newer
rustc --version     # 1.75 or newer
python3 --version   # 3.9 or newer

# everything from scratch
make clean && make build && make test
```

For a hermetic build, pin the toolchains (`rust-toolchain.toml`, `go.mod`'s
`toolchain` directive) and build inside the provided container images
(`golang:1.22`, `rust:1.75`, `python:3.11`) — the Go server needs no network
access at build time, the Rust beacon needs crates.io once (vendor them with
`cargo vendor` for offline builds).
