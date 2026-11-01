# Build and test evidence, module by module

> One page per module: what was built, where, with which toolchain, and what
> the result was.  Two environments are named — **local** (the machine this
> repository is maintained on: Debian, x86_64, Python 3.11.2, gcc 12) and
> **CI** (GitHub Actions, `ubuntu-latest`, the run ids are given).
>
> The rule: a row is green only if the command in it ran and exited zero on
> the commit named at the top.  Everything else says what it is.

Commit of record: `e1e27b0` (CI run 41289349561) — eleven jobs of eleven,
including the Windows target that no job had ever compiled.
Reviewed: 2026-10-31.

## The summary

| Module | Build | Tests | CI job | Verdict |
|---|---|---|---|---|
| Go server | green on 1.22.10 **and** 1.27.3 | 25 packages, `-race` clean | **green** (1.22 and stable) | verified on two toolchains |
| Go beacon | green on 1.22.10 and 1.27.3 | 5 packages, `-race` clean | **green** (1.22 and stable) | verified on two toolchains |
| Python console + protocol | n/a | 378 passed in a clean venv from the hashed lock | **green** (3.11 and 3.12) | verified from a lock file |
| Rust beacon | **green** on five targets (linux, `chacha`, macOS ×2, **windows**) | 125 unit + 8 vector tests, 0 failed | **green** (default, `chacha`, macOS ×2, windows) | compiled, tested and run as a binary; the windows binary links and is **never executed** |
| Android implant | **green** (`assembleDebug`, three ABIs, NDK pinned) | 27 compile errors and **22 lint errors** closed; `lintDebug` green; 29 warnings; no unit tests | **green** (11 of 11 jobs on `e1e27b0`) | compiles, packages and passes lint; never run on a device |
| Dashboard | built by `go build` | Go test + jsdom smoke | green (inside `go server`) | verified, not in a browser |

The gate this feeds is in [`RELEASE-PROCESS.md`](RELEASE-PROCESS.md): **the
release gate is closed** — not because a job is red any more, but because the
changelog the gate requires does not exist.  A green matrix is the first
condition of that gate, not the gate.

## 1. Go server

**Local, both ends of the supported range.** The manifest declares `go 1.22`,
so the oldest toolchain it allows and the newest one that exists were both
installed from PyPI (`tools/get_go.py`, digests verified against the index) and
run separately:

| Toolchain | `go build ./...` | `go vet ./...` | `go test ./... -count=1` | `-race` | `gofmt -l` |
|---|---|---|---|---|---|
| go1.22.10 | ok (17 s cold) | ok | 25 packages ok, 0 fail | 25 ok | empty |
| go1.27.3 | ok (21 s cold) | ok | 25 packages ok, 0 fail | 25 ok | empty |

Command, for either toolchain:

```bash
python3 tools/get_go.py --version 1.22.10 --dest /tmp/go122
export PATH=/tmp/go122/go/bin:$PATH GOTOOLCHAIN=local GOPROXY=off
cd server && go build ./... && go vet ./... && go test ./... -count=1 -race
```

`GOPROXY=off` is part of the evidence: the module has no requirements, so the
build must succeed with the network switched off.  It does.

**CI.** `ci.yml` job `go server (1.22)` and `go server (stable)`, both green
on run 41227557468 (`d9aa1a9`): `gofmt` gate, `go vet`,
`go test -race`, `go build -trimpath`, `go vet -race`, and a check that
`go.sum` stays empty.

## 2. Go beacon (`implant/go`)

**Local:** go1.22.10 and go1.27.3, `go test ./... -race` = 5 packages ok,
`gofmt` empty, `go build ./...` ok.  The beacon also runs `--selftest` in CI.

**CI:** `go implant (1.22)` and `go implant (stable)`, both green — including `go mod verify`, the
empty-`go.sum` gate, `--selftest`, and a start against an unreachable server
that must exit cleanly.

## 3. Python console, mock and contract

**Clean environment, not the maintainer's virtualenv.** This was the point of
the exercise: the suite had only ever run in a venv that had accumulated
packages over months.

```bash
python3 -m venv /tmp/locked-venv
/tmp/locked-venv/bin/pip install --require-hashes -r requirements-dev.lock
GO=/path/to/go /tmp/locked-venv/bin/pytest tests/ -q
```

* `requirements-dev.lock` is new: `pip-compile --generate-hashes`, 8 packages,
  every wheel by digest.  `requirements-dev.txt` stays the readable input.
* Result: **378 passed in 194 s** (including `tests/test_real_server.py`,
  which builds and drives the server binary).
* The first clean run failed two tests that pass in the warm venv
  (`test_the_picture_of_the_reach_shows_the_graph`,
  `test_a_chained_pivot_falls_back_to_the_server_when_the_peer_is_down`).
  Cause: fixed 5- and 10-second deadlines that the full suite's load can
  exceed.  They now wait 20 s and assert with a message; a flaky proof is a
  proof nobody can use.

**CI:** `protocol (python 3.11)` and `protocol (python 3.12)`, both green;
each installs from the hashed lock with `--require-hashes`, runs the
consistency checkers, `pytest tests`, and regenerates `contracts/vectors.json`
to prove the vectors are reproducible.

## 4. Rust beacon

**Green.**  The crate compiles, its tests run and its release binary starts.
That is new in this pass: before it, the crate had never been handed to a
compiler at all.

**Where it ran.**  Not here.  There is still no `cargo` on the maintaining
machine and `static.rust-lang.org` is unreachable from it, so the Rust column
of this page is CI-only.  Three jobs, one commit (`93b679c`):

| Job | Command | Result |
|---|---|---|
| `rust beacon` | `cargo check --locked --all-targets` + `cargo test --locked --all-targets` + `cargo build --locked --release` + `--selftest` | **green** |
| `rust beacon (--features chacha)` | the same four, with `--features chacha` | **green** |
| `rust beacon (the macOS target compiles)` | `cargo check --locked --all-targets --target x86_64-apple-darwin` and `aarch64-apple-darwin` | **green** |

The test log of the run — read from the temporary `ci/log-rust` branch, because
the job log itself sits on a blob host this machine cannot reach — says:

```
Running unittests src/lib.rs   test result: ok. 125 passed; 0 failed
Running unittests src/main.rs  test result: ok.   0 passed; 0 failed
Running tests/vectors.rs       test result: ok.   8 passed; 0 failed
```

The eight vector tests are the cross-language contract
(`contracts/vectors.json`), so a Rust derivation that drifts from Go or Python
fails here, not in production.

**What it took: 38 compile errors, in five rounds, none of them silenced.**

| Round | Errors | Kinds | What was wrong |
|---|---|---|---|
| 1 (`37d49b8`) | 35 | `E0308` ×18, `E0382` ×4, `E0061`, `E0502`, `E0507`, `E0599`, `E0277` | mismatched borrows and ownership: a `String` handed to a `&str` parameter, `Vec<&str>` annotated over a `usize`, `u32` passed where `u64` milliseconds were wanted, `EphemeralSecret` borrowed after it had been consumed, a listener thread that took the address its own report still needed, `sessions::open` putting two different pipe types in one array, `vpn::send_packet` promising `()` while returning a byte count |
| 2 (`2e98aeb`) | 3 | `E0308`, `E0599` | the residue the first round uncovered: `domain.collect` never initialised the `me` field, `hygiene::clean_environment` called `.is_ok()` on `remove_var`, which returns `()` |
| 3 (`d204e1b`) | 0 compile, 7 tests | behaviour | see the test row below |
| 4 (`ff2e0a0`) | 0 | — | the last red test: the group table |
| 5 (`93b679c`) | 1 | `E0382` | `keylog_to_file` on macOS built its reply from a path the thread had already moved — and the Windows twin of the same function had the identical bug and had never been compiled either |

No `unwrap`, no `allow`, no `unsafe` added and no security check removed on the
way: the four rounds changed flow and types only.

**The seven test failures that were not compile errors.**  Once the crate
built, `cargo test` failed seven times, and every one was a real defect in the
code, not a wrong assertion:

| Test | The defect |
|---|---|
| `beacon` jitter ×2 | `Window::schedule` scaled the operator's window by 0.5–2×, so a 20 s jitter produced gaps up to 240 s and the server's silence watch would read a live host as dead.  The jitter is now drawn *inside* the window. |
| `parse_delegation` | the account name kept the `CN=` prefix |
| `parse_group_table` | two revisions of the wrong idea: splitting on every space cut `CORP\Domain Admins` in half, splitting on runs of spaces merged `Well-known group S-1-1-0` into one column.  The row is now read by what its columns mean — SID first `S-1-` token, type the word or two in front of it, name everything before that |
| `parse_group_members` | the group-title line was parsed as a member, and the walk stopped at the blank line before the members |
| `migrate` ordering | a plan with no target reported a missing image |
| wasm capability | the test fixture declared its entry point with the import's three-argument signature, so the module failed on arity before the capability check.  The fixture was wrong, the assertion was not touched; a module without the capability is still refused |

**What this does not prove.**  It compiles and its own tests pass; it has not
been run against a real server from Rust (the Go and Python beacons have been),
the macOS target is type-checked on Linux and never linked or executed, the
`chacha` job proves the suite runs with that feature, not that an operator uses
it, and **no job in the matrix compiles the Windows-gated code** — 118
`cfg(windows)` blocks across 18 files, including its own `keylog_to_file`.
Round 5 fixed the Windows twin by reading it.  That is a reading, not a build.

### The Windows target

`cfg(windows)` covers 118 blocks across 18 files, and until `e034130` no job
had ever given them to a compiler: the linux job cannot see them, and the
macOS job compiles two apple targets.  The new job checks **every** target for
`x86_64-pc-windows-gnu` and then links the binary, because a target that
type-checks and does not link is half a result.

| Item | Value |
|---|---|
| Target | `x86_64-pc-windows-gnu` |
| rustc | 1.99.1 (58cf8f9c3 2026-10-13), stable, from `dtolnay/rust-toolchain` |
| Linker | `x86_64-w64-mingw32-gcc` (GCC) 13-win32, from `gcc-mingw-w64-x86-64` |
| `ld` | GNU ld (GNU Binutils) 2.45.90.20260125 |
| Commands | `cargo check --locked --all-targets --target x86_64-pc-windows-gnu` then `cargo build --locked --target x86_64-pc-windows-gnu` |
| Artefact | `target/x86_64-pc-windows-gnu/debug/umbra-beacon.exe` — *PE32+ executable for MS Windows 5.02 (console), x86-64, 20 sections* |
| Result | **PASS** (compiles, links) / **NOT VERIFIED** (never executed) |

**Seventeen failures, in four rounds, every one of them a real defect:**

| Round | Commit | Failures | What was wrong |
|---|---|---|---|
| 1 | `59913ea` | 13 compile | `post::token` called `win::duplicate_token`, a function that does not exist; two C strings ended with `push(0)` (a byte where a `char` was wanted); an ordinal was cast through `*const u16`, which cannot be a pointer; three raw dereferences were outside `unsafe`; `Luid` was moved twice (it is two integers); the import walk assigned to an immutable `offset`; `senses` imported `std::os::raw::u32`, which does not exist; `bof` read `PAGE_READWRITE` from a module it lives outside of; `domain` handed the text of an edge kind where the graph wants the static word |
| 2 | `3510f3c` | 1 compile | `protect_image` is an `unsafe fn`; the call was the only one in its function without a block |
| 3 | `f3aee67` | 2 compile | `GetAsyncKeyState` returns `i16` and the mask was `0x8000`, which does not fit in one — in both copies of the key loop |
| 4 | `e1e27b0` | 1 **link** | `CryptUnprotectData` lives in `crypt32`, which a mingw link does not pull in by default, and its extern block had no `#[link]` at all: the symbol existed and the linker did not know where |

Every one is the kind of defect that compiles nowhere until the target is
tried: the type checker had never seen these lines, and the linker had never
been asked for these libraries.

## 5. Android implant

**Green.**  `assembleDebug` builds a debug APK for `arm64-v8a`, `armeabi-v7a`
and `x86_64`; before this pass the app had never been through a Kotlin
compiler.

**Where it ran.**  CI only — there is no JDK, Gradle or SDK on the maintaining
machine, and the SDK cannot be downloaded from it.  Two workflows ran it:
`ci.yml` (`android implant (compile only)`, `gradle --no-daemon assembleDebug`)
and the temporary `ci-log.yml`, which additionally ran `testDebugUnitTest` and
`lintDebug` and published the reports.

| Tool | Version | Where it comes from |
|---|---|---|
| JDK | Temurin 17 | `actions/setup-java@v5` |
| Gradle | 8.7 | `gradle/actions/setup-gradle@v4` |
| Android Gradle Plugin | 8.5.2 | `build.gradle`, pinned |
| Kotlin | 1.9.24 | `build.gradle`, pinned |
| compileSdk / targetSdk | 34 / 34 | `app/build.gradle` |
| minSdk | 33 | `app/build.gradle` — X25519 from the platform XDH provider |
| build-tools | 34.0.0 | pinned in `app/build.gradle` |
| NDK | 26.1.10909125 | **pinned after the first green build**, the version that build used |
| CMake | 3.22.1 | pinned in `app/build.gradle` |

**The errors were not what the first report said.**  The GitHub annotation list
showed twenty; the compiler had emitted **twenty-seven** (the annotation API
caps the list).  And they were not an API-level mismatch: with `minSdk 33`
every API the code needed — `UsageStatsManager.getAppStandbyBucket()` (28),
`NotificationManager.areNotificationsEnabled()` (24),
`PackageInstaller.uninstall` (21), `DevicePolicyManager.wipeData(int)` (21),
`ScanResult.level` (1) — has been available for years.  The causes were four,
and each was verified against the platform reference before it was touched:

| Cause | Errors | Example |
|---|---|---|
| a member that does not exist, has another name, or is hidden | 15 | `Build.PRODUCT_DEVICE`, `IPackageInstaller`, `setDeviceOwner`, `GLOBAL_ACTION_VOLUME_*`/`POWER_DIALER`, `Context.ROLE_MANAGER`, `PowerManager.standbyBucket` and its `STANDBY_BUCKET_*`, `ScanResult.rssi` (it is `level`) |
| a Kotlin getter read as a property | 4 | `areNotificationsEnabled` instead of `areNotificationsEnabled()`, `isDeviceOwnerApp` without its argument (two messages on that line) |
| a missing import | 3 + 1 cascade | `Context` in `AppDump.kt`; the "cannot infer T" at line 118 went with it |
| a wrong argument list, or operator precedence | 4 | `wipeData()` with no flags, `clearDeviceOwnerApp()` with no package, `addPrimaryClipChangedListener` with a handler, `"size" to x ?: ""` |

Nine rounds, one file per round, each followed by a build, so that the delta of
every fix is visible and no fix can hide another:

| Round | Commit | Errors before → after | What it fixed |
|---|---|---|---|
| 1 | `0789c3a` | 27 → 23 | the missing `Context` import and the inference error it caused |
| 2 | `51bbda3` | 23 → 22 | the Elvis precedence in the dump row |
| 3 | `2bd7d32` | 22 → 20 | the hidden installer callback; `wipeData(0)` |
| 4 | `66df80a` | 20 → 19 | `Build.PRODUCT_DEVICE` |
| 5 | `4f26aff` | 19 → 15 | the device-owner trio: package argument, `isDeviceOwnerApp(pkg)`, and no pretence of setting ownership |
| 6 | `f67f5f3` | 15 → 14 | `ScanResult.level` |
| 7 | `169a0e7` | 14 → 11 | the invented `GLOBAL_ACTION_*` constants; volume goes through the audio manager |
| 8 | `711399a` | 11 → 2 | the standby bucket from `UsageStatsManager`; `areNotificationsEnabled()` |
| 9 | `6cddc1a` | 2 → **0** | `RoleManager` by class; one-argument clipboard listener |

No `TODO`, no empty return, no `runCatching` added, no permission removed and
no manifest entry touched.  The one behaviour that changed on purpose is
`persist.install --method device_owner`: the platform cannot grant ownership to
an installed app, so the command now succeeds only if the phone already is the
owner and otherwise fails with that sentence, instead of recording a technique
that was never installed.

**What came with the green build, and did not go away.**

* **Lint: 22 errors, 30 warnings** (`1aac1a9`, `lintDebug`, report in the
  temporary `ci/log-android` branch).  Fifteen are `MissingPermission` — calls
  the platform may refuse with `SecurityException` that lint cannot see guarded
  (`Sense.kt` ×9, `BluetoothScan.kt` ×2, `Lab.kt` ×2, `Media.kt`,
  `Forensics.kt`), one is `ScheduleExactAlarm`, four are
  `PermissionImpliesUnsupportedChromeOsHardware` in the manifest, two are
  `SuspiciousIndentation`.  The compiler is satisfied; the static analysis is
  not.  That work is a hardening pass, not a compile fix.
* **There are no Android unit tests.**  `testDebugUnitTest` runs, finds no test
  source set and succeeds with nothing — `NO-SOURCE`, not "all tests passed".
* **Nothing has run on a phone.**  An APK that builds is not an APK that
  starts, and neither is an APK whose permissions are granted.

### The lint findings, before and after

`assembleDebug` was green and `lintDebug` was not: the compiler accepts code
that the static analysis will not.  The report is real, and the count is the
report's own (`ci-log/android-lint-report.txt`, published by the temporary
`ci-log.yml`).

| Run | `assembleDebug` | `testDebugUnitTest` | `lintDebug` | Errors | Warnings |
|---|---|---|---|---|---|
| `1aac1a9` | green | `NO-SOURCE` | **failed** | 22 | 30 |
| `ae7b744` (after the permission guards) | green | `NO-SOURCE` | **failed** | 9 | 30 |
| `f3aee67` (after the alarm and the manifest) | green | `NO-SOURCE` | **failed** | 2 | 30 |
| `e1e27b0` (after the indentation) | green | `NO-SOURCE` | **green** | **0** | **29** |

Each finding, and what it actually was:

| Finding | Count | The root cause | What was done |
|---|---|---|---|
| `MissingPermission` — runtime permissions | 13 | the calls sat inside `try { } catch (Throwable)`, which lint does not accept and which would also have hidden the refusal; three of them were inside helper functions it cannot follow | each call site now names the permission and catches `SecurityException` with the sentence the operator should read: `Sense` (location ×2, scan results, saved networks, paired devices, discovery devices), `BluetoothScan` (start and cancel of the discovery), `Media` (camera), `Lab` (the phone number) |
| `MissingPermission` — device owner | 1 | `PackageInstaller.uninstall` needs `DELETE_PACKAGES` **or** `REQUEST_DELETE_PACKAGES` on paper; the platform exempts the device owner in `PackageInstallerService.uninstall`, which lint cannot model | `REQUEST_DELETE_PACKAGES` (a **normal** permission, granted at install, no prompt) is declared, because the platform's fallback branch does check it; `DELETE_PACKAGES` is not, because it is `signature\|privileged` and the application can never hold it |
| `MissingPermission` — privileged | 1 | `TelephonyManager.getSubscriberId` needs `READ_PRIVILEGED_PHONE_STATE`, which only a system application can hold: the call could never succeed | the call is gone, and the field says `unknown`, which is exactly what it said before — a check for the simulator's subscriber id against a value that cannot be read is a check of nothing |
| `ScheduleExactAlarm` | 1 | `setExactAndAllowWhileIdle` throws when the phone denies exact alarms, and the code never asked | `canScheduleExactAlarms()` decides: exact when allowed, `setAndAllowWhileIdle` otherwise, and the persistence entry says which of the two the phone got |
| `PermissionImpliesUnsupportedChromeOsHardware` | 4 | `READ_SMS`, `RECEIVE_SMS`, `RECEIVE_MMS` and `CAMERA` imply telephony and camera hardware, and a device without either was being filtered out | `<uses-feature android:required="false">` for `telephony`, `camera` and `camera.any` — the manifest now says what the code already does when the hardware is missing |
| `SuspiciousIndentation` | 2 | two `try` blocks returned the value of a statement that was indented as a continuation of the line above | de-indented; the parse was already a separate statement, so the behaviour is identical |

No rule was disabled, no `@SuppressLint` and no baseline was added, and no
catch was left empty: every refusal the platform can produce is turned into a
sentence in the report.

**The 29 warnings are still there** and are listed rather than explained away:
11 `ObsoleteSdkInt` (the `minSdk 33` checks), 3 `StaticFieldLeak`,
`WakelockTimeout`, `QueryPermissionsNeeded`, `BatteryLife`,
`HardwareIds`, `DefaultLocale`, `DataExtractionRules`, `RedundantLabel`,
`MissingApplicationIcon`.  None of them is an error and none of them has been
triaged.

## 6. Dashboard

There is no separate build: the page is a string in `internal/dash`, compiled
into the server.  What proves it is the Go test that computes the CSP hash from
the bytes that are served (`TestThePolicyNamesThePageThatIsServed`), the tests
for the token comparison and the headers, and `tools/dash_smoke.mjs`, which
renders the page in jsdom with a hostile agent name and asserts the name stays
text.  It is **not** a browser: it does not enforce the CSP.

## 7. What this page does not claim

* It does not claim the code is correct; it claims these commands ran and
  exited zero, on these commits, in these environments.
* It does not claim the CI matrix covers every platform: Windows, macOS and a
  real phone have never run anything, and the Rust `--target` checks compile
  but do not link or execute.
* It does not claim the Rust job is green on a machine that could build it
  here: every Rust row comes from CI, and the temporary `ci/log-rust` branch
  that carried the test output is deleted once the Android job is green (the
  run id and the SHA stay).
* It does not claim the Windows build exists.  No job compiles the
  `cfg(windows)` half of the crate; it is read, not built.
* It does not claim the Android app works.  The APK is compiled, packaged and
  lint-clean, it still has **no unit test** (`NO-SOURCE`), and no emulator or
  phone has ever started it.  "Green" here means the compiler and the static
  analysis both exited zero.
* It does not claim the Windows beacon works.  It compiles for the target and
  links into a PE32+ executable; nothing has run it, because this is a linux
  machine.  A linker that is satisfied is not a program that starts.
* The CI run ids are the proof of the CI column.  A local run and a CI run are
  not the same thing, which is why both are listed.
