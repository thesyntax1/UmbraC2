# Build and test evidence, module by module

> One page per module: what was built, where, with which toolchain, and what
> the result was.  Two environments are named — **local** (the machine this
> repository is maintained on: Debian, x86_64, Python 3.11.2, gcc 12) and
> **CI** (GitHub Actions, `ubuntu-latest`, the run ids are given).
>
> The rule: a row is green only if the command in it ran and exited zero on
> the commit named at the top.  Everything else says what it is.

Commit of record: `93b679c` (CI run 41233256649).
Reviewed: 2026-10-31.

## The summary

| Module | Build | Tests | CI job | Verdict |
|---|---|---|---|---|
| Go server | green on 1.22.10 **and** 1.27.3 | 25 packages, `-race` clean | **green** (1.22 and stable) | verified on two toolchains |
| Go beacon | green on 1.22.10 and 1.27.3 | 5 packages, `-race` clean | **green** (1.22 and stable) | verified on two toolchains |
| Python console + protocol | n/a | 378 passed in a clean venv from the hashed lock | **green** (3.11 and 3.12) | verified from a lock file |
| Rust beacon | **green** on all three targets | 125 unit + 8 vector tests, 0 failed | **green** (default, `chacha`, macOS ×2) | compiled, tested and run as a binary |
| Android implant | **red** | Kotlin compilation error | **red** | not verified |
| Dashboard | built by `go build` | Go test + jsdom smoke | green (inside `go server`) | verified, not in a browser |

The gate this feeds is in [`RELEASE-PROCESS.md`](RELEASE-PROCESS.md): **the
release gate is closed**, because a red job is a red job.

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

## 5. Android implant

**Not verified — it does not compile.**  No JDK, no Gradle, no SDK and no
emulator on the maintaining machine.

Versions pinned this pass, so the failure is at least reproducible:

| Component | Version | Where |
|---|---|---|
| JDK | 17 | `.java-version`, `compileOptions`/`jvmTarget` in `app/build.gradle`, `setup-java` in CI |
| Gradle | 8.7 | `gradle-wrapper.properties`, `gradle-version` in CI |
| Android Gradle Plugin | 8.5.2 | root `build.gradle` |
| Kotlin | 1.9.24 | root `build.gradle` |
| compileSdk / targetSdk | 34 | `app/build.gradle` |
| minSdk | 33 | `app/build.gradle` (X25519 from the platform provider) |
| Build tools | 34.0.0 | `app/build.gradle` (pinned this pass) |
| CMake | 3.22.1 | `app/build.gradle` |
| NDK | **not pinned** | AGP chooses it; pin on the first successful build and record it here |

CI job `android` fails in `assembleDebug` with a Kotlin compilation error; the
compiler's `e: file:line` lines are lifted into annotations by
`scripts/ci_tail.sh`, which is how the next fix will start.

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
* The CI run ids are the proof of the CI column.  A local run and a CI run are
  not the same thing, which is why both are listed.
