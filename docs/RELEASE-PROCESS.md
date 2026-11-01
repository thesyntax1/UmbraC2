# Release process, and the gate that is closed

> **Gate status: CLOSED.**  Eleven CI jobs of eleven are green on `e1e27b0`
> (run 41289349561) and the gate is still closed, because **a green matrix is
> one of nine conditions, not the gate**.  Conditions 1 to 4 are met and CI
> proves it; conditions 5 to 9 are not, and each one is listed in §1 with the
> evidence it would need.  Nothing may be tagged, published, called a beta or
> described as supported while this line says CLOSED.

## 1. The gate

Every row is a condition.  A release needs **all** of them, and each one names
how it is checked, so that "we are nearly ready" is a sentence about a table
rather than a feeling.

| # | Condition | How it is checked | Status today |
|---|---|---|---|
| 1 | Every job of `ci.yml` green on **one** commit | run page; `tools/release_gate.py --sha <sha>` | **green** — 11 of 11 on `e1e27b0` |
| 2 | The verification matrix is current and complete | `python tools/audit_matrix.py --check --strict` (a CI step) | green |
| 3 | The generated counts are not stale | `audit_matrix.py --write`, then `git diff --exit-code` (a CI step) | green |
| 4 | The build is reproducible from the lock files | `Cargo.lock`, `requirements-dev.lock`, no Go requirements (CI steps) | green |
| 5 | **Each platform's binary has run on its own platform** | a recorded run: Windows on Windows, Android on a device or an emulator, macOS on a mac | **NOT VERIFIED** — see §4 |
| 6 | **The Android implant has tests** | `testDebugUnitTest` must not report `NO-SOURCE` | **NOT VERIFIED** — there is no test source set |
| 7 | **The three implants speak the same protocol**, conformance-tested | a synthetic harness: fixed messages, schema checks, truncated length, missing field, version mismatch — no real command execution | **NOT VERIFIED** |
| 8 | **The persist and transport findings are closed** | `persist.rs` durable write and file modes, the transport's malformed-input cases | **NOT VERIFIED** — findings 19 and 20 |
| 9 | **The release has a changelog and signed artefacts** | `CHANGELOG.md`, `release.yml`, signed artefacts, the tag message of §3 | **NOT VERIFIED** — none of the three exists |

`tools/release_gate.py` reads this table in the two places it can read
mechanically (1 and the presence of `CHANGELOG.md`) and prints the rest as
NOT VERIFIED.  It exits **closed** unless a `release-evidence.json` in the
repository records the remaining conditions with the run ids that produced
them; a file that is absent is a condition that is not met.  A green CI run has
never been, and is not now, a release.

## 2. What a release has to carry (provenance)

Every release artefact — a tag, a tarball, a container image — states:

1. **Version** (semver, `0.x` until the gate has been open for a full cycle).
2. **Commit SHA** the artefact was built from.
3. **Build environment**: the CI runner image and the run id, or, for anything
   built by hand, the machine and the date.
4. **Toolchain**: the Go version (`go version`), the Rust version
   (`rustc --version`, `cargo --version`), the JDK, Gradle, AGP, Kotlin, SDK
   and NDK, and Python with the lock file's digest.
5. **Dependencies**: the lock files by digest (`Cargo.lock`,
   `requirements-dev.lock`; the Go modules have none, by design).
6. **Tests**: the CI run id whose jobs were green, and the local commands of
   [`BUILD-EVIDENCE.md`](BUILD-EVIDENCE.md) for whatever CI does not cover.
7. **Changelog**: `CHANGELOG.md`, one section per version, "added / changed /
   fixed / security / known issues".
8. **Known issues** at the moment of the release, by id, from
   `VERIFICATION-MATRIX.md`.
9. **Platforms**: the list is "what was executed", not "what was written" —
   Linux/amd64 for the server; whatever `BUILD-EVIDENCE.md` says for the
   beacons, per release.
10. **Rollback**: the previous version's tag, the data-file compatibility
    (snapshot schema version; the server refuses a file written by a newer
    schema), and the one-command restore in
    [`BACKUP-RECOVERY.md`](BACKUP-RECOVERY.md) §6.

## 3. The steps (when the gate opens)

```bash
# 0. the gate itself
gh run list --workflow=ci.yml --limit 1 --json conclusion,headSha
#    must print "success" for the commit you are about to tag

git checkout <sha>
git status --short          # empty
python3 tools/audit_matrix.py --check --strict
python3 tools/check_consistency.py

# 1. the tag, annotated, with the provenance text
git tag -a v0.x.y -F release-notes/v0.x.y.md
git push origin v0.x.y

# 2. the artefacts, from that tag, in CI (never from a dirty tree)
gh workflow run release.yml --ref v0.x.y   # not written yet: see §5

# 3. after publishing: write the run id into the release notes
```

The tag message is the provenance block of §2.  A tag without it is a name, not
a release.

## 4. What blocks the gate today

Conditions 1 to 4 are met — the matrix is green on one commit, the two matrix
audits and the lock files are CI steps.  The other five are not, so the gate is
closed for five reasons.  Each one is a thing that has to happen, not a thing
that has to be written down:

* **No platform of the beacons has executed anything** (condition 5).  The Rust
  beacon runs its own tests on linux; the Windows target compiles and links
  (`e1e27b0`) and has never been started; the Android APK has never been
  installed; the macOS targets have never been linked, let alone run.
* **The Android implant has no tests** (condition 6).  `testDebugUnitTest`
  reports `NO-SOURCE`.  Lint is not a test: it cannot tell whether the right
  database is read, only that a permission call is written in a shape it
  accepts.
* **The three implants have never been shown to speak the same protocol**
  (condition 7).  The Go and Python beacons talk to the real server; the Rust
  and the Android ones have only their own tests.  The evidence that closes
  this is a synthetic harness — fixed messages, schema checks, a truncated
  length, a missing field, a version mismatch — and it deliberately does not
  run a task.
* **The hardening findings are open** (condition 8): the state file of
  `persist.rs` is written with `rename` but not `fsync`, and no file mode of
  the implant is set (`0o600` appears nowhere); the transport's malformed
  `Content-Length`, the `content_length.ok()` fallback and the wasm step budget
  are untested.
* **There is no provenance** (condition 9): `CHANGELOG.md`, `release.yml` and a
  signed artefact do not exist.  A changelog is one half of that condition, and
  it is what the previous version of this page mistook for the whole gate.

Two things are closed and stay closed, for the record:

* the Rust beacon compiles with `--locked`, passes 125 unit and 8 vector tests
  on both feature sets and starts as a release binary (`93b679c`), and it
  compiles and links for `x86_64-pc-windows-gnu` (`e1e27b0`);
* the Android app assembles a debug APK for three ABIs (`1aac1a9`), 27 Kotlin
  errors closed in nine rounds, and `lintDebug` is green on `e1e27b0` after 22
  lint errors were closed one finding at a time.

The honest description of this repository today is *a Go server and a Python
console that have been executed against each other, three beacons that all
compile, an Android app that also passes lint, and nothing outside the Go and
Python pair that has ever been run.*

## 5. Not written yet

* `release.yml` — the workflow that would build the artefacts from a tag and
  attach them to a GitHub release.  Writing it before the gate opens would be
  a promise the repository cannot keep.
* A signed artefact and a published digest.  A release without a signature is
  a release you have to trust the host for.
* A rollback drill: the previous version's snapshot has to be read by the new
  binary — the schema check makes a *downgrade* explicit, but nobody has run
  the drill.  It is listed as **Not Verified** in the matrix.
