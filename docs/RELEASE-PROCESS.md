# Release process, and the gate that is closed

> **Gate status: CLOSED.**  A release is a commit on which every job of
> `.github/workflows/ci.yml` is green.  No such commit exists yet: the Rust and
> Android jobs are red on every run since the workflow started reporting.
> Nothing may be tagged, published, called a beta or described as supported
> while this line says CLOSED.

## 1. The gate

| Condition | Where it is checked | Status today |
|---|---|---|
| Every CI job green on **one** commit | `ci.yml` run page; `gh run list --workflow=ci.yml` | **red** — `rust`, `rust-macos`, `android` |
| The verification matrix is current | `python tools/audit_matrix.py --check --strict` (also a CI step) | green |
| The generated counts are not stale | `audit_matrix.py --write` then `git diff --exit-code` (CI step) | green |
| No unexpected dependency | `test ! -s go.sum`, `cargo metadata --locked`, `--require-hashes` | green |
| The build is reproducible from the lock files | `Cargo.lock`, `requirements-dev.lock`, no Go requirements | green |
| The changelog names what changed | `CHANGELOG.md` | **missing** |
| Known issues are written down | `KNOWN-LIMITATIONS.md`, `VERIFICATION-MATRIX.md` | green |

A local run is not a CI run.  The table above is the only place a release is
declared, and it is declared by the jobs, not by a person.

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

* `rust beacon` and `rust beacon (--features chacha)`: 36 compile errors.
* `rust beacon (the macOS target compiles)`: the same errors, plus the
  macOS-only code paths.
* `android implant (compile only)`: a Kotlin compilation error.
* `CHANGELOG.md` does not exist.

None of these is a documentation problem; they are the code not building.  The
honest description of this repository today is *a verified Go server and Python
console, with two beacons that have never compiled*.

## 5. Not written yet

* `release.yml` — the workflow that would build the artefacts from a tag and
  attach them to a GitHub release.  Writing it before the gate opens would be
  a promise the repository cannot keep.
* A signed artefact and a published digest.  A release without a signature is
  a release you have to trust the host for.
* A rollback drill: the previous version's snapshot has to be read by the new
  binary — the schema check makes a *downgrade* explicit, but nobody has run
  the drill.  It is listed as **Not Verified** in the matrix.
