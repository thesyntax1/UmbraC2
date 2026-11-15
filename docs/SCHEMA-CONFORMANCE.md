# Schema conformance: the same document in three languages

Stage 8 asks one question, and this file is the answer to it in prose:

> Is the same fixed, synthetic message read with the same schema and the same
> meaning by the Rust, Android (Kotlin) and Python components?

It is **not** an operational test.  Nothing here opens a socket, contacts a
server, takes a task or runs a command.  Every input is a constant in
`contracts/vectors.json`; every reader is the production parser of the
component, called directly, in a unit test.

Three layers are involved, and they fail differently:

| Layer | What it is | Where it lives |
|---|---|---|
| value | `upk`: the canonical TLV encoding of a value | `operator/umbra_cli/upk.py`, `implant/rust/src/upk.rs`, `implant/android/.../Upk.kt` |
| frame | the 12 byte prelude in front of every sealed frame | `operator/umbra_cli/wire.py`, `implant/rust/src/wire.rs`, `implant/android/.../Wire.kt` |
| document | a map the protocol names (`peer hello`, `RESULT`, `TASK_BATCH`) | `peer.py` / `tunnel.rs` / `Peer.kt`, `task.rs` / `TaskRunner.kt`, `beacon.rs` / `Beacon.kt` |

A value can be identical in all three and a *document* still diverge -- a
field renamed, a string accepted where bytes are required, a missing field
read as a default.  That is why the stage tests documents and not only bytes.

---

## 1. The map

### 1.1 Value layer (`upk`)

Identical tables in all three, checked statically by
`tools/check_consistency.py` (`UPK_MAX_DEPTH`, `UPK_MAX_ITEMS`,
`UPK_MAX_STRING`, `UPK_MAX_TOTAL`, the tag bytes) and by the shared vectors.

| Rule | Python | Rust | Kotlin |
|---|---|---|---|
| tags `0x00`–`0x09` | `upk.py:49-58` | `upk.rs` (`T_*`) | `Upk.kt:38-47` |
| minimal uvarint | `upk.py:238-251` | `upk.rs:306-330` | `Upk.kt:186-205` |
| map keys strictly ascending, UTF-8 | `upk.py:299-310` | `upk.rs:405-420` | `Upk.kt:247-268` |
| depth = containers, ≤ 16 | `upk.py:141` `_enter` | `upk.rs:373` | `Upk.kt:243` |
| `uint` above `i64::MAX` | accepted (`int`) | accepted (`Uint`) | **refused** (`Upk.kt:216`) |

### 1.2 Frame layer (prelude)

`magic 0x55 0x43`, `version 1`, `flags`, `type`, `suite`, two reserved bytes
that must be zero, a 4 byte big-endian body length, `MAX_BODY = 1 MiB`.
Python `wire.py:198-230`, Rust `wire.rs:parse_prelude`, Kotlin
`Wire.kt:parseHeader`.  All three reject bad magic, a bad version, a set
reserved byte, an unknown suite and an oversized body, **in that order**; the
Kotlin port is the one that had no test proving it.

### 1.3 Document layer

| Document | Produced by | Read by | Vector section |
|---|---|---|---|
| peer hello / ack `{id, pub, nonce, mac}` | all three | all three | `documents.peer_hello` |
| `RESULT` `{id, code, out, err}` | Rust `task::Outcome::to_value`, Kotlin `TaskRunner.Outcome.toValue` | Go server, Python console | `documents.result`, `documents.result_error` |
| `TASK_BATCH` `{tasks[], sleep, jitter, obf, route}` | Go server | Rust `beacon.rs:779-810`, Kotlin `Beacon.kt:516-545` | documented below; **Python does not read it** |

Python's role needs stating plainly: the operator console speaks JSON to the
server and reads `RESULT` documents as JSON records the server has already
decoded.  The binary `TASK_BATCH` document has **no Python reader**; the
three-language statement holds for the peer handshake and for every document
the console does read.  Where a row below lists only two languages, that is
the reason, not an omission.

---

## 2. What was found

Ten findings.  "Old behaviour" is what `25def19` does, read from the code and
confirmed by the tests in this stage.  The last column is the state at this
commit: findings 2–9 are **open** here and each is closed by its own commit,
which also moves its case into the vectors; a row that still says *open* at
the end of the stage is a row the stage did not close.

| # | Surface | Old behaviour | Risk | New behaviour |
|---|---|---|---|---|
| 1 | Kotlin conformance tests | none existed: `implant/android/app/src/test` was absent, and CI ran `assembleDebug` only | the port that ships on a phone was the only implementation whose vectors were never executed; a divergent decoder would have been invisible | `VectorsTest` + `DocumentTest` read the same `contracts/vectors.json` on the JVM (this commit) |
| 2 | peer hello `pub`/`nonce`/`mac` given as a **string** | Rust `as_bin` (`upk.rs:44`) and Kotlin `bytes()` (`Upk.kt:297`) accept `Str`, so a 32-character string is a 32-byte key; Python `PeerHello.from_map` (`peer.py:70`) does `bytes(pub)` on it and raises `TypeError` | a peer that sends text where bytes are required authenticates in both implants and *crashes* the reference instead of being refused | **fixed** in `PEER-TYPES`: all three require `bin` for `pub`/`nonce`/`mac` and `str` for `id`, and refuse the rest with the protocol error.  Vectors `pub-as-text`, `id-a-number`, `empty-id`; tests `test_peer_hello_document_is_read_as_the_schema_says` (Python), `every_peer_hello_vector_is_read_as_the_schema_says` (Rust), `everyPeerHelloVectorIsReadAsTheSchemaSays` (Kotlin) |
| 3 | peer hello `mac` of the wrong length | Rust never checks the length; the MAC comparison (`tunnel.rs`, `ct_eq`) fails for a different length, so the answer is "authentication failed" rather than "malformed" | a malformed document is reported as an authentication problem, which is the wrong thing to investigate | **fixed** in `PEER-TYPES`: a 31-byte or missing tag is `malformed peer hello`, not `authentication failed` (Rust now checks the length it never checked).  Vectors `short-mac`, `no-mac`; the same three tests |
| 4 | peer hello `id` of the wrong type | Python `str(body.get("id",""))` turns `5` into `"5"` and `None` into `"None"`, so a numeric id becomes a non-empty identity; Rust and Kotlin default to `""` and refuse | three implementations disagree on whether a document is valid, decided by a coercion | **fixed** in `PEER-TYPES`: `5` is not `"5"` and `None` is not `"None"`; the id must be a `str` and non-empty.  Vector `id-a-number`, `empty-id`; the same three tests |
| 5 | peer handshake frame length | Rust `tunnel.rs:705` accepts up to 1 MiB; Python `peer.py:48` and Kotlin `Peer.kt:35` cap at 4096 | the same frame is legal on one side of a link and illegal on the other | **fixed** in `PEER-FRAME-LIMIT`: Rust reads and writes at most 4096, the number `peer.py:48` and `Peer.kt:35` already used.  Tests `a_peer_frame_is_bounded_on_both_sides_of_the_link` and `the_peer_frame_limit_is_the_shared_one` |
| 6 | a message body that is not a map | Python `wire.decode_body` (`wire.py:240`) refuses; both implants read fields off the value and get defaults, so `TASK_BATCH` as an array is an *empty batch* | a broken message is silently a valid empty one -- the failure mode this project exists to remove | **fixed** in `BATCH-RULES`: `task_batch`/`taskBatch` refuse it before any field is read.  Vector `batch_not_a_map`; tests `a_batch_that_is_not_a_map_is_refused` (Rust), `aBatchThatIsNotAMapIsRefused` (Kotlin) |
| 7 | `TASK_BATCH.sleep` of 0 or above 86400 | Rust applies any `sleep > 0`, so `sleep: 90000` makes the beacon nap for 25 hours; Kotlin clamps to `[1, 86400]`, so `sleep: 0` becomes 1 second | the same document produces two different cadences, and one of them is outside the protocol | **fixed** in `BATCH-RULES`: `policy_from`/`policyFrom` accept 1..86400 and ignore anything else on both sides.  Vectors `sleep-zero`, `sleep-too-large`, `upper-boundaries`; tests `the_batch_cadence_is_read_as_the_schema_says` (Rust), `theBatchCadenceIsReadAsTheSchemaSays` (Kotlin) |
| 8 | `TASK_BATCH.jitter` above 90 | Rust ignores it; Kotlin clamps to 90 | same document, two cadences | **fixed** in `BATCH-RULES`: same rule, 0..90.  Vector `jitter-too-large`; the same two tests |
| 9 | `TASK_BATCH.jitter` above `u32::MAX` | Rust `batch.u64_or("jitter", …) as u32` truncates: `2^32 + 5` becomes `5` and is accepted | a value the protocol cannot express becomes a valid one by wrapping | **fixed** in `BATCH-RULES`: the range is checked while the number is still a `u64`, so `2^32 + 5` is out of range and ignored instead of becoming 5.  Vector `jitter-wraps-u32`; the same two tests |
| 10 | `upk` value `2^64 − 1` | Kotlin `Upk.kt:216` refuses `uint out of range`; Python and Rust decode and re-encode it | a value the reference produces cannot be decoded by the Android beacon | **open** -- see §4 |
| 11 | suite 2 (ChaCha20-Poly1305) | the Kotlin prelude parser (`Wire.kt:parseHeader`) refuses it: the port defines only `SUITE_AES256_GCM`, and `tools/check_consistency.py` has no Kotlin constant for suite 2 (`"kotlin": None`) | a server that negotiates ChaCha cannot talk to an Android beacon at all; the shared frame vectors contain one such frame, which the Android test now asserts is *refused* rather than skipped | **open by design** -- see §4 |

### 2.1 What is already conformant, and now proven

Not everything found is a defect.  These hold in all three implementations on
`25def19` and are now pinned rather than trusted:

* the 20 `upk` vectors encode to the same bytes and decode back to
  themselves, and the 11 `upk_*` reject vectors are refused;
* the prelude of every **suite 1** frame vector parses to the same `{type,
  suite, length}`; bad magic, a set reserved byte, an unknown suite and an
  oversized body are refused.  The one suite 2 vector is a documented
  divergence, not an agreement (finding 11);
* a peer hello with a short `pub` or a long `nonce` is refused by all three;
* an unknown field in a document is **ignored on read** and **dropped on
  re-encode** -- the beacon never re-encodes a document it received, and the
  test says so;
* a `RESULT` document is byte-identical between the Rust and Kotlin implants:
  the same outcome produces the same map, keys sorted, `code` an integer,
  `out` bytes, `err` a string.

---

## 3. The vectors

`contracts/vectors.json`, section `documents`, generated by
`tools/gen_vectors.py` (the file is regenerated in CI and diffed, so it cannot
drift from the encoder):

| Case | What it is | Expectation |
|---|---|---|
| `peer_hello/valid` | 32-byte key, 16-byte nonce, 32-byte tag | accept |
| `peer_hello/short-pub` | `pub` is 31 bytes | reject |
| `peer_hello/long-nonce` | `nonce` is 17 bytes | reject |
| `peer_hello/extra-field` | a field this build does not know | accept, ignored |
| `result` | `{id: t-1, code: 0, out: "hi", err: ""}` | exact bytes |
| `result_error` | `{id: t-2, code: 125, err: "cancelled…"}` | exact bytes |

Each case carries the canonical `hex` as well as the JSON, because the two
halves can disagree: a vector whose hex is not what the encoder produces
would be a hand-edited fixture, and the Python test asserts they match.

---

## 4. What is still open

1. **`uint` above `i64::MAX` (finding 10).**  `Upk.Num` holds a `Long`, so the
   Android decoder refuses `2^64 − 1` while the reference decodes it.  The
   refusal is loud and it is pinned by a test, but it is a divergence from
   `docs/PROTOCOL.md` §3 ("uvarint, < 2⁶⁴").  Closing it means a value type
   that can hold an unsigned 64-bit number, which touches every `when` over
   the sealed class; that is a change with its own risk and it is not made
   here.  **Not verified:** no real message is known to carry such a value --
   the claim that the protocol "never needs one" is the Kotlin comment's
   assertion, not a measurement of the server's code.
2. **`TASK_BATCH` has no Python reader**, so the batch document is a two
   language contract.  The Rust and Kotlin fixes for findings 6–9 are tested
   against each other and against the doc table, not against Python.
3. **`route` and the task `args` map** are only sketched: both implants read
   them with the same defaults, but there is no vector for a malformed route
   or a non-map `args` yet.  Finding 6 covers the shape; the fields inside are
   not pinned.
4. **No mutation testing and no fuzzing.**  The documents are read by
   hand-written parsers; a generator that flips bytes would find cases these
   tables do not name.  Not run.
5. **macOS and Windows runtime**: the Rust changes are compiled for both in
   CI, and executed only on Linux.  The Kotlin tests run on the JVM on Linux,
   which is not Android.  Both are compile-level evidence on those platforms.
6. **Suite 2 on Android (finding 11).**  The port speaks AES-256-GCM only.
   Adding ChaCha20-Poly1305 to the Android build is a feature, not a
   conformance fix -- it needs a provider the platform does not promise -- and
   the feature freeze is in force.  The consequence is operational and worth
   saying plainly: an Android beacon must be served by a server configured
   for suite 1, and nothing in this stage proves what happens if one is not.
