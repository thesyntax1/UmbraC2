# The transport parser: what it reads, and what it does with what it is given

> `implant/rust/src/transport.rs` and `implant/rust/src/wire.rs`, the two
> places where the Rust beacon turns bytes into decisions.  This page is the
> map Aşama 7 started from: every input the parser accepts, every way it can
> be wrong, and what the code did about each one *before* the stage and
> after.  The stage's rows are in `docs/VERIFICATION-MATRIX.md` 20 and 21.

Nothing on this page involves a socket.  Every case here is a `&[u8]` handed
to a function and the answer it produced -- the tests use `Cursor`, and a
`Cursor` cannot reach a network.

## 1. The two parsers

| Parser | Where | Reads | Bound |
|---|---|---|---|
| the frame prelude | `wire.rs:118` `parse_prelude` | 12 bytes: magic, version, flags, type, suite, reserved, length | `MAX_BODY` = 1 MiB, `MAX_FRAME` = 1 MiB + 40 B |
| the HTTP/1.1 response | `transport.rs:520` `read_http_response` | status line, headers, body (length-delimited, chunked or to-EOF) | headers 64 KiB; body **unbounded** before the stage |
| the chunk decoder | `transport.rs:610` `dechunk` | chunk sizes in hex and the chunk data | none |

`split_frames` (`wire.rs:169`) reuses `parse_prelude` over a buffer, and the
SOCKS5 reply (`transport.rs:114`) reads a length-prefixed address -- both are
covered by the same rules but neither is what this stage changed.

## 2. The frame prelude

What it does, and it was already right:

| Input | Answer |
|---|---|
| fewer than 12 bytes | `Truncated` |
| magic not `UC` | `BadMagic` |
| version not 1 | `BadVersion` |
| reserved bytes 6 and 7 not zero | `ReservedSet` |
| suite not 1 or 2 | `UnknownSuite` |
| length over `MAX_BODY` | `TooLarge` |
| a length that would overflow the frame | cannot: `length` is `u32`, `MAX_BODY` is `2^20`, and `frame_len` adds two small constants |

`read_frame` allocates `NONCE_LEN + length + TAG_LEN` only *after*
`parse_prelude` has approved the length, so a hostile `length` cannot make it
allocate.  `split_frames` checks `pos + total > buf.len()` with values that
cannot overflow.  The stage added tests for each row because none existed;
it changed none of them.

## 3. The HTTP response: the findings

Each row is a case the parser met before the stage, what it did, and what it
does now.  "old" is the behaviour on `e5e1c5c`, "new" is the behaviour on the
commit named beside it.

| # | Input | old behaviour | risk | new behaviour |
|---|---|---|---|---|
| 1 | `Content-Length: 12x` | `parse::<usize>().ok()` → `None` → **read to end of stream** | a body that was meant to be 12 bytes is silently re-framed as "everything until the peer closes", mixing the next response into this one | `InvalidData: the content length is not a number`, commit `TRANSPORT-CL` |
| 2 | `Content-Length: 0` twice, then `Content-Length: 5` | the last one wins | request/response smuggling: two parsers disagree on where the body ends | conflicting values are `InvalidData`; identical duplicates are accepted, `TRANSPORT-CL` |
| 3 | `Transfer-Encoding: chunked` **and** `Content-Length: 5` | chunked wins, the length is ignored silently | the classic desync pair: one peer frames by length, the other by chunk | `InvalidData: both a length and chunked framing`, `TRANSPORT-CL` |
| 4 | a chunk size near `usize::MAX` (`f000000000000000`) | `pos + size` overflows: panic in a debug build, wrap-then-panic in a release build | a remote peer panics the beacon with 20 bytes | `InvalidData: the chunk size overflows`, `TRANSPORT-DECHUNK` |
| 5 | chunk data with no trailing `CRLF`, or the last chunk without its terminator | `break` out of the loop and return the partial body as a success | a truncated body is reported as a complete one | `UnexpectedEof`, `TRANSPORT-DECHUNK` |
| 6 | headers that cross the 64 KiB limit | the limit is checked **after** a 4 KiB read is appended, so the buffer can reach 68 288 bytes before the error | the documented bound is not the actual one | the read is bounded before it is appended: at most 64 KiB is ever in the buffer, `TRANSPORT-LIMITS` |
| 7 | a body with neither a length nor chunked framing | read until the peer closes, into a `Vec` with no limit | a hostile or broken peer decides how much memory this process gives it | `MAX_BODY_BYTES` = 64 MiB, then `InvalidData`, `TRANSPORT-LIMITS` |
| 8 | `HTTP/1.1 200 OK` where the status line is `foo 200 bar` | accepted as status 200 | a non-HTTP speaker is treated as a server that answered | the line must start with `HTTP/1.`, `TRANSPORT-STATUS` |
| 9 | `Connection: keep-alive, close` | compared with `== "close"`, so not detected; the socket is reused after the peer said it would close it | the next request goes to a socket being closed: a failed cycle for a reason that has nothing to do with the operator | the header is split into tokens, `TRANSPORT-STATUS` |
| 10 | a header name containing a non-ASCII byte before `content-length` | `from_utf8_lossy` replaces the byte, so the prefix does not match and the header is ignored | none: the replacement is not `:`-compatible, so it cannot smuggle a length | unchanged; now pinned by a test |

## 4. What is *not* parsed, deliberately

* **The request.**  The beacon writes its own request; the response is the
  only input in this file.
* **`obs-fold` continuation lines.**  A header line that does not contain a
  `:` is ignored, which is what the RFC says to do with a malformed one in a
  message this code only reads three headers from.
* **Header order, duplicates of other fields.**  Only the three fields the
  transport acts on are read.
* **The body's content.**  It is a sequence of umbra frames, and the frame
  parser in `wire.rs` is what validates it.  A body that survives §3 intact
  is handed to `wire::split_frames`, and that is where its frames are
  checked.

## 5. The wasm budgets

`wasm.rs` runs a module with four limits and had a test for none of them
before this stage:

| Limit | Value | Enforced at | Tested |
|---|---|---|---|
| `MAX_STEPS` | 2 000 000 | every instruction | before: no.  now: yes |
| `MAX_DEPTH` | 32 | every call | before: no.  now: yes |
| `MAX_PAGES` | 16 (1 MiB) | the memory section and `memory.grow` | before: no.  now: yes |
| `MAX_LOCALS` | 1024 | every function body | before: no.  now: yes |
| wall clock | none | -- | the step budget is not a time budget: one instruction can copy a whole page, and 2 000 000 of those is not two seconds |

The step budget bounds the *number of instructions*, and an instruction is
not a constant amount of work: `memory.fill`, `memory.copy` and the host's
`sha256` all take time proportional to a size the module chooses.  A module
inside its step budget can therefore run for an unbounded time.  The stage
adds a wall-clock deadline next to the step counter; what it does *not* do is
claim that it makes a module safe -- a module that is cut off at the deadline
has still run, and `docs/EXTENSIONS.md` is where the sandbox's actual
guarantees live.
