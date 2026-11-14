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

### 3.1 What fixes each finding, and what proves it

Every commit below is on `arena/af25ce6b-umbrac2` with its own CI run (all
eleven jobs).  Test names are the ones in `transport.rs`; each can be run
alone with `cargo test --locked <name>`.

| # | Fix | Tests that pin it |
|---|---|---|
| 1 | `db02163` | `a_length_that_is_not_a_number_is_refused` |
| 2 | `db02163`, plus the pinning test from `9eb703a` | `two_lengths_that_disagree_are_refused`, `a_length_that_does_not_fit_is_refused`, `two_identical_lengths_are_one_answer` |
| 3 | `db02163` | `chunked_framing_next_to_a_length_is_refused` |
| 4 | `528e851` | `a_chunk_size_that_overflows_is_refused_and_not_a_panic` |
| 5 | `528e851` | `a_chunk_without_its_trailing_crlf_is_refused`, `a_chunk_followed_by_the_wrong_bytes_is_refused`, `a_chunked_body_without_its_terminator_is_refused`, `an_empty_chunked_body_is_refused` |
| 6 | `5f92590`, plus `a_header_block_over_the_limit_is_refused` from `9eb703a` | `a_header_block_of_exactly_the_limit_is_accepted`, `a_header_block_one_byte_past_the_limit_is_refused` |
| 7 | `5f92590` | `an_announced_body_over_the_limit_is_refused_before_it_is_read`, `a_body_of_exactly_the_limit_is_accepted`, `a_body_one_byte_past_the_limit_is_refused`, `a_body_with_no_length_and_no_end_stops_at_the_limit` |
| 8 | `f01d1af` | `a_status_line_that_does_not_say_http_is_refused`, `a_version_this_parser_does_not_speak_is_refused`, `a_status_line_without_a_number_is_refused` |
| 9 | `f01d1af` | `a_close_token_in_a_list_is_seen`, `a_keep_alive_token_is_reusable` |
| 10 | `9eb703a` | `a_header_name_with_a_high_byte_cannot_smuggle_a_length` |

The other side of a hardening pass is that legal input keeps working, so
these tests were added in `9eb703a` and are unchanged since -- if a fix
above had narrowed the parser too far, one of these would fail:

| Legal input | Test |
|---|---|
| a chunk extension (`4;name=value`) | `a_chunk_extension_is_ignored_and_the_data_kept` |
| the terminating zero chunk alone | `the_terminator_alone_is_an_empty_body` |
| a chunked response that may not be reused | `chunked_response_is_not_reusable` |
| a `Content-Length` response that may | `length_delimited_response_is_keep_alive` |
| `Connection: close` at the end of a list | `a_close_token_in_a_list_is_seen` |
| a body **longer** than its `Content-Length` (the extra bytes are the next message) | `a_body_longer_than_its_length_is_cut_to_the_length` |

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
| wall clock | 5 s per run (`RUN_BUDGET`) | every 1024 instructions | before: the limit did not exist.  now: yes -- a zero budget is refused deterministically, and a finite module under a 60 s budget still runs |

The step budget bounds the *number of instructions*, and an instruction is
not a constant amount of work: `memory.fill`, `memory.copy` and the host's
`sha256` all take time proportional to a size the module chooses.  A module
inside its step budget could therefore run for an unbounded time.  `c1312c9`
adds a deadline next to the step counter, checked every 1024 instructions so
that the check is not itself the cost.

The tests, by limit:

| Limit | Refused side | Accepted side |
|---|---|---|
| `MAX_STEPS` | `a_module_that_never_stops_is_stopped` | every other test in the module |
| `MAX_DEPTH` | `a_module_that_calls_itself_is_stopped_at_the_depth_limit` | `the_arguments_are_taken_from_the_manifest` |
| `MAX_PAGES` | `a_module_may_ask_for_the_largest_memory_and_not_one_page_more` (17) | the same test (16) |
| `MAX_LOCALS` | `a_function_may_declare_the_largest_number_of_locals_and_not_one_more` (1025) | the same test (1024) |
| wall clock | `a_run_with_no_time_left_is_stopped_by_the_clock` (zero budget) | `a_finite_module_is_not_stopped_by_a_budget_it_does_not_use` |

What the tests prove, and what they do not:

* the step, depth, page and locals limits each have a test on the refused
  side, and the page and locals limits also have one on the accepted side
  (`16` pages and `1024` locals must parse, `17` and `1025` must not);
* the clock is tested with a **zero** budget, which has already expired when
  the first check runs.  That is deterministic and runner-independent.  It
  proves the check exists and fires; it does not measure five seconds;
* **five seconds is a policy choice, not a measurement.**  Whether a
  legitimate task can exceed it is NOT VERIFIED -- no real module has been
  run against it, because this stage does not run tasks.

`memory.grow` is checked against `MAX_PAGES` at `wasm.rs:887`, and there is
**no test for that path**: the page test above covers the memory section only.
That gap is listed in the stage report rather than papered over.

What none of this does is claim a module is safe.  A module that is cut off
at a deadline has still run for five seconds, and `docs/EXTENSIONS.md` is
where the sandbox's actual guarantees live.
