"""Document-level conformance: the same synthetic maps, read by this parser.

``contracts/vectors.json`` has two halves.  The ``upk`` and ``rejects``
sections pin the *value* encoding; ``documents`` pins the *documents* built
from those values -- the maps the protocol names, with the fields and types
it names.  A document can diverge while every value stays identical: a field
renamed, a string accepted where bytes are required, a missing field quietly
read as a default.

Each case says what the schema requires (``accept``/``reject``), not what one
implementation happens to do, so a test that disagrees with it is a finding.
The other sides of the same file are
``implant/rust/src/tunnel.rs`` (``parse_peer_hello``) and
``implant/android/.../Peer.kt`` (``helloFrom``).

Only static, local data is used here: no socket, no server, no task.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))

from umbra_cli import peer, upk, wire  # noqa: E402

VECTORS = json.load(open(os.path.join(ROOT, "contracts", "vectors.json"), encoding="utf-8"))


def _from_json(value):
    """The JSON spelling of a value back to the Python value."""
    if isinstance(value, dict) and set(value) == {"$bin"}:
        return bytes.fromhex(value["$bin"])
    if isinstance(value, dict):
        return {k: _from_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_json(v) for v in value]
    return value


PEER_CASES = VECTORS["documents"]["peer_hello"]


@pytest.mark.parametrize("case", PEER_CASES, ids=lambda c: c["name"])
def test_peer_hello_document_is_read_as_the_schema_says(case):
    body = _from_json(case["json"])
    if case["expect"] == "accept":
        hello = peer.PeerHello.from_map(body)
        assert hello.id == "beacon-a"
        assert len(hello.pub) == 32
        assert len(hello.nonce) == 16
    else:
        with pytest.raises(peer.PeerError):
            peer.PeerHello.from_map(body)


def test_the_peer_hello_vector_is_the_bytes_this_encoder_writes():
    """The document half and the value half have to agree.

    ``hex`` is produced by the reference encoder, so this also proves the
    vector itself was not hand-edited into something no encoder emits.
    """
    for case in PEER_CASES:
        body = _from_json(case["json"])
        assert upk.encode(body).hex() == case["hex"], case["name"]
        assert upk.encode(upk.decode_exact(bytes.fromhex(case["hex"]))).hex() == case["hex"]


@pytest.mark.parametrize("name", ["result", "result_error"])
def test_the_result_document_is_the_shared_one(name):
    """The RESULT map both implants write, read the way the server reads it."""
    case = VECTORS["documents"][name]
    body = _from_json(case["json"])
    assert upk.encode(body).hex() == case["hex"]
    decoded = wire.decode_body(bytes.fromhex(case["hex"]))
    assert decoded == body
    assert decoded["id"] == case["task_id"]
    assert isinstance(decoded["code"], int)
    assert isinstance(decoded["out"], bytes)
    assert isinstance(decoded["err"], str)


def test_a_body_that_is_not_a_map_is_refused():
    """The reference rejects a non-map body instead of reading it as empty.

    This is the rule the two implants have to match: ``TASK_BATCH`` whose body
    is an array is a broken message, not a batch with no tasks.
    """
    encoded = upk.encode([1, 2, 3])
    with pytest.raises(ValueError):
        wire.decode_body(encoded)


def test_the_peer_frame_limit_is_the_shared_one():
    """The handshake messages travel with a 4 byte length prefix and a cap.

    Python and Kotlin cap them at 4096; Rust caps them at 1 MiB, which is a
    divergence recorded in ``docs/SCHEMA-CONFORMANCE.md`` and not something
    this test can decide on its own -- so it pins this side only.
    """
    assert peer.MAX_PEER_FRAME == 4096


def test_the_batch_vectors_are_the_bytes_this_encoder_writes():
    """Python encodes a ``TASK_BATCH`` but does not read one.

    The console is the sender: it hands the kind and the arguments to the
    server as JSON, and the server builds the document.  So the batch is a
    two-language contract (Rust and Kotlin read it) and this test can only
    prove that the bytes in the vectors are the bytes the reference encoder
    produces -- which is the half Python owns.
    """
    for case in VECTORS["documents"]["batch_policy"]:
        body = _from_json(case["json"])
        assert upk.encode(body).hex() == case["hex"], case["name"]
        assert upk.decode_exact(bytes.fromhex(case["hex"])) == body


def test_a_batch_vector_is_a_map_and_the_other_is_not():
    # The reader's rule is "a batch body is a map"; the vector that exercises
    # the refusal has to actually not be one, or the test would prove nothing.
    for case in VECTORS["documents"]["batch_policy"]:
        assert isinstance(upk.decode_exact(bytes.fromhex(case["hex"])), dict), case["name"]
    not_a_map = VECTORS["documents"]["batch_not_a_map"]
    assert not isinstance(upk.decode_exact(bytes.fromhex(not_a_map["hex"])), dict)
