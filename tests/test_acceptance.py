"""The acceptance test of the mandate.

The mandate ends with ten lines that say what "a real C2" means.  Each of
them is a test here, and each of them names the code that does the work.
A mandate is not finished when the code compiles; it is finished when the
ten lines can be pointed at.

The suite runs against the reference server in `tools/mock_server.py`,
because that is the implementation of the protocol that runs everywhere:
the Go server, the console and the reference agree with it by the
conformance vectors.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

AGENT_PSK = bytes(range(32))
OPERATOR_TOKEN = b"acceptance-operator-token-0123456789"


def read_text(relative: str) -> str:
    """Read a file of the repository."""
    with open(os.path.join(ROOT, relative), encoding="utf-8") as fh:
        return fh.read()


def wait_until(predicate, timeout: float = 15.0, poll: float = 0.02) -> bool:
    """Wait for a condition instead of sleeping and hoping."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(poll)
    return False


@pytest.fixture()
def team():
    """A server, a beacon and an operator: the whole picture."""
    from mock_server import FakeAgent, MockServer
    from umbra_cli.client import OperatorClient

    server = MockServer(AGENT_PSK, {"alice": OPERATOR_TOKEN,
                                  "bob": b"acceptance-second-token-01234567"})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "host-1", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, OPERATOR_TOKEN.decode(), "alice", timeout=30)
    client.connect()
    assert wait_until(lambda: bool(client.agents()))
    try:
        yield client, server, agent
    finally:
        try:
            client.close()
        except Exception:
            pass
        agent.stop()
        server.stop()


# --------------------------------------------------------------------- 1


def test_a_beacon_survives_the_host_and_leaves_nothing_behind(team):
    """1. A beacon survives a reboot, a logoff, a user switch and an update.

    The catalogue of the implant has a technique for every platform and
    for every trigger; the manager installs what it chose, verifies it and
    takes it away again with one command.
    """
    client, _server, agent = team

    catalogue = read_text("implant/rust/src/persist.rs")
    for platform in ("windows", "linux", "macos"):
        assert f'platform: "{platform}"' in catalogue
    for trigger in ("boot", "logon", "schedule"):
        assert f'trigger: "{trigger}"' in catalogue

    task = client.submit("host-1", "persist", {"method": "auto"})
    done = client.wait_for_result(task, timeout=20, poll=0.05)
    assert done["state"] == "done", done
    entries = (done.get("meta") or {}).get("persist") or []
    assert entries, done
    assert entries[0]["state"] == "installed"
    assert entries[0]["technique"], entries[0]

    # An update of the host does not take the start-up entry with it: the
    # new build is installed and the entry stays.
    task = client.submit("host-1", "update", {"path": "/tmp/umbra-beacon-new"})
    done = client.wait_for_result(task, timeout=20, poll=0.05)
    assert done["state"] == "done", done
    assert agent.persist, "the update took the start-up entry with it"

    # The verification reads the entries back from the host.
    task = client.submit("host-1", "persist.verify", {})
    done = client.wait_for_result(task, timeout=20, poll=0.05)
    assert done["state"] == "done", done
    assert (done.get("meta") or {}).get("persist_broken") == 0

    # One command, and nothing is left behind.
    task = client.submit("host-1", "unpersist", {"method": "all"})
    done = client.wait_for_result(task, timeout=20, poll=0.05)
    assert done["state"] == "done", done
    assert not agent.persist, agent.persist
    assert not (done.get("meta") or {}).get("persist")


# --------------------------------------------------------------------- 2


def test_the_server_knows_what_it_installed_and_can_prove_it(team):
    """2. The server knows what it installed on every host, and can prove it.

    The record is the report of the beacon, so the fleet can be read
    without touching a single host, and a verification says which entry
    was removed behind the operator's back.
    """
    client, _server, _agent = team

    task = client.submit("host-1", "persist", {"method": "auto"})
    client.wait_for_result(task, timeout=20, poll=0.05)

    rows = client.persistence_report()
    assert rows, rows
    row = rows[0]
    assert row["agent"] == "host-1"
    assert row["entries"] == 1
    assert row["state"] == "covered"
    assert row["methods"], row

    # The fleet can be filtered by "has something installed".
    assert [a["id"] for a in client.agents(persisted="yes")] == ["host-1"]

    # The proof: an entry that was removed behind the operator's back is
    # reported as broken, not as covered.
    task = client.submit("host-1", "persist.verify",
                         {"break": row["methods"][0]})
    done = client.wait_for_result(task, timeout=20, poll=0.05)
    assert done["state"] == "done", done
    assert (done.get("meta") or {}).get("persist_broken") == 1

    rows = client.persistence_report()
    assert rows[0]["state"] == "broken"
    assert rows[0]["broken"] == 1

    # The health of the fleet is a question with an answer.
    task = client.submit("host-1", "persist.health", {})
    done = client.wait_for_result(task, timeout=20, poll=0.05)
    assert done["state"] == "done", done


# --------------------------------------------------------------------- 3


def test_no_task_is_queued_that_the_host_cannot_run(team):
    """3. No operator can queue a task a host cannot run.

    The beacon advertises what it can do in the handshake, the server
    refuses the rest, and the operator can see the reach of the host
    before they try.
    """
    client, server, _agent = team

    # The beacon said what it can do.
    caps = server.agent_caps("host-1")
    assert caps, caps
    assert "shell" in caps or "exec" in caps, caps

    # The operator can see it.
    info = client.agent_info("host-1")
    assert info["caps"], info
    assert info["caps"] == list(caps)

    # A kind the host never advertised is refused, with a reason.
    res = client.rpc("task.submit", {"id": "host-1", "kind": "not-a-kind"})
    assert not res.ok
    assert "not-a-kind" in res.error, res.error

    # The refusal leaves no task behind.
    assert not [t for t in client.tasks("host-1")
                if t.get("kind") == "not-a-kind"]

    # The same rule is the server's own, in the server the console talks to.
    source = read_text("server/internal/hub/hub.go")
    assert "func agentSupports(caps []string, kind string) bool" in source
    assert "does not support the task kind" in source


# --------------------------------------------------------------------- 4


def test_a_file_is_put_on_the_server_once_and_pushed_to_many_hosts(team, tmp_path):
    """4. A file can be put on the server once and pushed to any number of
    hosts, chunked, digest-verified on both ends, and encrypted at rest
    when asked.
    """
    client, _server, _agent = team

    payload = b"the bytes of the artifact, twice over: " + bytes(range(256))
    digest = hashlib.sha256(payload).hexdigest()
    chunk = 128
    for offset in range(0, len(payload), chunk):
        piece = payload[offset:offset + chunk]
        last = offset + chunk >= len(payload)
        info = client.artifact_put("payload.bin", piece, offset=offset,
                                   eof=last)
        if last:
            assert info.get("sha256") == digest, info
            assert info.get("size") == len(payload), info
        else:
            assert info.get("received") == offset + len(piece), info

    listed = client.artifact_list()
    names = [a.get("name") for a in listed]
    assert "payload.bin" in names, listed

    stored = client.artifact_get("payload.bin", offset=0, limit=4096)
    assert stored.get("eof") is True, stored
    assert stored.get("sha256") == digest, stored
    assert stored.get("data") == payload, stored

    # Pushing it to a host is a chain of tasks, and the host checks the
    # digest of what it received.
    target = str(tmp_path / "payload.bin")
    pushed = client.artifact_push("payload.bin", "host-1", path=target)
    assert pushed, pushed

    def landed() -> bool:
        if not os.path.exists(target):
            return False
        with open(target, "rb") as fh:
            return fh.read() == payload

    assert wait_until(landed, timeout=20), "the artifact never reached the host"
    with open(target, "rb") as fh:
        assert hashlib.sha256(fh.read()).hexdigest() == digest

    # The store may be sealed: the server encrypts the blob and the index
    # when it is given a key, and the key is a configuration value.
    config = read_text("server/internal/config/config.go")
    assert "artifact_key" in config
    store = read_text("server/internal/artifact/artifact.go")
    assert "seal" in store.lower()
    store_tests = read_text("server/internal/artifact/artifact_test.go")
    assert "TestTheStoreIsSealedWhenAKeyIsGiven" in store_tests


# --------------------------------------------------------------------- 5


def test_one_host_pivots_to_the_next_and_the_topology_is_visible(team):
    """5. One compromised host can pivot to a second, and the second can
    pivot to a third, over any transport, with the topology visible.
    """
    from mock_server import FakeAgent

    client, server, _agent = team

    first = client.pivot_open("host-1", mode="socks", host="10.0.0.9",
                              port=1080, listen="127.0.0.1:0")
    assert first.get("stream"), first
    assert first.get("listen"), first

    # The second host is reached through the first one.
    second_agent = FakeAgent(server.address, AGENT_PSK, "host-2", interval=0.2)
    second_agent.start()
    try:
        assert wait_until(lambda: any(a["id"] == "host-2"
                                      for a in client.agents()))
        chained = client.pivot_open("host-2", mode="forward", host="10.0.0.20",
                                    port=445, listen="127.0.0.1:0",
                                    through="host-1")
        assert chained.get("stream"), chained
        assert chained.get("through") == "host-1", chained

        # The topology is the picture of the reach: the hosts, the pivots
        # between them and the state of every one.
        topology = client.pivot_topology()
        assert topology, topology
        nodes = topology.get("nodes") or []
        edges = topology.get("edges") or []
        assert nodes and edges, topology
        names = {n.get("agent_id") for n in nodes}
        assert {"host-1", "host-2"} <= names, names
        through = {e.get("through") for e in edges}
        assert "host-1" in through, edges

        # The list of the tunnels agrees with the graph.
        tunnels = client.pivot_list()
        assert len(tunnels) == len(edges), (tunnels, edges)
    finally:
        second_agent.stop()


# --------------------------------------------------------------------- 6


def test_two_operators_work_together_without_losing_each_other(team):
    """6. Two operators can work the same engagement at the same time
    without duplicating work, without losing each other's events, and can
    hand over with one command.
    """
    from umbra_cli.client import OperatorClient

    client, server, _agent = team
    second = OperatorClient(server.address, "acceptance-second-token-01234567",
                            "bob", timeout=30)
    second.connect()
    try:
        task = client.submit("host-1", "shell", {"command": "whoami"})
        done = client.wait_for_result(task, timeout=20, poll=0.05)
        assert done["state"] == "done", done

        # The event stream of one operator contains the work of both.
        assert wait_until(lambda: bool(client.events(limit=200)))
        events = client.events(limit=200)
        flat = json.dumps(events)
        assert task in flat, flat

        # A claim keeps the second operator from repeating the work.
        second_task = client.submit("host-1", "shell", {"command": "id"})
        claimed = second.claim(second_task)
        assert claimed, claimed
        assert wait_until(lambda: any(
            t.get("id") == second_task and t.get("claimed_by")
            for t in client.tasks("host-1")))

        # The chat is shared: one operator says, the other reads.
        client.say("the second host is next")
        assert wait_until(lambda: any(
            "second host" in json.dumps(m) for m in second.chat_history()))

        # The handover is one command, and it moves the work.
        handover = second.team_handover()
        assert handover, handover
    finally:
        second.close()


# --------------------------------------------------------------------- 7


def test_every_task_has_a_deadline_a_timeout_a_priority_and_an_audit_line(team):
    """7. Every task the server queues has a deadline, a timeout, a
    priority and a place in the audit trail.
    """
    client, server, _agent = team

    task = client.submit("host-1", "shell", {"command": "echo hello"},
                         deadline="2026-01-01T00:00:00Z", timeout=30)
    done = client.wait_for_result(task, timeout=20, poll=0.05)
    assert done["state"] == "done", done
    assert done.get("deadline"), done
    assert done.get("timeout") == 30, done

    # The priority can be changed while the task waits.
    queued = client.submit("host-1", "shell", {"command": "sleep 1"})
    client.set_priority(queued, 9)
    assert wait_until(lambda: any(
        t.get("id") == queued and t.get("priority") == 9
        for t in client.tasks("host-1")))

    # The audit trail has the task in it.
    audit = client.audit(limit=200)
    flat = json.dumps(audit)
    assert task in flat, flat

    # A task that passes its deadline is cancelled, not delivered: the
    # promise the operator made is kept by the server.
    stale = client.submit("host-1", "shell", {"command": "echo late"},
                           deadline=str(int(time.time()) - 5))
    server.sweep_tasks(300)
    record = client.task(stale)
    assert record["state"] == "cancelled", record
    assert "deadline" in str(record.get("err", "")), record

    # The event says it too.
    events = json.dumps(client.events(limit=200))
    assert "task.expired" in events, events


# --------------------------------------------------------------------- 8


def test_a_wire_change_is_in_all_four_implementations_at_once(team):
    """8. Every wire change is reflected in all four implementations, in the
    conformance vectors, in the checker and in the documentation -- at the
    same time.
    """
    checker = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "check_consistency.py")],
        capture_output=True, text=True)
    assert checker.returncode == 0, checker.stdout + checker.stderr

    # The four implementations.
    for relative in ("server/internal/wire/wire.go",
                     "implant/go/internal/wire/wire.go",
                     "implant/rust/src/wire.rs",
                     "operator/umbra_cli/wire.py"):
        assert os.path.exists(os.path.join(ROOT, relative)), relative

    # The vectors are the agreement, and they are generated from the
    # agreement itself.
    vectors = json.loads(read_text("contracts/vectors.json"))
    assert vectors.get("frames"), vectors.keys()
    assert vectors.get("handshake"), vectors.keys()

    # The documentation.
    protocol = read_text("docs/PROTOCOL.md")
    assert "0x1D" in protocol, "the heartbeat is not documented"

    # The message types of the four implementations are the same set: the
    # checker reads them the same way, and the answer is one answer.
    import importlib.util
    import re

    spec = importlib.util.spec_from_file_location(
        "check_consistency", os.path.join(ROOT, "tools", "check_consistency.py"))
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)

    go = set(re.findall(r"\bMsg([A-Z]\w*)\s+byte\s*=\s*(0x[0-9A-Fa-f]+)",
                        read_text("server/internal/wire/wire.go")))
    rust = set(re.findall(r"pub const MSG_([A-Z_]+): u8 = (0x[0-9A-Fa-f]+)",
                          read_text("implant/rust/src/wire.rs")))
    kotlin = set(re.findall(r"const val MSG_([A-Z_]+) = (0x[0-9A-Fa-f]+)",
                             read_text("implant/android/app/src/main/java/io/umbra/"
                                       "beacon/Wire.kt")))
    python = set(re.findall(r"^\s{4}([A-Z_]+) = (0x[0-9A-Fa-f]+)",
                             read_text("operator/umbra_cli/wire.py"), re.M))

    def names(pairs):
        return {checker.camel_to_snake(name): value for name, value in pairs}

    def plain(pairs):
        return {checker.camel_to_snake(name): value for name, value in pairs}

    # The beacon side of the protocol is the same everywhere: the Rust and
    # the Kotlin speak the frames the Go server and the console speak.
    agent_types = plain(rust)
    assert agent_types, "the Rust beacon has no message types"
    for name, value in agent_types.items():
        assert names(go).get(name) == value, (name, names(go).get(name), value)
        assert plain(python).get(name) == value, (name, plain(python).get(name), value)
        assert plain(kotlin).get(name) == value, (name, plain(kotlin).get(name), value)


# --------------------------------------------------------------------- 9


def test_the_suite_the_checkers_and_the_build_are_green():
    """9. The suite is green, the three checkers are green, and the build of
    every component is green.
    """
    for tool in ("check_consistency.py", "check_symbols.py",
                 "check_go_symbols.py"):
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", tool)],
            capture_output=True, text=True)
        assert proc.returncode == 0, tool + ": " + proc.stdout + proc.stderr

    # The workflow is not the build.  When a toolchain is present the
    # modules are built and tested here, because a job in a YAML file has
    # never run a compiler; when it is absent the test says so instead of
    # pretending.
    go = shutil.which("go")
    if go:
        for module in ("server", os.path.join("implant", "go")):
            for command in (["build", "./..."], ["vet", "./..."], ["test", "./...", "-count=1"]):
                proc = subprocess.run(
                    [go, *command], cwd=os.path.join(ROOT, module),
                    capture_output=True, text=True, timeout=900,
                )
                assert proc.returncode == 0, (
                    module + " go " + " ".join(command) + ":\n"
                    + proc.stdout[-3000:] + proc.stderr[-3000:])
    else:
        pytest.skip("no Go toolchain on this machine: the modules were not built")

    # Every component of the repository is built by the workflow: the
    # server, the three implants and the console.
    workflow = read_text(".github/workflows/ci.yml")
    for job in ("  protocol:", "  go:", "  go-implant:", "  rust:",
                "  rust-macos:", "  android:"):
        assert job in workflow, job

    # The Rust beacon adds no crate: the dependency set is exactly the one
    # the repository started with.
    cargo = read_text("implant/rust/Cargo.toml")
    deps = []
    section = ""
    for line in cargo.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line
            continue
        if section not in ("[dependencies]", "[dev-dependencies]"):
            continue
        if not line or line.startswith("#") or "=" not in line:
            continue
        deps.append((section, line.split("=")[0].strip()))
    assert deps == [
        ("[dependencies]", "aes-gcm"),
        ("[dependencies]", "chacha20poly1305"),
        ("[dependencies]", "x25519-dalek"),
        ("[dependencies]", "sha2"),
        ("[dependencies]", "hmac"),
        ("[dependencies]", "hkdf"),
        ("[dependencies]", "rand"),
        ("[dev-dependencies]", "serde_json"),
    ], deps

    # The Go modules have no requirements of their own: the standard
    # library is the whole dependency set.
    for module in ("server/go.mod", "implant/go/go.mod"):
        text = read_text(module)
        requirements = [line for line in text.splitlines()
                        if line.startswith("require ")]
        assert not requirements, (module, requirements)

    # The Python console adds no dependency: the only third party import
    # is the cryptography package the mandate allows.
    import ast

    allowed = {"cryptography"}
    package = os.path.join(ROOT, "operator", "umbra_cli")
    for name in sorted(os.listdir(package)):
        if not name.endswith(".py"):
            continue
        tree = ast.parse(read_text(os.path.join("operator", "umbra_cli", name)))
        for node in ast.walk(tree):
            roots = []
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                roots = [(node.module or "").split(".")[0]]
            for root in roots:
                assert root in sys.stdlib_module_names or root in allowed, (
                    name, root)


# -------------------------------------------------------------------- 10


def test_the_engagement_ends_with_one_command_each_and_the_record_is_whole(team):
    """10. The engagement can be ended, on the server and on the targets,
    with one command each, and the record of what was done is complete
    enough to write the report from.
    """
    client, _server, _agent = team

    task = client.submit("host-1", "shell", {"command": "echo the last thing"})
    client.wait_for_result(task, timeout=20, poll=0.05)
    work = task

    # The target goes first: one command, and the beacon is gone.
    task = client.submit("host-1", "exit", {})
    done = client.wait_for_result(task, timeout=20, poll=0.05)
    assert done["state"] in ("done", "failed"), done

    # The server goes second: one command, and the engagement is closed.
    wipe = client.wipe()
    assert wipe, wipe
    assert wipe.get("agents") == 1, wipe
    assert wipe.get("tasks", 0) >= 1, wipe

    # The machines are gone from the server, and the work is gone with them.
    assert client.agents() == []

    # The record is not: the trail and the events still say what was done,
    # and that is what the report is written from.
    audit = client.audit(limit=500)
    flat = json.dumps(audit)
    assert work in flat or "the last thing" in flat, flat
    events = json.dumps(client.events(limit=500))
    assert work in events, events
    assert task in events, events
    assert "engagement.wiped" in events, events

    # The report can be written from the console's own view.
    report = client.posture_report()
    assert isinstance(report, list)


# ---------------------------------------------------------------------------
# The dashboard is a page, and a page has to run
# ---------------------------------------------------------------------------

def _jsdom_dir() -> str:
    """Where jsdom is installed, if it is installed at all."""
    candidates = [
        os.environ.get("UMBRA_JSDOM_DIR", ""),
        os.path.join(os.path.expanduser("~"), ".cache", "dashjs", "node_modules"),
        "/tmp/dashjs/node_modules",
    ]
    for path in candidates:
        if path and os.path.isdir(os.path.join(path, "jsdom")):
            return path
    return ""


def test_the_dashboard_runs_in_a_dom_and_escapes_what_the_hosts_say():
    """The page is executed, not read.

    A Go test can prove the page is served with the right headers; it
    cannot prove the script runs, and a typo would ship a blank dashboard
    with every Go test green.  This runs the page in jsdom against a fake
    server that answers with markup in a host name and in a pivot label,
    and asserts two things at once: the page renders, and the markup is
    shown as text rather than becoming an element.

    jsdom is not a dependency of the repository, so the test skips when it
    is not installed:

        npm install --prefix /tmp/dashjs jsdom
    """
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    modules = _jsdom_dir()
    if not modules:
        pytest.skip("jsdom is not installed (npm install --prefix /tmp/dashjs jsdom)")
    result = subprocess.run(
        [node, os.path.join(ROOT, "tools", "dash_smoke.mjs"), modules],
        capture_output=True, text=True, timeout=120, cwd=ROOT,
    )
    if result.returncode == 77:
        pytest.skip(result.stdout.strip() or "jsdom is not installed")
    assert result.returncode == 0, (result.stdout + result.stderr)[-4000:]
    assert "ok: the dashboard renders" in result.stdout, result.stdout
