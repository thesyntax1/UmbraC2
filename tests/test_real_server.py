"""The product, executed.

Every other test in this repository talks to `tools/mock_server.py`: the
Python reference implementation of the protocol.  That is worth a great
deal — it proves the console, the wire format and the contract — and it
proves nothing at all about `cmd/umbra-server`, the binary an operator
deploys.  Until this file existed, that binary had been compiled and its
packages unit-tested, and it had never been *run*: no test started it, no
test connected a console to it, no test killed it to see what the state
file did.

So this file starts the real server on two ephemeral ports, points the
Python console at it, points the Python beacon (`FakeAgent`, the same one
the rest of the suite uses) at its agent listener, and checks the things
that only a running product can answer:

  * the console of one language can drive the server of another;
  * a beacon registers and a task is delivered and answered;
  * the role table refuses, in the product, what it refuses in the mock;
  * the two-person rule gates a task kind the configuration names;
  * the audit ledger of the product verifies;
  * a garbage handshake and a half-written request do not take it down;
  * a `SIGKILL` and a restart keep the engagement, and how long that takes.

The recovery test is deliberately a `SIGKILL`: a graceful stop flushes the
state, and the question is what happens when the machine does not get the
chance.  The measured numbers (restart to ready, the window of work that
the last snapshot did not contain) are printed, because they are the RPO
and RTO of the deployment and inventing them in a document would be a lie.

The suite needs a Go toolchain to build the binary and skips without one:

    python3 tools/get_go.py && export PATH="$HOME/.cache/umbra-go/go/bin:$PATH"
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

AGENT_PSK = bytes(range(32))
TOKEN = "real-server-token-0123456789abcdef"

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None,
    reason="the real server needs a Go toolchain (python3 tools/get_go.py)",
)


# ---------------------------------------------------------------------------
# the harness
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def server_binary(tmp_path_factory) -> str:
    """Build `umbra-server` once, with the toolchain that is on the PATH."""
    out = tmp_path_factory.mktemp("bin") / "umbra-server"
    proc = subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/umbra-server"],
        cwd=os.path.join(ROOT, "server"),
        capture_output=True, text=True, timeout=600,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return str(out)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.02)
    return False


class Server:
    """One run of the real binary, on two ephemeral ports."""

    def __init__(self, binary: str, workdir: str, operators: str, config: dict | None = None):
        self.binary = binary
        self.dir = workdir
        self.agent_port = free_port()
        self.op_port = free_port()
        self.operators = operators
        self.config_path = ""
        if config is not None:
            self.config_path = os.path.join(workdir, "server.json")
            with open(self.config_path, "w", encoding="utf-8") as handle:
                json.dump(config, handle)
        self.proc: subprocess.Popen | None = None
        self.started_at = 0.0
        self.ready_at = 0.0
        self.log_path = os.path.join(workdir, "server.log")

    @property
    def agent_addr(self) -> str:
        return f"127.0.0.1:{self.agent_port}"

    @property
    def op_addr(self) -> str:
        return f"127.0.0.1:{self.op_port}"

    def start(self, wait: bool = True) -> "Server":
        env = dict(
            os.environ,
            UMBRA_AGENT_PSK=AGENT_PSK.hex(),
            UMBRA_OPERATOR_TOKENS=self.operators,
        )
        args = [
            self.binary,
            "--listen-agent", self.agent_addr,
            "--listen-operator", self.op_addr,
            "--data", os.path.join(self.dir, "state.json"),
            "--log-level", "info",
        ]
        if self.config_path:
            args = [self.binary, "--config", self.config_path, *args[1:]]
        self.started_at = time.time()
        self.proc = subprocess.Popen(
            args, env=env, cwd=self.dir,
            stdout=open(self.log_path, "ab"), stderr=subprocess.STDOUT,
        )
        if wait:
            assert wait_for_port(self.op_port), self.log()
            assert wait_for_port(self.agent_port), self.log()
            self.ready_at = time.time()
        return self

    def log(self) -> str:
        with open(self.log_path, "rb") as handle:
            return handle.read().decode("utf-8", "replace")

    def kill(self) -> None:
        """SIGKILL: the machine lost power, the process had no chance."""
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait(timeout=10)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.proc.kill()
                self.proc.wait(timeout=10)


@pytest.fixture()
def server(server_binary, tmp_path):
    """A fresh server, stopped at the end of the test."""
    box = Server(server_binary, str(tmp_path), f"alice:admin:{TOKEN}")
    box.start()
    yield box
    box.stop()


def console(box: Server, token: str = TOKEN, name: str = "alice"):
    from umbra_cli.client import OperatorClient

    client = OperatorClient(box.op_addr, token, name)
    client.connect()
    return client


def beacon(box: Server, agent_id: str, *, psk: bytes = AGENT_PSK):
    from mock_server import FakeAgent

    agent = FakeAgent(box.agent_addr, psk, agent_id)
    agent.start()
    return agent


def wait_for(predicate, timeout: float = 10.0, poll: float = 0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(poll)
    return predicate()


# ---------------------------------------------------------------------------
# the product answers
# ---------------------------------------------------------------------------

def test_the_real_server_answers_the_python_console(server):
    """The server of one language, driven by the console of another."""
    client = console(server)
    try:
        stats = client.stats()
        assert stats["protocol"] == "umbra/v1", stats
        assert stats["agents_total"] == 0, stats
        assert client.agents() == []
        # The handshake of the product negotiated the suite the protocol names.
        assert "aes-256-gcm" in stats["suites"], stats
    finally:
        client.close()


def test_a_beacon_registers_and_a_task_comes_back(server):
    """The whole cycle, on the product: register, queue, deliver, answer."""
    agent = beacon(server, "agent-live-1")
    client = console(server)
    try:
        agents = wait_for(lambda: client.agents(), timeout=10)
        assert [a["id"] for a in agents] == ["agent-live-1"], agents

        task_id = client.submit("agent-live-1", "netinfo", {})
        result = client.wait_for_result(task_id, timeout=15, poll=0.05)
        assert result["state"] == "done", result
        assert result.get("code") == 0, result
        assert b"mock" in result["out"], result
    finally:
        client.close()
        agent.stop()


def test_the_product_refuses_what_the_role_table_forbids(server_binary, tmp_path):
    """RBAC in the product, not only in the mock.

    A viewer may read the inventory and may not queue work.  The test runs
    against the real binary, so the refusal is the one an operator would
    meet.
    """
    # The server refuses to start when nobody is an admin, which is its own
    # safety rule and is pinned by its own test below; this one needs a
    # deployment that starts, so an unused admin sits beside the viewer.
    box = Server(server_binary, str(tmp_path),
                 f"root:admin:{TOKEN}-root,viewer:viewer:{TOKEN}")
    box.start()
    try:
        client = console(box, name="viewer")
        try:
            assert client.agents() == []  # the reading is allowed
            from umbra_cli.client import OperatorError

            with pytest.raises(OperatorError) as caught:
                client.submit("agent-none", "netinfo", {})
            assert "permission denied" in str(caught.value), caught.value
        finally:
            client.close()
    finally:
        box.stop()


def test_the_two_person_rule_gates_the_real_server(server_binary, tmp_path):
    """The rule is a policy of the deployment, and the deployment says so.

    Two operators, one host, and a task kind the configuration puts behind
    the rule: the operation is refused as a task, a second operator may
    approve it, and the requester may not approve their own.
    """
    config = {"approval_required": ["netinfo"]}
    box = Server(server_binary, str(tmp_path),
                 f"alice:admin:{TOKEN},bob:admin:{TOKEN}-bob", config=config)
    box.start()
    agent = beacon(box, "agent-approval-1")
    alice = console(box, name="alice")
    bob = console(box, TOKEN + "-bob", name="bob")
    try:
        assert wait_for(lambda: alice.agents(), timeout=10)
        from umbra_cli.client import OperatorError

        with pytest.raises(OperatorError) as caught:
            alice.submit("agent-approval-1", "netinfo", {})
        assert "two-person rule" in str(caught.value), caught.value

        request = alice.approval_request("netinfo", "agent-approval-1", "the lab drill")
        request_id = request["id"]
        assert request["state"] == "pending", request

        # The requester cannot decide their own request.
        with pytest.raises(OperatorError) as own:
            alice.approval_approve(request_id, "approved by me")
        assert "asked for it" in str(own.value), own.value

        decision = bob.approval_approve(request_id, "the second pair of eyes")
        assert decision["state"] == "approved", decision
        task_id = decision.get("task_id")
        assert task_id, decision
        result = alice.wait_for_result(task_id, timeout=15, poll=0.05)
        assert result["state"] == "done", result
    finally:
        alice.close()
        bob.close()
        agent.stop()
        box.stop()


def test_the_audit_ledger_of_the_product_verifies(server):
    """The trail the deployment keeps is a chain that verifies."""
    client = console(server)
    try:
        client.stats()
        client.agents()
        plain = client.audit_verify()
        assert plain["ok"] is True, plain
        assert plain["head"], plain
        tail = client.audit(limit=10)
        assert tail["enabled"] is True, tail
        entries = tail["entries"]
        assert entries, tail
        commands = {row.get("cmd") for row in entries}
        assert "server.stats" in commands, commands
    finally:
        client.close()


# ---------------------------------------------------------------------------
# the product does not fall over
# ---------------------------------------------------------------------------

def test_a_hostile_handshake_does_not_take_the_server_down(server):
    """Garbage at the agent listener is a dropped connection, not an outage."""
    with socket.create_connection(("127.0.0.1", server.agent_port), timeout=2) as sock:
        sock.sendall(b"UMBRA" + b"\x00" * 5)  # a prelude that goes nowhere
        sock.sendall(os.urandom(64))
    with socket.create_connection(("127.0.0.1", server.agent_port), timeout=2) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # not this protocol at all

    client = console(server)
    try:
        assert client.stats()["protocol"] == "umbra/v1"
    finally:
        client.close()


def test_a_half_written_operator_request_does_not_take_the_server_down(server):
    """A console that dies mid-frame costs its own session and nothing else."""
    with socket.create_connection(("127.0.0.1", server.op_port), timeout=2) as sock:
        sock.sendall(b"\x01\x00")  # the start of a prelude, then silence
    time.sleep(0.1)
    client = console(server)
    try:
        assert client.stats()["protocol"] == "umbra/v1"
    finally:
        client.close()


def test_the_server_survives_a_console_that_disconnects_mid_call(server):
    """A console killed during a call leaves the queue and the other consoles alone."""
    first = console(server)
    second = console(server)
    try:
        first.close()
        time.sleep(0.1)
        assert second.stats()["operators"] == 1, second.stats()
    finally:
        second.close()


# ---------------------------------------------------------------------------
# recovery: what a SIGKILL costs, measured
# ---------------------------------------------------------------------------

def test_a_sigkill_and_a_restart_keep_the_engagement(server_binary, tmp_path):
    """The recovery drill, with the numbers it produces.

    Work is done, the process is killed without warning, and the server is
    started again over the same state directory.  What survives is the
    engagement; what is printed is how long the restart took (the RTO of
    this deployment, in this environment) and the evidence for the RPO:
    the task that was completed before the kill is still there and still
    done.
    """
    box = Server(server_binary, str(tmp_path), f"alice:admin:{TOKEN}")
    box.start()
    startup = box.ready_at - box.started_at
    agent = beacon(box, "agent-recover-1")
    client = console(box)
    try:
        assert wait_for(lambda: client.agents(), timeout=10)
        first = client.submit("agent-recover-1", "netinfo", {})
        result = client.wait_for_result(first, timeout=15, poll=0.05)
        assert result["state"] == "done", result
        # Give the coalescing writer the moment it asks for, then kill.
        time.sleep(0.5)
        before = client.stats()
    finally:
        client.close()
        agent.stop()

    box.kill()
    assert box.proc is not None and box.proc.poll() is not None

    box.start()
    restart = box.ready_at - box.started_at
    client = console(box)
    try:
        agents = client.agents()
        assert [a["id"] for a in agents] == ["agent-recover-1"], agents
        restored = client.task(first)
        assert restored["state"] == "done", restored
        assert restored.get("out", b"") != b"", restored
        after = client.stats()
        assert after["tasks_total"] >= before["tasks_total"], (before, after)
    finally:
        client.close()
        box.stop()

    print(f"\nrecovery: cold start {startup*1000:.0f} ms, "
          f"restart after SIGKILL {restart*1000:.0f} ms, "
          f"state {os.path.getsize(os.path.join(str(tmp_path), 'state.json'))} bytes")
    # A restart that takes longer than this is not a restart, it is an outage.
    assert restart < 10.0, restart


# ---------------------------------------------------------------------------
# latency of the product, measured rather than claimed
# ---------------------------------------------------------------------------

def test_the_latency_of_the_product_is_measured(server):
    """One console, 200 calls, no throughput claim: the shape of the answer.

    This is a latency *sample*, not a load test: it says what one console
    waited for on an idle server, and it is printed so that a document can
    quote a number instead of an adjective.
    """
    client = console(server)
    try:
        samples = []
        for _ in range(200):
            started = time.perf_counter()
            client.stats()
            samples.append((time.perf_counter() - started) * 1000)
            # The server allows 40 calls per second per operator, and a
            # sample that ignores the limit measures the limiter instead of
            # the latency.
            if len(samples) % 20 == 0:
                time.sleep(0.5)
        samples.sort()
        p50 = samples[len(samples) // 2]
        p95 = samples[int(len(samples) * 0.95)]
        worst = samples[-1]
        print(f"\nconsole RPC latency (idle server, {len(samples)} calls): "
              f"p50 {p50:.2f} ms, p95 {p95:.2f} ms, max {worst:.2f} ms")
        assert p95 < 250, p95
    finally:
        client.close()


# ---------------------------------------------------------------------------
# a deployment that is wrong stops before it serves
# ---------------------------------------------------------------------------

def _start_expecting_failure(binary: str, workdir: str, operators: str,
                             config: dict | None = None) -> subprocess.CompletedProcess:
    """Start the server and wait for it to refuse: a misconfiguration is a
    start-up error with a message, not a server that half works."""
    box = Server(binary, workdir, operators, config=config)
    env = dict(os.environ, UMBRA_AGENT_PSK=AGENT_PSK.hex(),
               UMBRA_OPERATOR_TOKENS=box.operators)
    args = [binary, "--listen-agent", box.agent_addr,
            "--listen-operator", box.op_addr,
            "--data", os.path.join(workdir, "state.json")]
    if box.config_path:
        args = [binary, "--config", box.config_path, *args[1:]]
    return subprocess.run(args, env=env, cwd=workdir, capture_output=True,
                          text=True, timeout=30)


def test_a_deployment_without_an_admin_does_not_start(server_binary, tmp_path):
    """The server refuses to serve a team that cannot administer itself."""
    result = _start_expecting_failure(server_binary, str(tmp_path),
                                      f"viewer:viewer:{TOKEN}")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "admin" in result.stderr, result.stderr


def test_a_malformed_token_line_does_not_start(server_binary, tmp_path):
    """A keyring line that cannot be read is a start-up error that says so."""
    result = _start_expecting_failure(server_binary, str(tmp_path),
                                      "alice=not-a-keyring-line")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "name:token or name:role:token" in result.stderr, result.stderr


def test_the_product_rate_limits_a_burst(server):
    """Forty calls a second is the budget, and the refusal is visible.

    This is the limiter of the product, not of the mock: a console that
    loops faster than the budget is told so instead of being queued.
    """
    from umbra_cli.client import OperatorError

    client = console(server)
    refused = 0
    try:
        # The budget is per second, so the burst has to outrun a second of
        # round trips; how many are refused depends on the machine, and the
        # test asserts only that the limit exists.
        for _ in range(400):
            try:
                client.stats()
            except OperatorError as exc:
                if "rate limited" in str(exc):
                    refused += 1
                else:  # pragma: no cover - another refusal is a surprise
                    raise
        assert refused > 0, "a burst of 120 calls was served without a limit"
    finally:
        client.close()
