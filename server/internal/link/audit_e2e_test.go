package link_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// Every operator RPC must leave a line behind, whether it succeeded or not.
// The audit trail is the only record of *who* queued a command, so a silent
// gap is a security bug rather than a logging nicety.
func TestOperatorActionsAreAudited(t *testing.T) {
	srv, _, _, opAddr := newTestServer(t)

	dir := t.TempDir()
	log, err := audit.Open(audit.Options{Path: filepath.Join(dir, "audit.jsonl"), RingSize: 4})
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	srv.SetAudit(log)

	op := dial(t, opAddr, opToken, crypt.RoleOperator, "op1")

	// A success, a failure, and a task submission that we can trace by id.
	op.send(t, wire.MsgOpRequest, upk.Map{"rid": uint64(1), "cmd": "server.stats", "args": upk.Map{}})
	if msgType, resp := op.recv(t); msgType != wire.MsgOpResponse || resp["ok"] != true {
		t.Fatalf("server.stats failed: %v", resp["err"])
	}
	op.send(t, wire.MsgOpRequest, upk.Map{"rid": uint64(2), "cmd": "agents.info", "args": upk.Map{"id": "nope"}})
	if _, resp := op.recv(t); resp["ok"] == true {
		t.Fatal("agents.info on an unknown agent reported success")
	}

	// The operator can read the trail back through the RPC that the CLI uses.
	op.send(t, wire.MsgOpRequest, upk.Map{
		"rid": uint64(3), "cmd": "audit.tail", "args": upk.Map{"limit": int64(10)},
	})
	_, resp := op.recv(t)
	if resp["ok"] != true {
		t.Fatalf("audit.tail failed: %v", resp["err"])
	}
	data, _ := resp["data"].(map[string]any)
	entries, _ := data["entries"].([]any)
	if len(entries) < 2 {
		t.Fatalf("expected at least two audit entries, got %d", len(entries))
	}
	// Newest first: audit.tail itself is the most recent recorded action.
	first, _ := entries[0].(map[string]any)
	if first["cmd"] != "audit.tail" {
		t.Fatalf("newest entry is %v, want audit.tail", first["cmd"])
	}
	if first["operator"] != "op1" {
		t.Fatalf("entry not attributed to the operator: %v", first["operator"])
	}
	if first["transport"] != "tcp/operator" {
		t.Fatalf("entry lost the transport: %v", first["transport"])
	}
	if first["peer"] == "" {
		t.Error("entry lost the peer address")
	}

	// Find the failed call and make sure the error text survived.
	var sawFailure bool
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		if e["cmd"] == "agents.info" {
			sawFailure = true
			if e["ok"] == true || e["err"] == "" {
				t.Errorf("failed RPC recorded as a success: %v", e)
			}
		}
	}
	if !sawFailure {
		t.Error("failed RPC never reached the audit log")
	}

	// And the file itself must contain parseable JSON Lines with the same data:
	// the RPC is a convenience, the file is the record.
	raw, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	lines := 0
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("audit line %d is not JSON: %v (%s)", lines+1, err, line)
		}
		if e.At.IsZero() || e.Cmd == "" {
			t.Errorf("incomplete audit entry on disk: %+v", e)
		}
		lines++
	}
	if lines < 3 {
		t.Fatalf("expected at least three lines on disk, got %d", lines)
	}
}

// Assignment of task and agent ids is what makes an entry actionable later.
func TestAuditRecordsTaskAndAgentIDs(t *testing.T) {
	srv, h, agentAddr, opAddr := newTestServer(t)

	dir := t.TempDir()
	log, err := audit.Open(audit.Options{Path: filepath.Join(dir, "audit.jsonl")})
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	srv.SetAudit(log)

	// Register an agent so task.submit has a target.
	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-audit-1")
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	ag.recv(t)

	task, err := h.SubmitTask("agent-audit-1", "ping", nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	op := dial(t, opAddr, opToken, crypt.RoleOperator, "op1")
	op.send(t, wire.MsgOpRequest, upk.Map{
		"rid": uint64(1), "cmd": "task.cancel",
		"args": upk.Map{"task_id": task.ID},
	})
	if _, resp := op.recv(t); resp["ok"] != true {
		t.Fatalf("task.cancel failed: %v", resp["err"])
	}

	entries := log.Tail(10)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	if entries[0].TaskID != task.ID {
		t.Errorf("task id not recorded: %+v", entries[0])
	}
}
