package link_test

import (
	"strings"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// rpc is a tiny helper: send one operator request and return its response body.
func (c *client) rpc(t *testing.T, rid uint64, cmd string, args upk.Map) map[string]any {
	t.Helper()
	req := upk.Map{"rid": rid, "cmd": cmd}
	if args != nil {
		req["args"] = args
	}
	c.send(t, wire.MsgOpRequest, req)
	resp := c.recvResponse(t, rid)
	if got, _ := resp["rid"].(uint64); got != rid {
		t.Fatalf("%s: rid %v != %d", cmd, resp["rid"], rid)
	}
	return resp
}

// A claim must be visible to the whole team and must not be stealable: two
// operators sharing an engagement is the normal case, and duplicating work is
// the failure mode that costs time.
func TestTaskClaimIsExclusiveAndVisible(t *testing.T) {
	_, h, agentAddr, opAddr := newTestServer(t)

	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-coord-1")
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(1)})
	ag.recv(t)

	task, err := h.SubmitTask("agent-coord-1", "ping", nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	admin := dial(t, opAddr, opToken, crypt.RoleOperator, "op1")
	resp := admin.rpc(t, 1, "task.claim", upk.Map{"task_id": task.ID})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("claim failed: %v", resp["err"])
	}
	data, _ := resp["data"].(map[string]any)
	if data["claimed_by"] != "op1" {
		t.Fatalf("claim not recorded: %v", data)
	}

	// The claim is part of the task view.
	resp = admin.rpc(t, 2, "task.get", upk.Map{"task_id": task.ID})
	data, _ = resp["data"].(map[string]any)
	if data["claimed_by"] != "op1" {
		t.Fatalf("task.get lost the claim: %v", data)
	}

	// A second operator cannot steal the claim, and a viewer cannot claim at
	// all: the RBAC gate runs before the store is touched.
	second := dial(t, opAddr, op2Token, crypt.RoleOperator, "op2")
	resp = second.rpc(t, 1, "task.claim", upk.Map{"task_id": task.ID})
	if ok, _ := resp["ok"].(bool); ok {
		t.Fatal("a claim was stolen by another operator")
	}
	if errText, _ := resp["err"].(string); !strings.Contains(errText, "claimed by op1") {
		t.Fatalf("unexpected claim conflict: %q", errText)
	}

	viewer := dial(t, opAddr, viewerToken, crypt.RoleOperator, "viewer1")
	resp = viewer.rpc(t, 1, "task.claim", upk.Map{"task_id": task.ID})
	if ok, _ := resp["ok"].(bool); ok {
		t.Fatal("viewer was allowed to claim a task")
	}
	if errText, _ := resp["err"].(string); !strings.Contains(errText, "permission denied") {
		t.Fatalf("unexpected refusal: %q", errText)
	}

	// op1 releases it; the same operator may claim again.
	resp = admin.rpc(t, 3, "task.release", upk.Map{"task_id": task.ID})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("release failed: %v", resp["err"])
	}
	if _, ok := h.Store().Task(task.ID); !ok {
		t.Fatal("task vanished")
	}
	got, _ := h.Store().Task(task.ID)
	if got.ClaimedBy != "" {
		t.Fatalf("claim survived release: %q", got.ClaimedBy)
	}

	// Claiming an unknown task is an error, not a silent no-op.
	resp = admin.rpc(t, 4, "task.claim", upk.Map{"task_id": "t-does-not-exist"})
	if ok, _ := resp["ok"].(bool); ok {
		t.Fatal("claiming an unknown task succeeded")
	}
}

// Focus is presence only: it must show up in operators.list for teammates and
// must not be accepted for an agent that does not exist.
func TestOperatorFocusIsPresence(t *testing.T) {
	_, _, agentAddr, opAddr := newTestServer(t)

	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-focus-1")
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(1)})
	ag.recv(t)

	op := dial(t, opAddr, opToken, crypt.RoleOperator, "op1")
	resp := op.rpc(t, 1, "operators.focus", upk.Map{"id": "agent-focus-1"})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("focus failed: %v", resp["err"])
	}

	resp = op.rpc(t, 2, "operators.list", nil)
	data, _ := resp["data"].(map[string]any)
	ops, _ := data["operators"].([]any)
	if len(ops) != 1 {
		t.Fatalf("expected one console, got %d", len(ops))
	}
	row, _ := ops[0].(map[string]any)
	if row["focus"] != "agent-focus-1" {
		t.Fatalf("focus not listed: %v", row)
	}
	if _, ok := row["idle_sec"]; !ok {
		t.Fatalf("idle_sec missing: %v", row)
	}

	// Unknown agents are rejected instead of being stored as a dangling focus.
	resp = op.rpc(t, 3, "operators.focus", upk.Map{"id": "ghost"})
	if ok, _ := resp["ok"].(bool); ok {
		t.Fatal("focus accepted an unknown agent")
	}

	// Clearing works.
	resp = op.rpc(t, 4, "operators.focus", upk.Map{})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("clearing focus failed: %v", resp["err"])
	}
}
