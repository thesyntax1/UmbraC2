package link_test

import (
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// A task may carry a deadline and a timeout, and the server keeps both
// promises: the record says what the operator asked for, a task that passed
// its deadline is cancelled instead of delivered, and the timeout travels to
// the beacon so it can stop the work itself.
func TestATaskHasADeadlineAndATimeout(t *testing.T) {
	_, h, agentAddr, opAddr := newTestServer(t)

	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-limits-1")
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(1)})
	ag.recv(t)

	admin := dial(t, opAddr, opToken, crypt.RoleOperator, "op1")
	resp := admin.rpc(t, 1, "task.submit", upk.Map{
		"id":       "agent-limits-1",
		"kind":     "ping",
		"deadline": "2030-01-01T00:00:00Z",
		"timeout":  uint64(45),
	})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("submit failed: %v", resp["err"])
	}
	data, _ := resp["data"].(map[string]any)
	taskID, _ := data["task_id"].(string)
	if taskID == "" {
		t.Fatalf("no task id: %v", data)
	}

	// The record carries the deadline and the timeout.
	resp = admin.rpc(t, 2, "task.get", upk.Map{"task_id": taskID})
	data, _ = resp["data"].(map[string]any)
	if _, ok := data["deadline"]; !ok {
		t.Fatalf("the task has no deadline: %v", data)
	}
	if timeout, _ := data["timeout"].(int64); timeout != 45 {
		t.Fatalf("the timeout is %v, want 45: %v", data["timeout"], data)
	}

	// The timeout travels to the beacon inside the arguments, so the
	// implant stops the work itself instead of running past its time.
	task, ok := h.Store().Task(taskID)
	if !ok {
		t.Fatalf("the task is not in the store")
	}
	if secs, _ := task.Args["timeout"].(int); secs != 45 {
		t.Fatalf("the beacon was not told the bound: %v", task.Args)
	}

	// A task that passed its deadline is cancelled, not delivered.
	resp = admin.rpc(t, 3, "task.submit", upk.Map{
		"id":       "agent-limits-1",
		"kind":     "ping",
		"deadline": uint64(time.Now().Add(-time.Minute).Unix()),
	})
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("submit failed: %v", resp["err"])
	}
	data, _ = resp["data"].(map[string]any)
	staleID, _ := data["task_id"].(string)

	h.SweepTasks(time.Minute)

	resp = admin.rpc(t, 4, "task.get", upk.Map{"task_id": staleID})
	data, _ = resp["data"].(map[string]any)
	if data["state"] != "cancelled" {
		t.Fatalf("the task with a deadline in the past is %v, want cancelled", data["state"])
	}
	if errText, _ := data["err"].(string); errText == "" {
		t.Fatalf("the cancellation has no reason: %v", data)
	}

	// A deadline that is not a time at all is refused with a reason.
	resp = admin.rpc(t, 5, "task.submit", upk.Map{
		"id":       "agent-limits-1",
		"kind":     "ping",
		"deadline": "when the coffee is ready",
	})
	if ok, _ := resp["ok"].(bool); ok {
		t.Fatalf("a deadline that is not a time was accepted: %v", resp)
	}
	if errText, _ := resp["err"].(string); errText == "" {
		t.Fatalf("the refusal has no reason: %v", resp)
	}
}
