package link_test

import (
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// A cancel for a task the beacon already holds must arrive as a TASK_CANCEL
// frame *before* the TASK_BATCH of the next check-in, and must not disturb the
// batch that follows.
func TestCancelIsSentBeforeTheNextBatch(t *testing.T) {
	_, h, agentAddr, _ := newTestServer(t)

	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-cancel-1")
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	if msgType, _ := ag.recv(t); msgType != wire.MsgTaskBatch {
		t.Fatalf("first check-in: expected TASK_BATCH, got %s", wire.TypeName(msgType))
	}

	task, err := h.SubmitTask("agent-cancel-1", "shell", map[string]any{"cmd": "sleep 60"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	// Deliver it (this is what puts it in "delivered" and therefore cancellable
	// with a frame).
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	if msgType, batch := ag.recv(t); msgType != wire.MsgTaskBatch || len(batch["tasks"].([]any)) != 1 {
		t.Fatalf("second check-in did not deliver the task: %s", wire.TypeName(msgType))
	}

	if !h.CancelTask(task.ID) {
		t.Fatal("cancel of a delivered task was refused")
	}

	// The next cycle: TASK_CANCEL then TASK_BATCH, in that order.
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	msgType, body := ag.recv(t)
	if msgType != wire.MsgTaskCancel {
		t.Fatalf("expected TASK_CANCEL first, got %s", wire.TypeName(msgType))
	}
	if id, _ := body["id"].(string); id != task.ID {
		t.Fatalf("cancel frame carries %q, want %q", id, task.ID)
	}
	msgType, batch := ag.recv(t)
	if msgType != wire.MsgTaskBatch {
		t.Fatalf("expected TASK_BATCH after the cancel, got %s", wire.TypeName(msgType))
	}
	if tasks, _ := batch["tasks"].([]any); len(tasks) != 0 {
		t.Fatalf("cancelled task was re-delivered: %v", tasks)
	}

	// The queue is drained: the following cycle has no control frame at all.
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	if msgType, _ := ag.recv(t); msgType != wire.MsgTaskBatch {
		t.Fatalf("cancel frame repeated: got %s", wire.TypeName(msgType))
	}
}

// A queued-but-undelivered task never ships, so it needs no frame.
func TestCancelOfAQueuedTaskSendsNoFrame(t *testing.T) {
	_, h, agentAddr, _ := newTestServer(t)

	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-cancel-2")
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	ag.recv(t)

	task, err := h.SubmitTask("agent-cancel-2", "ping", nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !h.CancelTask(task.ID) {
		t.Fatal("cancel of a queued task was refused")
	}

	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	msgType, batch := ag.recv(t)
	if msgType != wire.MsgTaskBatch {
		t.Fatalf("expected TASK_BATCH, got %s", wire.TypeName(msgType))
	}
	if tasks, _ := batch["tasks"].([]any); len(tasks) != 0 {
		t.Fatalf("a cancelled queued task was delivered: %v", tasks)
	}
	if got := h.TakeCancels("agent-cancel-2"); len(got) != 0 {
		t.Fatalf("unexpected pending cancels: %v", got)
	}
}
