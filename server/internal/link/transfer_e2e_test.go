package link_test

import (
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// A chunked transfer is only verifiable if the beacon's transfer metadata
// survives: the RESULT body carries `total`/`offset`/`eof`/`sha256` next to the
// payload, the server stores them and task.get hands them back.
func TestResultMetaIsStoredAndReturned(t *testing.T) {
	_, h, agentAddr, opAddr := newTestServer(t)

	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-xfer-1")
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	if msgType, _ := ag.recv(t); msgType != wire.MsgTaskBatch {
		t.Fatalf("expected TASK_BATCH, got %s", wire.TypeName(msgType))
	}

	task, err := h.SubmitTask("agent-xfer-1", "download", map[string]any{
		"path": "/etc/hostname", "offset": 0, "limit": 1024,
	})
	if err != nil {
		t.Fatalf("submit task: %v", err)
	}
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	if msgType, _ := ag.recv(t); msgType != wire.MsgTaskBatch {
		t.Fatalf("expected TASK_BATCH, got %s", wire.TypeName(msgType))
	}

	ag.send(t, wire.MsgResult, upk.Map{
		"id":     task.ID,
		"code":   int64(0),
		"out":    []byte("lab-01\n"),
		"err":    "",
		"total":  uint64(7),
		"offset": uint64(0),
		"eof":    true,
		"sha256": "5d41402abc4b2a76b9719d911017c592",
		// Nested values must be dropped: the state file only takes scalars.
		"nested": upk.Map{"x": int64(1)},
	})

	deadline := time.Now().Add(2 * time.Second)
	for {
		got, ok := h.Store().Task(task.ID)
		if ok && got.State == store.TaskDone {
			if got.Meta["sha256"] != "5d41402abc4b2a76b9719d911017c592" {
				t.Fatalf("sha256 meta missing: %v", got.Meta)
			}
			if total, _ := got.Meta["total"].(uint64); total != 7 {
				t.Fatalf("total meta wrong: %v", got.Meta)
			}
			if eof, _ := got.Meta["eof"].(bool); !eof {
				t.Fatalf("eof meta wrong: %v", got.Meta)
			}
			if _, bad := got.Meta["nested"]; bad {
				t.Fatalf("non-scalar meta was stored: %v", got.Meta)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("task was never completed")
		}
		time.Sleep(20 * time.Millisecond)
	}

	op := dial(t, opAddr, opToken, crypt.RoleOperator, "op1")
	op.send(t, wire.MsgOpRequest, upk.Map{
		"rid": uint64(1), "cmd": "task.get",
		"args": upk.Map{"task_id": task.ID},
	})
	resp := op.recvResponse(t, 1)
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("task.get failed: %v", resp["err"])
	}
	data, _ := resp["data"].(map[string]any)
	meta, _ := data["meta"].(map[string]any)
	if meta["sha256"] != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("task.get did not return meta: %v", data)
	}
	if out, _ := data["out"].([]byte); string(out) != "lab-01\n" {
		t.Fatalf("task.get lost the payload: %q", data["out"])
	}
}
