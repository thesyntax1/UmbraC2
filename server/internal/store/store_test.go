package store_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// Concurrent saves must never produce a torn or overwritten document. Before
// the write mutex and per-save temp files, every writer shared one
// "<path>.tmp" and could rename a half-rewritten file into place.
func TestConcurrentSavesStayValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st.UpsertAgent(&store.Agent{ID: "agent-1", Host: "host", OS: "linux"})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st.AddTask(&store.Task{AgentID: "agent-1", Kind: "ping"})
			if i%2 == 0 {
				if err := st.Save(); err != nil {
					t.Errorf("save: %v", err)
				}
				return
			}
			st.SaveAsync()
		}(i)
	}
	wg.Wait()
	// Waits for the coalescing writer, then writes the newest snapshot.
	if err := st.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var decoded struct {
		Agents []map[string]any `json:"agents"`
		Tasks  []map[string]any `json:"tasks"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("saved state is not valid JSON: %v", err)
	}
	if len(decoded.Agents) != 1 || decoded.Agents[0]["id"] != "agent-1" {
		t.Fatalf("agent lost: %+v", decoded.Agents)
	}
	if len(decoded.Tasks) != 32 {
		t.Fatalf("expected 32 tasks, got %d", len(decoded.Tasks))
	}

	// The swap must not leave temp files behind, and the file must reload.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "state.json" {
			t.Errorf("stray file after save: %s", e.Name())
		}
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := reopened.Agent("agent-1"); !ok {
		t.Error("agent did not survive a reload")
	}
}

func TestSaveWithoutPathIsANoOp(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.Save(); err != nil {
		t.Errorf("Save with no path: %v", err)
	}
	if err := st.Flush(); err != nil {
		t.Errorf("Flush with no path: %v", err)
	}
}

func TestBackgroundSaveErrorReachesTheHandler(t *testing.T) {
	dir := t.TempDir()
	// A regular file where the directory should be: every write fails with
	// ENOTDIR, deterministically.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	st, err := store.Open(filepath.Join(blocker, "state.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	reported := make(chan error, 1)
	st.SetSaveErrorHandler(func(err error) {
		select {
		case reported <- err:
		default:
		}
	})
	st.SaveAsync()

	select {
	case err := <-reported:
		if err == nil {
			t.Error("handler received a nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("save failure never reached the handler")
	}
}

// A task that was delivered but not completed must be re-queued on start: the
// process may have died before the agent ran it.
func TestDeliveredTasksAreRequeuedOnOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st.UpsertAgent(&store.Agent{ID: "a", Host: "h"})
	task := st.AddTask(&store.Task{AgentID: "a", Kind: "shell", Args: map[string]any{"cmd": "id"}})
	if got := st.Pending("a", 10); len(got) != 1 {
		t.Fatalf("task not delivered: %+v", got)
	}
	if err := st.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	rec, ok := reopened.Task(task.ID)
	if !ok {
		t.Fatal("task lost across restart")
	}
	if rec.State != store.TaskQueued {
		t.Fatalf("delivered task not re-queued: %q", rec.State)
	}
	if again := reopened.Pending("a", 10); len(again) != 1 || again[0].ID != task.ID {
		t.Fatalf("re-queued task not pending: %+v", again)
	}
}

func TestPendingMarksDelivered(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st.UpsertAgent(&store.Agent{ID: "a", Host: "h"})
	task := st.AddTask(&store.Task{AgentID: "a", Kind: "ping"})
	got := st.Pending("a", 10)
	if len(got) != 1 || got[0].ID != task.ID {
		t.Fatalf("pending returned %+v", got)
	}
	if again := st.Pending("a", 10); len(again) != 0 {
		t.Errorf("task delivered twice: %+v", again)
	}
	if rec, ok := st.Task(task.ID); !ok || rec.State != store.TaskDelivered {
		t.Errorf("state not advanced: %+v", rec)
	}
}

// Cancel must report what it replaced, refuse terminal states, and a late
// result must not resurrect a cancelled task.
func TestCancelStateMachine(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st.UpsertAgent(&store.Agent{ID: "a", Host: "h"})

	queued := st.AddTask(&store.Task{AgentID: "a", Kind: "shell"})
	previous, ok := st.Cancel(queued.ID)
	if !ok || previous != store.TaskQueued {
		t.Fatalf("cancel of a queued task: ok=%v previous=%q", ok, previous)
	}
	if again, ok := st.Cancel(queued.ID); ok {
		t.Fatalf("second cancel succeeded (previous=%q)", again)
	}

	delivered := st.AddTask(&store.Task{AgentID: "a", Kind: "shell"})
	if got := st.Pending("a", 10); len(got) != 1 || got[0].ID != delivered.ID {
		t.Fatalf("pending: %+v", got)
	}
	previous, ok = st.Cancel(delivered.ID)
	if !ok || previous != store.TaskDelivered {
		t.Fatalf("cancel of a delivered task: ok=%v previous=%q", ok, previous)
	}

	// The command did run; the result is recorded but the state stays cancelled.
	rec, ok := st.Complete(delivered.ID, 0, []byte("ran anyway\n"), "", nil)
	if !ok {
		t.Fatal("Complete reported the task missing")
	}
	if rec.State != store.TaskCancelled {
		t.Fatalf("late result changed state to %q", rec.State)
	}
	if string(rec.Output) != "ran anyway\n" {
		t.Fatalf("output not stored for a cancelled task: %q", rec.Output)
	}

	done := st.AddTask(&store.Task{AgentID: "a", Kind: "ping"})
	st.Complete(done.ID, 0, []byte("pong\n"), "", nil)
	if _, ok := st.Cancel(done.ID); ok {
		t.Fatal("a finished task was cancelled")
	}
}

// Result metadata must survive a restart: it is what makes a chunked transfer
// resumable, so losing it after a server restart would silently turn a partial
// download into an accepted one.
func TestResultMetaPersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertAgent(&store.Agent{ID: "a1", Host: "lab"})
	task := st.AddTask(&store.Task{AgentID: "a1", Kind: "download",
		Args: map[string]any{"path": "/etc/hostname", "offset": 0}})
	if _, ok := st.Complete(task.ID, 0, []byte("lab\n"), "", map[string]any{
		"total": uint64(4), "offset": uint64(0), "eof": true, "sha256": "abc123",
	}); !ok {
		t.Fatal("complete failed")
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Task(task.ID)
	if !ok {
		t.Fatal("task lost on reload")
	}
	if got.Meta["sha256"] != "abc123" {
		t.Fatalf("meta lost on reload: %v", got.Meta)
	}
	// JSON numbers come back as float64; the value must still be readable.
	if got.Meta["total"] != float64(4) && got.Meta["total"] != 4 {
		t.Fatalf("total meta wrong: %#v", got.Meta["total"])
	}
	if eof, _ := got.Meta["eof"].(bool); !eof {
		t.Fatalf("eof meta wrong: %#v", got.Meta["eof"])
	}
	// The copy must not share the map with the store.
	got.Meta["sha256"] = "tampered"
	if again, _ := reopened.Task(task.ID); again.Meta["sha256"] == "tampered" {
		t.Fatal("Clone shared the Meta map")
	}
}
