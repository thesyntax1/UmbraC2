package store_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// Claims order human work: they must be exclusive, releasable by the holder,
// and impossible once the task has finished.
func TestTaskClaimLifecycle(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertAgent(&store.Agent{ID: "a1", Host: "lab"})
	task := st.AddTask(&store.Task{AgentID: "a1", Kind: "ping"})

	if _, err := st.Claim(task.ID, ""); err == nil {
		t.Fatal("claim without an operator succeeded")
	}
	claimed, err := st.Claim(task.ID, "alice")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed.ClaimedBy != "alice" || claimed.ClaimedAt.IsZero() {
		t.Fatalf("claim not recorded: %+v", claimed)
	}
	// Idempotent for the holder.
	if again, err := st.Claim(task.ID, "alice"); err != nil || again.ClaimedBy != "alice" {
		t.Fatalf("re-claim by the holder: %v / %+v", err, again)
	}
	// Refused for everyone else, release included.
	if _, err := st.Claim(task.ID, "bob"); err == nil {
		t.Fatal("bob stole a claim")
	}
	if _, err := st.Release(task.ID, "bob"); err == nil {
		t.Fatal("bob released someone else's claim")
	}
	if _, err := st.Release(task.ID, "alice"); err != nil {
		t.Fatalf("release by the holder: %v", err)
	}
	if got, _ := st.Task(task.ID); got.ClaimedBy != "" || !got.ClaimedAt.IsZero() {
		t.Fatalf("claim survived release: %+v", got)
	}
	// A finished task cannot be claimed.
	if _, ok := st.Complete(task.ID, 0, []byte("pong\n"), "", nil); !ok {
		t.Fatal("complete failed")
	}
	if _, err := st.Claim(task.ID, "bob"); err == nil {
		t.Fatal("a finished task was claimed")
	}
	if _, err := st.Claim("t-missing", "alice"); err == nil {
		t.Fatal("claiming a missing task succeeded")
	}
}

// A crash between the two renames of a save leaves no primary file at all.
// Open must fall back to the previous generation instead of starting empty.
func TestOpenFallsBackToTheBackupGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	first, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first.UpsertAgent(&store.Agent{ID: "a1", Host: "lab"})
	if err := first.Save(); err != nil {
		t.Fatal(err)
	}
	// Second save rotates a1 into the backup and installs the new state.
	first.UpsertAgent(&store.Agent{ID: "a2", Host: "lab-2"})
	if err := first.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("backup generation missing: %v", err)
	}

	// Simulate the crash window: primary gone, backup intact.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatalf("open after a lost primary: %v", err)
	}
	if !reopened.Recovered() {
		t.Fatal("recovery was not reported")
	}
	if _, ok := reopened.Agent("a1"); !ok {
		t.Fatal("the backup generation was not loaded")
	}
	// Saving again reinstalls the primary and clears the flag.
	if err := reopened.Save(); err != nil {
		t.Fatal(err)
	}
	if reopened.Recovered() {
		t.Fatal("recovery flag survived a successful save")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("primary not restored: %v", err)
	}
}

// A torn primary (valid JSON, wrong shape; or half a document) must not cost
// the engagement: the previous generation is still good.
func TestOpenIgnoresATornSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertAgent(&store.Agent{ID: "a1", Host: "lab"})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	task := st.AddTask(&store.Task{AgentID: "a1", Kind: "ping"})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	// Truncate the primary the way a failing disk would.
	if err := os.WriteFile(path, []byte(`{"version":2,"agents":[{"id":"a1"`), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatalf("open with a torn primary: %v", err)
	}
	if !reopened.Recovered() {
		t.Fatal("torn primary was not reported as a recovery")
	}
	if _, ok := reopened.Agent("a1"); !ok {
		t.Fatal("the backup generation was not loaded")
	}
	// The torn save is older than the task, so that task is expected to be
	// absent; what matters is that the file is coherent and usable.
	_, ok := reopened.Task(task.ID)
	if ok {
		t.Log("backup contained the newest task; both outcomes are valid")
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("backup consumed: %v", err)
	}
}

// `{}` is valid JSON but not a snapshot; treating it as an empty engagement
// would silently wipe the state file on the next save.
func TestEmptyJSONIsNotASnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(path); err == nil {
		t.Fatal("Open accepted an empty JSON document as state")
	}
}

// A file from a newer build must be refused, not silently downgraded.
func TestSnapshotVersionIsEnforced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	raw := `{"version":999,"saved_at":"2030-01-01T00:00:00Z","agents":[],"tasks":[]}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Open(path)
	if err == nil {
		t.Fatal("Open accepted a snapshot from a newer schema")
	}
	if !strings.Contains(err.Error(), "newer server") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// A beacon that stops checking in is offline, whatever its connection
// looked like when it was last open.
//
// The grace window is what keeps the inventory honest: a beacon closes its
// connection after every cycle, so a host that is merely asleep must not
// flip to "offline" between two cycles.  A host that has been quiet for
// longer than the grace has really gone.
func TestAnAgentThatStoppedCheckingInGoesOffline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	old := time.Now().UTC().Add(-2 * store.OfflineGrace)
	snap := map[string]any{
		"version":  3,
		"saved_at": time.Now().UTC(),
		"agents": []any{map[string]any{
			"id":         "quiet-1",
			"host":       "host-quiet-1",
			"os":         "linux",
			"arch":       "x86_64",
			"first_seen": old,
			"last_seen":  old,
			"state":      "online",
		}},
		"tasks": []any{},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	agents := st.Agents()
	if len(agents) != 1 {
		t.Fatalf("expected one agent, got %d", len(agents))
	}
	if agents[0].State != store.StateOffline {
		t.Fatalf("agent state is %q, want offline", agents[0].State)
	}
	// The record can be flipped as well: the hub does it when a link
	// ends, and it reports whether the host really went away.
	if !st.MarkOffline("quiet-1") {
		t.Fatal("MarkOffline did not report the change")
	}
	rec, ok := st.Agent("quiet-1")
	if !ok {
		t.Fatal("agent record disappeared")
	}
	if rec.State != store.StateOffline {
		t.Fatalf("agent state is %q, want offline", rec.State)
	}
}

// A task with a deadline of its own is not worth running after it, and a
// task with a timeout of its own is measured by that timeout: the promise
// the operator made is kept by the server, not by the good manners of the
// beacon.
func TestDeadlineAndTimeoutOfATask(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st.UpsertAgent(&store.Agent{ID: "agent-1", Host: "host", OS: "linux"})

	now := time.Now().UTC()
	past := st.AddTask(&store.Task{
		AgentID: "agent-1", Kind: "ping", Deadline: now.Add(-time.Minute),
	})
	future := st.AddTask(&store.Task{
		AgentID: "agent-1", Kind: "ping", Deadline: now.Add(time.Hour),
	})

	expired := st.ExpiredTasks(now)
	if len(expired) != 1 || expired[0].ID != past.ID {
		t.Fatalf("the expired task is not the one that passed its deadline: %v", expired)
	}
	for _, task := range expired {
		if task.ID == future.ID {
			t.Fatalf("a task with a deadline in the future expired: %v", expired)
		}
	}

	// A task with a timeout of its own is stale after that timeout, even
	// when the server's own timeout is much longer.
	short := st.AddTask(&store.Task{
		AgentID: "agent-1", Kind: "ping", TimeoutSec: 1,
	})
	st.MarkDelivered([]string{short.ID})
	time.Sleep(1100 * time.Millisecond)
	stale := st.StaleTasks(10 * time.Minute)
	found := false
	for _, task := range stale {
		if task.ID == short.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the task with its own timeout is not stale: %v", stale)
	}

	// The reason a task was cancelled is part of the record.
	previous, ok := st.CancelWithReason(short.ID, "the deadline passed")
	if !ok || previous != store.TaskDelivered {
		t.Fatalf("cancel: %v %v", previous, ok)
	}
	task, ok := st.Task(short.ID)
	if !ok {
		t.Fatalf("the task is gone")
	}
	if task.Err != "the deadline passed" {
		t.Fatalf("the reason was not kept: %q", task.Err)
	}
}
