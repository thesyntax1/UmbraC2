package silence

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// seenOf is the lookup for the tests: the moments the hosts called
// home, from a map instead of a store.
func seenOf(moments map[string]time.Time) func(string) (time.Time, bool) {
	return func(agentID string) (time.Time, bool) {
		when, ok := moments[agentID]
		return when, ok
	}
}

func TestTheWatchSaysTheWord(t *testing.T) {
	r := New()
	now := time.Now().UTC()
	w, err := r.Add(Watch{AgentID: "web-01", Seconds: 30, Creator: "alice"})
	if err != nil {
		t.Fatalf("the promise was refused: %v", err)
	}
	if w.ID != "s-0001" || w.Cooldown != 300 {
		t.Fatalf("the promise lost its details: %+v", w)
	}
	moments := map[string]time.Time{"web-01": now}

	// Not yet: twenty seconds of quiet is not news when the pause is thirty.
	if due := r.Due(now.Add(20*time.Second), seenOf(moments)); len(due) != 0 {
		t.Fatalf("the watch cried early: %v", due)
	}
	// Long quiet is one word, said once.
	if due := r.Due(now.Add(31*time.Second), seenOf(moments)); len(due) != 1 {
		t.Fatalf("the watch stayed quiet: %v", due)
	}
	due := r.Due(now.Add(40*time.Second), seenOf(moments))
	if len(due) != 0 {
		t.Fatalf("the watch drummed: %v", due)
	}
	// After the cooldown the still-quiet host is news again.
	if due := r.Due(now.Add(331*time.Second), seenOf(moments)); len(due) != 1 {
		t.Fatalf("the watch forgot to speak again: %v", due)
	}
	// A fresh beat ends the matter.
	moments["web-01"] = now.Add(340 * time.Second)
	if due := r.Due(now.Add(341*time.Second), seenOf(moments)); len(due) != 0 {
		t.Fatalf("the watch worried about a host that called home: %v", due)
	}
}

func TestTheUnseenHostIsNotLost(t *testing.T) {
	r := New()
	now := time.Now().UTC()
	if _, err := r.Add(Watch{AgentID: "ghost", Seconds: 10, Creator: "alice"}); err != nil {
		t.Fatalf("the promise was refused: %v", err)
	}
	// A host the server never saw starts its clock when the watch was
	// promised: ten seconds later, its absence is news.
	if due := r.Due(now.Add(11*time.Second), seenOf(nil)); len(due) != 1 {
		t.Fatalf("the silence of the unseen was not news: %v", due)
	}
}

func TestThePromiseIsBounded(t *testing.T) {
	r := New()
	if _, err := r.Add(Watch{Seconds: 60}); err != ErrNoAgent {
		t.Fatalf("a watch without a host was accepted: %v", err)
	}
	if _, err := r.Add(Watch{AgentID: "a", Seconds: 2}); err == nil {
		t.Fatal("a pause of a panic was accepted")
	}
	if _, err := r.Add(Watch{AgentID: "a", Seconds: 60}); err != nil {
		t.Fatalf("a sane watch was refused: %v", err)
	}
	// The refusal names the host, so it wraps the sentinel: the test asks
	// whether the error *is* ErrTwiceWatched, not whether it is the bare
	// value, which would forbid the message that makes the log useful.
	if _, err := r.Add(Watch{AgentID: "a", Seconds: 90}); !errors.Is(err, ErrTwiceWatched) {
		t.Fatalf("the second promise over the same silence was accepted: %v", err)
	}
	if err := r.Remove("s-0099"); err != ErrNoSuchWatch {
		t.Fatalf("an unknown watch was removed: %v", err)
	}
}

func TestTheLedgerSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "silences.json")
	r := New()
	r.SetPath(path)
	if _, err := r.Add(Watch{AgentID: "web-01", Seconds: 45, Creator: "alice"}); err != nil {
		t.Fatalf("the promise was refused: %v", err)
	}
	if err := r.Save(); err != nil {
		t.Fatalf("the ledger could not be saved: %v", err)
	}
	again := New()
	again.SetPath(path)
	if err := again.Load(); err != nil {
		t.Fatalf("the ledger could not be read back: %v", err)
	}
	watches := again.List()
	if len(watches) != 1 || watches[0].AgentID != "web-01" || watches[0].Seconds != 45 {
		t.Fatalf("the ledger forgot the promise: %+v", watches)
	}
}
