package store_test

import (
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

func TestScheduleValidation(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st.UpsertAgent(&store.Agent{ID: "a", Host: "h"})

	if _, err := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "ping", EverySec: 1}); err == nil {
		t.Error("a 1 s interval was accepted (self-inflicted DoS)")
	}
	if _, err := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "ping", EverySec: 90000}); err == nil {
		t.Error("a 25 h interval was accepted")
	}
	if _, err := st.AddSchedule(&store.Schedule{Kind: "ping", EverySec: 30}); err == nil {
		t.Error("a schedule without an agent was accepted")
	}
	if _, err := st.AddSchedule(&store.Schedule{AgentID: "a", EverySec: 30}); err == nil {
		t.Error("a schedule without a kind was accepted")
	}
	sc, err := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "ping", EverySec: 5})
	if err != nil || sc.ID == "" {
		t.Fatalf("valid schedule rejected: %v", err)
	}
}

func TestDueSchedulesAdvanceExactlyOnce(t *testing.T) {
	st, _ := store.Open("")
	now := time.Now().UTC()
	sc, err := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "ping", EverySec: 10})
	if err != nil {
		t.Fatal(err)
	}

	if due := st.DueSchedules(now); len(due) != 0 {
		t.Fatalf("a fresh schedule fired immediately: %+v", due)
	}
	due := st.DueSchedules(now.Add(11 * time.Second))
	if len(due) != 1 || due[0].ID != sc.ID {
		t.Fatalf("schedule did not fire: %+v", due)
	}
	// The same instant must not fire again: NextRun moved forward.
	if again := st.DueSchedules(now.Add(11 * time.Second)); len(again) != 0 {
		t.Fatalf("schedule fired twice for one interval: %+v", again)
	}
	// A long pause fires once, not once per missed interval.
	if later := st.DueSchedules(now.Add(10 * time.Minute)); len(later) != 1 {
		t.Fatalf("expected a single catch-up firing, got %d", len(later))
	}
}

func TestSchedulesSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/state.json"
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertAgent(&store.Agent{ID: "a", Host: "h"})
	sc, err := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "sysinfo", EverySec: 60, CreatedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Schedule(sc.ID)
	if !ok {
		t.Fatal("schedule lost across restart")
	}
	if got.Kind != "sysinfo" || got.EverySec != 60 || got.CreatedBy != "alice" {
		t.Fatalf("schedule corrupted: %+v", got)
	}
	// A schedule whose window passed while offline must not fire immediately.
	if due := reopened.DueSchedules(time.Now().UTC().Add(-time.Hour)); len(due) != 0 {
		t.Fatalf("a reloaded schedule fired with a stale window: %+v", due)
	}
	if due := reopened.DueSchedules(time.Now().UTC().Add(2 * time.Minute)); len(due) != 1 {
		t.Fatalf("reloaded schedule did not fire when due: %+v", due)
	}
}

func TestRemoveScheduleKeepsOrdering(t *testing.T) {
	st, _ := store.Open("")
	a, _ := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "ping", EverySec: 30})
	b, _ := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "sysinfo", EverySec: 30})
	c, _ := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "ls", EverySec: 30})

	if !st.RemoveSchedule(b.ID) {
		t.Fatal("remove failed")
	}
	if st.RemoveSchedule(b.ID) {
		t.Fatal("removing twice reported success")
	}
	all := st.Schedules()
	if len(all) != 2 || all[0].ID != a.ID || all[1].ID != c.ID {
		t.Fatalf("unexpected schedule list: %+v", all)
	}
	// Adding again must not resurrect the removed id or duplicate order entries.
	d, _ := st.AddSchedule(&store.Schedule{AgentID: "a", Kind: "ps", EverySec: 30})
	all = st.Schedules()
	if len(all) != 3 || all[2].ID != d.ID {
		t.Fatalf("added schedule not appended once: %+v", all)
	}
}
