package rhythm

import (
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/hub"
)

func TestTwoCheckInsAreNotAShape(t *testing.T) {
	r := New()
	now := time.Now().UTC()
	r.Record("web-01", now)
	r.Dispatch(hub.Event{Kind: "agent.heartbeat", AgentID: "web-01",
		At: now.Add(time.Second)})
	stats, ok := r.Stats("web-01")
	if !ok {
		t.Fatal("the registry forgot the host")
	}
	if stats.Beats != 2 || stats.Shape != ShapeYoung {
		t.Fatalf("two check-ins are young, not a shape: %+v", stats)
	}
	// An event that is not a heartbeat is not the rhythm of a host.
	r.Dispatch(hub.Event{Kind: "task.result", AgentID: "web-01", At: now})
	if stats, _ := r.Stats("web-01"); stats.Beats != 2 {
		t.Fatalf("the rhythm counted work as a heartbeat: %+v", stats)
	}
	if _, ok := r.Stats("no-such-host"); ok {
		t.Fatal("the registry knows a host that never called home")
	}
}

func TestTheMetronomeIsNamed(t *testing.T) {
	r := New()
	now := time.Now().UTC()
	// A beacon on a clock: ten beats, sixty seconds apart, give or take
	// a breath of a tenth of a second.
	for i := 0; i < 10; i++ {
		gap := time.Duration(60*i)*time.Second + time.Duration(i%2)*100*time.Millisecond
		r.Record("db-02", now.Add(gap))
	}
	stats, _ := r.Stats("db-02")
	if stats.Shape != ShapeMetronome {
		t.Fatalf("a clock was called %q", stats.Shape)
	}
	if stats.Interval < 59_900 || stats.Interval > 60_100 {
		t.Fatalf("the mean pause is not the minute: %d", stats.Interval)
	}
	if stats.ETA.Before(stats.Last.Add(59 * time.Second)) {
		t.Fatal("the eta does not follow the mean")
	}

	// A wandering host pauses wherever the scheduler put it.
	wander := []time.Duration{0, 3, 4, 120, 121, 250, 900, 1000, 2000, 4000}
	for _, seconds := range wander {
		r.Record("laptop-9", now.Add(seconds*time.Second))
	}
	stats, _ = r.Stats("laptop-9")
	if stats.Shape != ShapeWandering && stats.Shape != ShapeBreathing {
		t.Fatalf("a wandering host was called %q", stats.Shape)
	}
	if !stats.ETA.After(stats.Last) {
		t.Fatal("the eta of the wandering host went backwards")
	}
}

func TestTheFleetPutsTheClocksFirst(t *testing.T) {
	r := New()
	now := time.Now().UTC()
	for i := 0; i < 8; i++ {
		r.Record("clock-1", now.Add(time.Duration(i)*time.Minute))
		gap := time.Duration(i*i) * 7 * time.Second
		r.Record("wander-2", now.Add(gap))
	}
	r.Record("young-3", now)
	fleet := r.Fleet()
	if len(fleet) != 3 {
		t.Fatalf("the fleet forgot somebody: %v", fleet)
	}
	if fleet[0].AgentID != "clock-1" {
		t.Fatalf("the clock did not come first: %+v", fleet)
	}
	if fleet[len(fleet)-1].AgentID != "young-3" {
		t.Fatalf("the young one did not come last: %+v", fleet)
	}
}
