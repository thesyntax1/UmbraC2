// Package rhythm is how the beacons breathe.
//
// An implant calls home on a clock somebody set: a sleep and a jitter.
// What it actually does on the wire is a different matter — the
// scheduler of the host, the load of the link and the patience of the
// implant all stand between the plan and the world.  The rhythm keeps
// the moments the check-ins arrived and says the shape of them: the
// mean, the spread, and a name for the shape, because a beacon that
// calls home like a metronome is a beacon a watcher can set a clock
// by, and the team that knows its own shape is the team that can fix
// it.
//
// The rules are the ones of the watchers of the watch:
//
//   - it counts what arrived, never what was hoped for: the journal
//     of the hub is the only truth it reads;
//   - it keeps moments, not bytes: the number of the moment, and
//     nothing of what the beat carried;
//   - it says "young" instead of guessing, because two check-ins are
//     not a shape.
package rhythm

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/hub"
)

// Limits.
//
// The rhythm is the shape of a host, not the history of it: two
// hundred and fifty-six beats are enough to know how a beacon
// breathes, and the rest is archaeology.
const (
	// MaxBeats bounds the moments kept for one host.
	MaxBeats = 256
	// MaxAgents bounds the hosts the rhythm remembers at once.  A host
	// that is not on the map cannot leak memory here either.
	MaxAgents = 4096
)

// The names of the shapes.
//
// A metronome is a beacon a watcher can set a clock by; steady is the
// shape of a jitter that works; breathing is the shape of a jitter
// that is wide enough to look like a human's work; wandering is the
// host whose own scheduler does the hiding for free.  Young is not a
// shape: it is the honest word for a host that has not called home
// often enough.
const (
	ShapeYoung     = "young"
	ShapeMetronome = "a metronome"
	ShapeSteady    = "steady"
	ShapeBreathing = "breathing"
	ShapeWandering = "wandering"
)

// Registry keeps the moments the beacons called home.
type Registry struct {
	mu    sync.Mutex
	beats map[string][]time.Time
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{beats: make(map[string][]time.Time)}
}

// Dispatch is the tap the hub calls for every event.  Only the beats
// are counted: the events that carry work — results, outputs, the
// business of the day — are not the rhythm of a host.
func (r *Registry) Dispatch(ev hub.Event) {
	if ev.Kind != "agent.heartbeat" || ev.AgentID == "" {
		return
	}
	when := ev.At
	if when.IsZero() {
		when = time.Now().UTC()
	}
	r.Record(ev.AgentID, when)
}

// Record writes down one moment a host called home.
func (r *Registry) Record(agentID string, at time.Time) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.beats[agentID]; !ok && len(r.beats) >= MaxAgents {
		return
	}
	list := append(r.beats[agentID], at.UTC())
	if len(list) > MaxBeats {
		copy(list, list[len(list)-MaxBeats:])
		list = list[:MaxBeats]
	}
	r.beats[agentID] = list
}

// Stats is the shape of one host: how often it called home, what the
// pauses between the calls look like, and a name for the shape.
type Stats struct {
	// AgentID is the host the shape belongs to.
	AgentID string `json:"agent_id"`
	// Beats is how many check-ins the registry holds.
	Beats int `json:"beats"`
	// First and Last bound the window the shape was measured in.
	First time.Time `json:"first,omitempty"`
	Last  time.Time `json:"last,omitempty"`
	// Interval is the mean pause between the beats, in milliseconds.
	Interval int64 `json:"interval_ms"`
	// Spread is the population spread of the pauses, in milliseconds.
	Spread int64 `json:"spread_ms"`
	// Shortest and Longest are the extremes of the pauses.
	Shortest int64 `json:"shortest_ms"`
	Longest  int64 `json:"longest_ms"`
	// CV is the spread against the mean: the closer to zero, the more
	// the beacon calls home like a clock.
	CV float64 `json:"cv"`
	// Shape is the name of the shape; it is honest about "young".
	Shape string `json:"shape"`
	// ETA is when the next beat would come if the host kept its mean,
	// so the operator waiting for a host knows when to start worrying.
	ETA time.Time `json:"eta,omitempty"`
}

// shapeOf names the coefficient of variation: the spread against the
// mean.  The numbers are opinionated on purpose — 5% is a clock, 20%
// is a jitter that exists, 50% is a jitter that works.
func shapeOf(cv float64) string {
	switch {
	case cv < 0.05:
		return ShapeMetronome
	case cv < 0.20:
		return ShapeSteady
	case cv < 0.50:
		return ShapeBreathing
	default:
		return ShapeWandering
	}
}

// statsOf measures one list of moments.
func statsOf(agentID string, beats []time.Time) Stats {
	stats := Stats{AgentID: agentID, Beats: len(beats), Shape: ShapeYoung}
	if len(beats) == 0 {
		return stats
	}
	stats.First = beats[0]
	stats.Last = beats[len(beats)-1]
	if len(beats) < 4 {
		return stats
	}
	pauses := make([]float64, 0, len(beats)-1)
	for i := 1; i < len(beats); i++ {
		gap := beats[i].Sub(beats[i-1]).Milliseconds()
		if gap < 0 {
			gap = 0
		}
		pauses = append(pauses, float64(gap))
	}
	var sum float64
	shortest, longest := pauses[0], pauses[0]
	for _, gap := range pauses {
		sum += gap
		if gap < shortest {
			shortest = gap
		}
		if gap > longest {
			longest = gap
		}
	}
	mean := sum / float64(len(pauses))
	var sq float64
	for _, gap := range pauses {
		d := gap - mean
		sq += d * d
	}
	spread := math.Sqrt(sq / float64(len(pauses)))
	stats.Interval = int64(mean)
	stats.Spread = int64(spread)
	stats.Shortest = int64(shortest)
	stats.Longest = int64(longest)
	if mean > 0 {
		stats.CV = spread / mean
	}
	stats.Shape = shapeOf(stats.CV)
	stats.ETA = stats.Last.Add(time.Duration(stats.Interval) * time.Millisecond)
	return stats
}

// Stats returns the shape of one host, and whether it knows the host.
func (r *Registry) Stats(agentID string) (Stats, bool) {
	r.mu.Lock()
	beats, ok := r.beats[agentID]
	clone := append([]time.Time(nil), beats...)
	r.mu.Unlock()
	if !ok {
		return Stats{}, false
	}
	return statsOf(agentID, clone), true
}

// Fleet returns the shapes of every host the registry knows, the
// clocks first: the host a watcher could set a watch by comes before
// the host that wanders, because the first kind is the one to fix.
// Hosts too young to have a shape come last, honest about it.
func (r *Registry) Fleet() []Stats {
	r.mu.Lock()
	snapshot := make(map[string][]time.Time, len(r.beats))
	for id, beats := range r.beats {
		snapshot[id] = append([]time.Time(nil), beats...)
	}
	r.mu.Unlock()
	out := make([]Stats, 0, len(snapshot))
	for id, beats := range snapshot {
		out = append(out, statsOf(id, beats))
	}
	rank := map[string]int{
		ShapeMetronome: 0, ShapeSteady: 1, ShapeBreathing: 2,
		ShapeWandering: 3, ShapeYoung: 4,
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := rank[out[i].Shape], rank[out[j].Shape]
		if ri != rj {
			return ri < rj
		}
		if out[i].CV != out[j].CV {
			return out[i].CV < out[j].CV
		}
		return out[i].AgentID < out[j].AgentID
	})
	return out
}
