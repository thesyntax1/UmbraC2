package hub

import (
	"sort"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// The buckets of the task latency histogram.
//
// The buckets are the ones Prometheus uses by default, so the numbers can
// be compared with the ones of the other exporters without thinking about
// it.  The last bucket is the sum of everything above it.
var LatencyBuckets = []time.Duration{
	100 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	5 * time.Second,
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
}

// Metrics is the snapshot of the counters of the server.
//
// It is the answer to "is the engagement healthy": the depth of the queue,
// how long a task takes, how often the beacons check in, how often a task
// fails, which transports the beacons speak and how many bytes moved.
type Metrics struct {
	AgentsTotal  int
	AgentsOnline int
	TasksTotal   int
	TasksPending int
	TasksDone    int
	TasksFailed  int
	TasksDead    int
	// LatencyBuckets holds, for every bucket of LatencyBuckets, the number
	// of tasks that finished inside it (cumulative).
	LatencyBuckets []int
	// LatencyCount is the number of tasks that finished, and LatencySum
	// the total of their durations in seconds.
	LatencyCount int
	LatencySum   float64
	// Checkins is the number of check-ins the beacons made.
	Checkins uint64
	// Transports counts the agents per transport.
	Transports map[string]int
	BytesIn    int64
	BytesOut   int64
	Operators  int
	// EventsDropped counts the events a console missed because its queue
	// was full.
	EventsDropped uint64
	// Quiet says whether the server is in its maintenance window.
	Quiet bool
	// BreakersOpen counts the hosts whose circuit breaker is open.
	BreakersOpen int
	// Uptime is how long the server has been running.
	Uptime time.Duration
}

// Metrics returns the counters of the server.
//
// The numbers are read in one pass over the state, so a scrape of the
// metrics endpoint does not disturb the work.
func (h *Hub) Metrics() Metrics {
	agents := h.store.Agents()
	out := Metrics{
		AgentsTotal:   len(agents),
		Transports:   map[string]int{},
		LatencyBuckets: make([]int, len(LatencyBuckets)),
	}
	for _, agent := range agents {
		if agent.State == store.StateOnline {
			out.AgentsOnline++
		}
		out.Checkins += agent.Checkins
		transport := agent.Transport
		if transport == "" {
			transport = "unknown"
		}
		out.Transports[transport]++
	}
	tasks := h.store.FilteredTasks("", "", "", 0)
	for _, t := range tasks {
		switch t.State {
		case store.TaskQueued, store.TaskDelivered:
			out.TasksPending++
		case store.TaskDone:
			out.TasksDone++
		case store.TaskFailed:
			out.TasksFailed++
		case store.TaskDead:
			out.TasksDead++
		}
		if t.State != store.TaskDone || t.Delivered.IsZero() || t.Completed.IsZero() {
			continue
		}
		latency := t.Completed.Sub(t.Delivered)
		if latency < 0 {
			continue
		}
		out.LatencyCount++
		out.LatencySum += latency.Seconds()
		for i, bound := range LatencyBuckets {
			if latency <= bound {
				out.LatencyBuckets[i]++
			}
		}
	}
	h.mu.Lock()
	out.Operators = len(h.subs)
	out.EventsDropped = h.dropped
	out.Uptime = time.Since(h.started)
	h.mu.Unlock()

	quiet, _ := h.Quiet()
	out.Quiet = quiet
	out.BytesIn, out.BytesOut = h.Bytes()

	h.qmu.Lock()
	counters := h.queue()
	if counters.policy.BreakerThreshold > 0 {
		for _, b := range counters.breakers {
			if b.failures >= counters.policy.BreakerThreshold {
				out.BreakersOpen++
			}
		}
	}
	h.qmu.Unlock()
	return out
}

// TransportNames returns the transports in a stable order, so the metrics
// of two scrapes can be compared.
func (m Metrics) TransportNames() []string {
	names := make([]string, 0, len(m.Transports))
	for name := range m.Transports {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
