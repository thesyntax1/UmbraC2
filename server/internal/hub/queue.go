package hub

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// QueuePolicy is how the server hands work out.
//
// The queue is the part of a C2 that decides what happens when there is
// more work than the hosts can take.  A predictable queue is worth more
// than a fast one: an operator who knows that the urgent task goes first,
// that a slow host does not hold the queue, and that a task which keeps
// failing ends up in the dead letter queue instead of being retried
// forever, can trust the server.
type QueuePolicy struct {
	// MaxInFlightPerAgent is how many tasks may run on one host.
	MaxInFlightPerAgent int `json:"max_in_flight_per_agent"`
	// MaxDeliverPerMinutePerAgent is the rate one host receives work at.
	MaxDeliverPerMinutePerAgent int `json:"max_deliver_per_minute_per_agent"`
	// MaxDeliverPerSecond is the throughput of the whole server.
	MaxDeliverPerSecond int `json:"max_deliver_per_second"`
	// MaxAttempts is how many times a task may be delivered.
	MaxAttempts int `json:"max_attempts"`
	// BreakerThreshold is how many failures in a row open the breaker of
	// a host.
	BreakerThreshold int `json:"breaker_threshold"`
	// BreakerCooldown is how long the breaker stays open.
	BreakerCooldown time.Duration `json:"-"`
	// BreakerCooldownSec is the cooldown in seconds, which is the unit
	// the configuration and the console use.
	BreakerCooldownSec int `json:"breaker_cooldown_s"`
}

// defaultQueuePolicy is the policy of a server that was not told otherwise.
func defaultQueuePolicy() QueuePolicy {
	return QueuePolicy{
		MaxInFlightPerAgent:         config.DefaultMaxInFlightPerAgent,
		MaxDeliverPerMinutePerAgent: config.DefaultMaxDeliverPerMinutePerAgent,
		MaxDeliverPerSecond:         config.DefaultMaxDeliverPerSecond,
		MaxAttempts:                 config.DefaultMaxAttempts,
		BreakerThreshold:            config.DefaultBreakerThreshold,
		BreakerCooldown:             time.Duration(config.DefaultBreakerCooldownSec) * time.Second,
		BreakerCooldownSec:          config.DefaultBreakerCooldownSec,
	}
}

// QueuePolicyFromConfig reads the policy out of the configuration.
func QueuePolicyFromConfig(c *config.Config) QueuePolicy {
	policy := defaultQueuePolicy()
	if c == nil {
		return policy
	}
	q := c.Server.Queue
	if q.MaxInFlightPerAgent > 0 {
		policy.MaxInFlightPerAgent = q.MaxInFlightPerAgent
	}
	if q.MaxDeliverPerMinutePerAgent > 0 {
		policy.MaxDeliverPerMinutePerAgent = q.MaxDeliverPerMinutePerAgent
	}
	if q.MaxDeliverPerSecond > 0 {
		policy.MaxDeliverPerSecond = q.MaxDeliverPerSecond
	}
	if q.MaxAttempts > 0 {
		policy.MaxAttempts = q.MaxAttempts
	}
	if q.BreakerThreshold > 0 {
		policy.BreakerThreshold = q.BreakerThreshold
	}
	if q.BreakerCooldownSec > 0 {
		policy.BreakerCooldown = time.Duration(q.BreakerCooldownSec) * time.Second
		policy.BreakerCooldownSec = q.BreakerCooldownSec
	}
	return policy
}

// The counters of the queue.
//
// The lock is the one of the hub (hub.qmu): the counters are never read
// or written without it.
type queueCounters struct {
	// policy is the policy in force.
	policy QueuePolicy
	// perAgent counts the deliveries of the last minute, per agent.
	perAgent map[string]int
	// minute is the minute those counters belong to.
	minute int64
	// global counts the deliveries of the last second.
	global int
	// second is the second those counters belong to.
	second int64
	// breakers holds the circuit breaker of every host that failed.
	breakers map[string]*breaker
	// holds are the pauses the operators put on the queues of single
	// hosts: the work stays queued and the host is not asked for it.
	holds map[string]Hold
	// quiet stops the traffic while it is on.
	quiet bool
	// quietUntil is when the quiet mode ends by itself.
	quietUntil time.Time
	// bytesIn and bytesOut are the bytes that moved through the server.
	bytesIn  int64
	bytesOut int64
}

// breaker is the circuit breaker of one host.
//
// A host that does not answer is not a host that needs more work: the
// breaker opens after a few failures in a row, the server stops handing
// work to it, and one probe is let through after the cooldown.
type breaker struct {
	// failures counts the failures in a row.
	failures int
	// openedAt is when the breaker opened.
	openedAt time.Time
	// probing says a probe was let through and the answer is awaited.
	probing bool
}

// SetQueuePolicy replaces the policy of the queue.
func (h *Hub) SetQueuePolicy(policy QueuePolicy) {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	h.queue().policy = policy
}

// QueuePolicy returns the policy of the queue.
func (h *Hub) QueuePolicy() QueuePolicy {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	return h.queue().policy
}

// queue returns the counters of the queue, creating them once.
//
// The caller holds the lock of the queue: the counters are the state of
// the hub, and two callers must not see two different queues.
func (h *Hub) queue() *queueCounters {
	if h.counters == nil {
		h.counters = &queueCounters{
			policy:   defaultQueuePolicy(),
			perAgent: map[string]int{},
			breakers: map[string]*breaker{},
			holds:    map[string]Hold{},
		}
	}
	return h.counters
}

// Hold is the pause an operator puts on the queue of one host.
//
// A hold is not a punishment and not a failure state: it is the hand of an
// operator on one queue.  The work of the host keeps queueing up, nothing is
// delivered until the hold lifts, and a hold may carry an end of its own so a
// forgotten pause cannot last for ever.  The quiet window stops the whole
// fleet; a hold stops one host, and that difference is the whole point of it.
type Hold struct {
	AgentID string    `json:"agent"`
	By      string    `json:"by"`
	Reason  string    `json:"reason,omitempty"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until,omitempty"`
}

// SetHold puts a hold on the queue of one host.
//
// The caller decides who holds the queue and until when; a zero `until`
// means the hold stands until it is lifted by hand.  A second hold on the
// same host replaces the first and keeps its author honest: the line that
// lifts it later names the operator who put it there.
func (h *Hub) SetHold(agentID, by, reason string, until time.Time) Hold {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	if counters.holds == nil {
		counters.holds = map[string]Hold{}
	}
	hold := Hold{
		AgentID: agentID,
		By:      strings.TrimSpace(by),
		Reason:  strings.TrimSpace(reason),
		Since:   time.Now().UTC(),
		Until:   until.UTC(),
	}
	counters.holds[agentID] = hold
	return hold
}

// ReleaseHold lifts the hold of a host and says whether there was one.
func (h *Hub) ReleaseHold(agentID string) (Hold, bool) {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	hold, ok := counters.holds[agentID]
	if ok {
		delete(counters.holds, agentID)
	}
	return hold, ok
}

// HoldOf is the hold of a host, if the host is held at all.
func (h *Hub) HoldOf(agentID string) (Hold, bool) {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	hold, ok := h.queue().holds[agentID]
	return hold, ok
}

// Holds is every hold of the fleet, oldest first.
func (h *Hub) Holds() []Hold {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	out := make([]Hold, 0, len(counters.holds))
	for _, hold := range counters.holds {
		out = append(out, hold)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Since.Equal(out[j].Since) {
			return out[i].AgentID < out[j].AgentID
		}
		return out[i].Since.Before(out[j].Since)
	})
	return out
}

// Held says whether the queue of a host is held right now.
//
// A hold whose end has passed is not a hold: the sweep of the server will
// say so to the team, but the queue does not wait for the sweep to resume.
func (h *Hub) Held(agentID string) bool {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	hold, ok := h.queue().holds[agentID]
	if !ok {
		return false
	}
	if hold.Until.IsZero() {
		return true
	}
	return time.Now().Before(hold.Until)
}

// SweepHolds lifts every hold whose end has passed and returns them, so the
// server can tell the team that the hand of an operator let go.
func (h *Hub) SweepHolds(now time.Time) []Hold {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	var out []Hold
	for agentID, hold := range counters.holds {
		if hold.Until.IsZero() || now.Before(hold.Until) {
			continue
		}
		delete(counters.holds, agentID)
		out = append(out, hold)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

// allowDelivery says whether a task may be handed to an agent right now.
//
// The three limits are checked in the order that hurts least: the work in
// flight first (a host that is busy is not helped by more work), then the
// rate of the host, then the throughput of the server.
func (h *Hub) allowDelivery(agentID string) bool {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	policy := counters.policy
	if policy.MaxInFlightPerAgent > 0 {
		if h.store.InFlight(agentID) >= policy.MaxInFlightPerAgent {
			return false
		}
	}
	now := time.Now()
	minute := now.Unix() / 60
	if counters.minute != minute {
		counters.minute = minute
		counters.perAgent = map[string]int{}
	}
	if policy.MaxDeliverPerMinutePerAgent > 0 &&
		counters.perAgent[agentID] >= policy.MaxDeliverPerMinutePerAgent {
		return false
	}
	second := now.Unix()
	if counters.second != second {
		counters.second = second
		counters.global = 0
	}
	if policy.MaxDeliverPerSecond > 0 && counters.global >= policy.MaxDeliverPerSecond {
		return false
	}
	return true
}

// noteDelivery counts a delivery.
func (h *Hub) noteDelivery(agentID string, n int) {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	now := time.Now()
	minute := now.Unix() / 60
	if counters.minute != minute {
		counters.minute = minute
		counters.perAgent = map[string]int{}
	}
	counters.perAgent[agentID] += n
	second := now.Unix()
	if counters.second != second {
		counters.second = second
		counters.global = 0
	}
	counters.global += n
}

// BreakerOpen says whether the circuit breaker of a host is open.
//
// An open breaker means the server does not hand work to that host: it
// failed too many times in a row.  After the cooldown one probe is let
// through, and the answer of the probe decides whether the breaker stays
// open.
func (h *Hub) BreakerOpen(agentID string) bool {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	b, ok := counters.breakers[agentID]
	if !ok || counters.policy.BreakerThreshold <= 0 ||
		b.failures < counters.policy.BreakerThreshold {
		return false
	}
	if time.Since(b.openedAt) < counters.policy.BreakerCooldown {
		return true
	}
	if b.probing {
		return true
	}
	// The cooldown is over: one probe goes through.
	b.probing = true
	return false
}

// NoteFailure counts a failure of a host.
//
// A failure is a task that did not come back, or a host that stopped
// answering.  Enough of them in a row open the breaker.
func (h *Hub) NoteFailure(agentID string) {
	if agentID == "" {
		return
	}
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	b, ok := counters.breakers[agentID]
	if !ok {
		b = &breaker{}
		counters.breakers[agentID] = b
	}
	b.failures++
	b.probing = false
	if counters.policy.BreakerThreshold <= 0 {
		return
	}
	if b.failures >= counters.policy.BreakerThreshold {
		if b.openedAt.IsZero() {
			h.log.Warn("the circuit breaker of a host opened",
				"agent", agentID, "failures", b.failures)
		}
		// The cooldown starts again with every failure: a host that
		// keeps failing is given a probe per cooldown, not per
		// failure.
		b.openedAt = time.Now()
	}
}

// NoteSuccess clears the failures of a host.
func (h *Hub) NoteSuccess(agentID string) {
	if agentID == "" {
		return
	}
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	if b, ok := counters.breakers[agentID]; ok {
		b.failures = 0
		b.probing = false
		b.openedAt = time.Time{}
	}
}

// NoteBytes counts the bytes that moved through the server.
func (h *Hub) NoteBytes(in, out int64) {
	if in == 0 && out == 0 {
		return
	}
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	counters.bytesIn += in
	counters.bytesOut += out
}

// Bytes returns the bytes that moved through the server.
func (h *Hub) Bytes() (int64, int64) {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	return counters.bytesIn, counters.bytesOut
}

// BreakerState returns the state of the breaker of a host, for the
// operator and for the metrics.
func (h *Hub) BreakerState(agentID string) (open bool, failures int) {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	b, ok := counters.breakers[agentID]
	if !ok || counters.policy.BreakerThreshold <= 0 {
		return false, 0
	}
	return b.failures >= counters.policy.BreakerThreshold, b.failures
}

// SetQuiet stops the traffic of the server.
//
// The quiet mode is the maintenance window: the agents keep checking in,
// but no work is handed out and nothing new is queued.  The window may
// end by itself at a given moment.
func (h *Hub) SetQuiet(on bool, until time.Time) {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	counters.quiet = on
	counters.quietUntil = until
	if on {
		h.log.Warn("the server went quiet", "until", until)
	} else {
		h.log.Info("the server is loud again")
	}
}

// Quiet says whether the server is in its maintenance window.
func (h *Hub) Quiet() (bool, time.Time) {
	h.qmu.Lock()
	defer h.qmu.Unlock()
	counters := h.queue()
	if counters.quiet && !counters.quietUntil.IsZero() && time.Now().After(counters.quietUntil) {
		counters.quiet = false
		counters.quietUntil = time.Time{}
	}
	return counters.quiet, counters.quietUntil
}

// ErrQuiet is returned when the server is in its maintenance window.
var ErrQuiet = errors.New("hub: the server is in its quiet window")

// NewTraceID returns the id that follows a task from the RPC to the result.
//
// The trace is short, random and local: it is a handle for the operator
// to grep with, not a secret and not a global identifier.
func NewTraceID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// The clock is a poor trace id, but it is better than nothing.
		return fmt.Sprintf("t%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

// DeadLetter moves a task that keeps failing into the dead letter queue.
//
// The task is not run again: a task that may have run must not run twice
// without a decision.  It stays visible, with the reason, until the
// operator looks at it.
func (h *Hub) DeadLetter(t *store.Task, reason string) bool {
	if t == nil {
		return false
	}
	policy := h.QueuePolicy()
	if policy.MaxAttempts <= 0 || t.Attempts < policy.MaxAttempts {
		return false
	}
	return h.ParkTask(t, reason)
}

// ParkTask puts a task in the dead letter queue.
//
// A parked task is not run again without a decision: a task that may have
// run must not run a second time.  The reason is in the record and in the
// event, so the operator knows why the task stopped.
func (h *Hub) ParkTask(t *store.Task, reason string) bool {
	if t == nil {
		return false
	}
	if !h.store.DeadLetter(t.ID, reason) {
		return false
	}
	h.store.SaveAsync()
	h.Emit(Event{Kind: "task.dead", AgentID: t.AgentID, TaskID: t.ID,
		From: t.ClaimedBy,
		Data: map[string]any{
			"kind":     t.Kind,
			"attempts": int64(t.Attempts),
			"reason":   reason,
			"trace":    t.TraceID,
		}})
	return true
}
