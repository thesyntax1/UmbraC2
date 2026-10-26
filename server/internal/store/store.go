// Package store keeps agent metadata and the task queue.
//
// Everything lives in memory and is snapshotted to a JSON file so an operator
// can restart the team server without losing the engagement history. Writes are
// serialised and atomic (temp file + rename).
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Agent lifecycle states.
const (
	StateOnline  = "online"
	StateOffline = "offline"
)

// Task lifecycle states.
const (
	TaskQueued    = "queued"
	TaskDelivered = "delivered"
	TaskDone      = "done"
	TaskFailed    = "failed"
	TaskCancelled = "cancelled"
)

// MaxTasks bounds the in-memory history.
const MaxTasks = 20000

// Agent is the persisted view of a beacon.
type Agent struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	User      string    `json:"user"`
	PID       int64     `json:"pid"`
	Version   string    `json:"version"`
	Integrity string    `json:"integrity,omitempty"`
	Transport string    `json:"transport"`
	Addr      string    `json:"addr"`
	Sleep     int       `json:"sleep"`
	Jitter    int       `json:"jitter"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	State     string    `json:"state"`
	Checkins  uint64    `json:"checkins"`
}

// Clone returns a copy safe to hand to other goroutines.
func (a *Agent) Clone() *Agent { c := *a; return &c }

// Task is one queued or completed command.
type Task struct {
	ID        string         `json:"id"`
	AgentID   string         `json:"agent_id"`
	Kind      string         `json:"kind"`
	Args      map[string]any `json:"args"`
	State     string         `json:"state"`
	Output    []byte         `json:"output,omitempty"`
	Code      int64          `json:"code"`
	Err       string         `json:"err,omitempty"`
	Created   time.Time      `json:"created"`
	Delivered time.Time      `json:"delivered,omitempty"`
	Completed time.Time      `json:"completed,omitempty"`
}

// Clone returns a copy with its own Args map.
func (t *Task) Clone() *Task {
	c := *t
	c.Args = make(map[string]any, len(t.Args))
	for k, v := range t.Args {
		c.Args[k] = v
	}
	c.Output = append([]byte(nil), t.Output...)
	return &c
}

type snapshot struct {
	Agents []*Agent `json:"agents"`
	Tasks  []*Task  `json:"tasks"`
}

// Store is the concurrency-safe data store.
type Store struct {
	mu     sync.RWMutex
	path   string
	agents map[string]*Agent
	tasks  map[string]*Task
	order  []string

	// writeMu serialises file writes. Without it two goroutines shared one
	// "<path>.tmp" file and could rename a half-rewritten document into place.
	writeMu sync.Mutex
	// asyncMu guards the coalescing state used by SaveAsync.
	asyncMu sync.Mutex
	saving  bool
	again   bool
	done    chan struct{}
	onError func(error)
}

// SetSaveErrorHandler registers a callback for background save failures.
// Foreground saves return their error to the caller instead.
func (s *Store) SetSaveErrorHandler(fn func(error)) {
	s.asyncMu.Lock()
	s.onError = fn
	s.asyncMu.Unlock()
}

// Open loads (or initialises) the store at path.
func Open(path string) (*Store, error) {
	s := &Store{
		path:   path,
		agents: make(map[string]*Agent),
		tasks:  make(map[string]*Task),
	}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", path, err)
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, fmt.Errorf("store: parse %s: %w", path, err)
	}
	for _, a := range snap.Agents {
		a.State = StateOffline // nothing is online until it checks in again
		s.agents[a.ID] = a
	}
	for _, t := range snap.Tasks {
		s.tasks[t.ID] = t
		s.order = append(s.order, t.ID)
		if t.State == TaskDelivered {
			t.State = TaskQueued // the agent may never have executed it
		}
	}
	return s, nil
}

// UpsertAgent inserts or updates an agent record from a check-in.
func (s *Store) UpsertAgent(in *Agent) *Agent {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	cur, ok := s.agents[in.ID]
	if !ok {
		in.FirstSeen = now
		in.LastSeen = now
		in.State = StateOnline
		s.agents[in.ID] = in
		return in.Clone()
	}
	cur.Host, cur.OS, cur.Arch = in.Host, in.OS, in.Arch
	cur.User, cur.PID, cur.Version = in.User, in.PID, in.Version
	cur.Transport, cur.Addr, cur.Integrity = in.Transport, in.Addr, in.Integrity
	if in.Sleep > 0 {
		cur.Sleep, cur.Jitter = in.Sleep, in.Jitter
	}
	cur.LastSeen = now
	cur.State = StateOnline
	cur.Checkins++
	return cur.Clone()
}

// MarkOffline flips an agent to offline (called when its connection ends).
func (s *Store) MarkOffline(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[id]; ok {
		a.State = StateOffline
	}
}

// SetPolicy updates the beacon cadence for one agent.
func (s *Store) SetPolicy(id string, sleep, jitter int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return false
	}
	a.Sleep, a.Jitter = sleep, jitter
	return true
}

// Agent returns a copy of one agent record.
func (s *Store) Agent(id string) (*Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, false
	}
	return a.Clone(), true
}

// Agents returns all agents, most recently seen first.
func (s *Store) Agents() []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Agent, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, a.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// AddTask queues a task, preserving caller-supplied args.
func (s *Store) AddTask(t *Task) *Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.ID == "" {
		t.ID = NewID("t")
	}
	if t.State == "" {
		t.State = TaskQueued
	}
	t.Created = time.Now().UTC()
	if t.Args == nil {
		t.Args = map[string]any{}
	}
	s.tasks[t.ID] = t
	s.order = append(s.order, t.ID)
	s.pruneLocked()
	return t.Clone()
}

// Pending marks all queued tasks of an agent as delivered and returns them.
func (s *Store) Pending(agentID string, max int) []*Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Task, 0, 4)
	for _, id := range s.order {
		if len(out) >= max {
			break
		}
		t := s.tasks[id]
		if t.AgentID != agentID || t.State != TaskQueued {
			continue
		}
		t.State = TaskDelivered
		t.Delivered = time.Now().UTC()
		out = append(out, t.Clone())
	}
	return out
}

// Complete records a task result.
//
// A result that arrives after the task was cancelled keeps the cancelled state:
// the operator wanted it stopped and the beacon ran it anyway (the beacon can
// only be interrupted between cycles). Overwriting that with "done" would hide
// both the cancellation and the fact that the command actually executed -- the
// output is still stored, because it is evidence either way.
func (s *Store) Complete(taskID string, code int64, output []byte, errMsg string) (*Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[taskID]
	if !ok {
		return nil, false
	}
	cancelled := t.State == TaskCancelled
	if !cancelled {
		t.State = TaskDone
		if code != 0 || errMsg != "" {
			t.State = TaskFailed
		}
	}
	t.Code = code
	t.Output = append([]byte(nil), output...)
	t.Err = errMsg
	t.Completed = time.Now().UTC()
	return t.Clone(), true
}

// Cancel marks a queued or delivered task as cancelled.
func (s *Store) Cancel(taskID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[taskID]
	if !ok {
		return false
	}
	// A task that already finished cannot be cancelled; reporting success would
	// tell the operator something that is not true.
	if t.State == TaskDone || t.State == TaskFailed || t.State == TaskCancelled {
		return false
	}
	t.State = TaskCancelled
	return true
}

// Task returns a copy of one task.
func (s *Store) Task(id string) (*Task, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[id]
	if !ok {
		return nil, false
	}
	return t.Clone(), true
}

// AgentTasks returns the newest tasks of one agent (limit <= 0 means all).
func (s *Store) AgentTasks(agentID string, limit int) []*Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Task, 0, 16)
	for i := len(s.order) - 1; i >= 0; i-- {
		t := s.tasks[s.order[i]]
		if t == nil || t.AgentID != agentID {
			continue
		}
		out = append(out, t.Clone())
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Stats returns counters for the operator dashboard.
func (s *Store) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	online, queued, done := 0, 0, 0
	for _, a := range s.agents {
		if a.State == StateOnline {
			online++
		}
	}
	for _, t := range s.tasks {
		switch t.State {
		case TaskQueued, TaskDelivered:
			queued++
		case TaskDone, TaskFailed:
			done++
		}
	}
	return map[string]any{
		"agents_total":  len(s.agents),
		"agents_online": online,
		"tasks_total":   len(s.tasks),
		"tasks_pending": queued,
		"tasks_done":    done,
	}
}

// Save writes a consistent snapshot of the store to disk.
//
// Writes are serialised and each one goes to a fresh temporary file that is
// fsynced and renamed over the target, so a reader (or a crash) never observes
// a partially written JSON document.
func (s *Store) Save() error {
	if s.path == "" {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.RLock()
	snap := snapshot{Agents: make([]*Agent, 0, len(s.agents)), Tasks: make([]*Task, 0, len(s.order))}
	for _, a := range s.agents {
		snap.Agents = append(snap.Agents, a.Clone())
	}
	for _, id := range s.order {
		if t := s.tasks[id]; t != nil {
			snap.Tasks = append(snap.Tasks, t.Clone())
		}
	}
	s.mu.RUnlock()

	raw, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".umbra-store-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	discard := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if _, err := f.Write(raw); err != nil {
		discard()
		return err
	}
	if err := f.Sync(); err != nil {
		discard()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Best effort: make the rename itself durable. Directory fsync is not
	// supported on every platform, so a failure here is not fatal.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// SaveAsync persists in the background and coalesces bursts: while a save is
// running, later requests only set a flag, so a hundred task events cost two
// marshals instead of a hundred.
func (s *Store) SaveAsync() {
	if s.path == "" {
		return
	}
	s.asyncMu.Lock()
	if s.saving {
		s.again = true
		s.asyncMu.Unlock()
		return
	}
	done := make(chan struct{})
	s.saving = true
	s.done = done
	s.asyncMu.Unlock()

	go func() {
		defer close(done)
		for {
			err := s.Save()
			s.asyncMu.Lock()
			handler := s.onError
			if !s.again {
				s.saving = false
				s.done = nil
				s.asyncMu.Unlock()
				if err != nil && handler != nil {
					handler(err)
				}
				return
			}
			s.again = false
			s.asyncMu.Unlock()
			if err != nil && handler != nil {
				handler(err)
			}
		}
	}()
}

// Flush waits for the background writer and then writes a final snapshot, so
// a caller that is about to exit cannot lose a queued save.
func (s *Store) Flush() error {
	for {
		s.asyncMu.Lock()
		waiter := s.done
		s.asyncMu.Unlock()
		if waiter == nil {
			break
		}
		<-waiter
	}
	return s.Save()
}

func (s *Store) pruneLocked() {
	if len(s.order) <= MaxTasks {
		return
	}
	keep := make([]string, 0, len(s.order))
	for _, id := range s.order {
		t := s.tasks[id]
		if t == nil {
			continue
		}
		drop := t.State == TaskDone || t.State == TaskFailed || t.State == TaskCancelled
		if drop && len(s.order)-len(keep) > MaxTasks {
			delete(s.tasks, id)
			continue
		}
		keep = append(keep, id)
	}
	s.order = keep
}

// NewID returns a short random identifier such as "t-9f3c1a2b".
func NewID(prefix string) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return prefix + "-" + fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	}
	return prefix + "-" + hex.EncodeToString(b)
}
