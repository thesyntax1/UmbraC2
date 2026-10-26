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
	"strings"
	"sync"
	"time"
)

// Agent lifecycle states.
const (
	StateOnline  = "online"
	StateOffline = "offline"
)

// OfflineGrace is how long an agent counts as online after its last check-in.
//
// The beacon opens one connection per cycle and closes it again, so a dropped
// link does not mean a dead agent: it means the agent is sleeping.  An agent
// is online while it keeps checking in, and offline once it has been silent
// for longer than this grace period (or three of its own intervals, whichever
// is longer).
const OfflineGrace = 90 * time.Second

// agentOnline decides whether an agent counts as online.
func agentOnline(a *Agent, now time.Time) bool {
	if a.State != StateOnline {
		return false
	}
	grace := OfflineGrace
	if a.Sleep > 0 {
		if longer := time.Duration(a.Sleep*3) * time.Second; longer > grace {
			grace = longer
		}
	}
	return now.Sub(a.LastSeen) <= grace
}

// Store-level errors callers may match instead of parsing messages.
var (
	ErrNoSuchTask  = errors.New("no such task")
	ErrNoSuchAgent = errors.New("no such agent")
)

// Task lifecycle states.
const (
	TaskQueued    = "queued"
	TaskDelivered = "delivered"
	TaskDone      = "done"
	TaskFailed    = "failed"
	TaskCancelled = "cancelled"
)

// Schedule is a recurring task: "run this kind on this agent every N seconds".
//
// It lives in the store rather than in a scheduler's memory so a restart does
// not silently stop an operator's collection run.
type Schedule struct {
	ID       string         `json:"id"`
	AgentID  string         `json:"agent_id"`
	Kind     string         `json:"kind"`
	Args     map[string]any `json:"args"`
	EverySec int            `json:"every_s"`
	Enabled  bool           `json:"enabled"`
	Created  time.Time      `json:"created"`
	NextRun  time.Time      `json:"next_run"`
	Runs     uint64         `json:"runs"`
	LastTask string         `json:"last_task,omitempty"`
	CreatedBy string        `json:"created_by,omitempty"`
}

// Clone returns a copy with its own Args map.
func (s *Schedule) Clone() *Schedule {
	c := *s
	c.Args = make(map[string]any, len(s.Args))
	for k, v := range s.Args {
		c.Args[k] = v
	}
	return &c
}

// MinScheduleInterval keeps a schedule from turning into a self-inflicted DoS.
const MinScheduleInterval = 5

// MaxScheduleInterval is a day: anything longer is a typo or a job for cron.
const MaxScheduleInterval = 86400

// MaxSchedules bounds the table.
const MaxSchedules = 256

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
	// What the beacon last reported, kept apart from the cadence the
	// operator controls.  A beacon that has not applied a pushed policy yet
	// still reports its old interval; the report must not undo the policy.
	ReportedSleep  int `json:"reported_sleep,omitempty"`
	ReportedJitter int `json:"reported_jitter,omitempty"`
	// Tags are the operator's own labels for this host ("finance", "dc-01",
	// "cobalt").  They are never derived from the target: the server only
	// stores what an operator typed, and the console filters on them.
	Tags []string `json:"tags,omitempty"`
	// NoObfuscate switches the sleep obfuscation off for this agent.  The
	// zero value keeps the obfuscation on, so an agent that was registered
	// before the flag existed keeps the behaviour it had.
	NoObfuscate bool      `json:"no_obfuscate,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	State       string    `json:"state"`
	Checkins    uint64    `json:"checkins"`
}

// Clone returns a copy safe to hand to other goroutines.
func (a *Agent) Clone() *Agent {
	c := *a
	c.Tags = append([]string(nil), a.Tags...)
	return &c
}

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
	// Meta carries extra result fields the beacon attached to the RESULT body
	// (`total`, `offset`, `eof`, `sha256`, ...). They are opaque to the server,
	// which only stores and forwards them, so new beacon-side metadata never
	// needs a server change.
	Meta      map[string]any `json:"meta,omitempty"`
	// ClaimedBy is the operator who took this task, so two consoles do not
	// duplicate work on the same target.
	ClaimedBy string    `json:"claimed_by,omitempty"`
	ClaimedAt time.Time `json:"claimed_at,omitempty"`
	Created   time.Time `json:"created"`
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
	if t.Meta != nil {
		c.Meta = make(map[string]any, len(t.Meta))
		for k, v := range t.Meta {
			c.Meta[k] = v
		}
	}
	c.Output = append([]byte(nil), t.Output...)
	return &c
}

type snapshot struct {
	// Version guards against a downgrade: a file written by a newer build may
	// contain fields this one would silently drop on the next save.
	Version   int         `json:"version"`
	SavedAt   time.Time   `json:"saved_at"`
	Agents    []*Agent    `json:"agents"`
	Tasks     []*Task     `json:"tasks"`
	Schedules []*Schedule `json:"schedules,omitempty"`
}

// snapshotVersion is the layout this build writes and understands.
const snapshotVersion = 2

// backupPath is the previous generation: the snapshot that was current before
// the last successful save.
func backupPath(path string) string { return path + ".bak" }

// Store is the concurrency-safe data store.
type Store struct {
	mu     sync.RWMutex
	path   string
	agents map[string]*Agent
	tasks  map[string]*Task
	order  []string

	schedules map[string]*Schedule
	schedIDs  []string // insertion order, for stable listing

	// writeMu serialises file writes. Without it two goroutines shared one
	// "<path>.tmp" file and could rename a half-rewritten document into place.
	writeMu sync.Mutex
	// asyncMu guards the coalescing state used by SaveAsync.
	asyncMu sync.Mutex
	saving  bool
	again   bool
	done    chan struct{}
	onError func(error)
	// recovered is set when Open had to fall back to the previous generation.
	// A caller should say so loudly: the newest few seconds of state are gone.
	recovered bool
}

// Recovered reports whether this store was loaded from the backup generation
// because the primary snapshot was missing or unreadable.
func (s *Store) Recovered() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recovered
}

// SetSaveErrorHandler registers a callback for background save failures.
// Foreground saves return their error to the caller instead.
func (s *Store) SetSaveErrorHandler(fn func(error)) {
	s.asyncMu.Lock()
	s.onError = fn
	s.asyncMu.Unlock()
}

// loadSnapshot reads the current generation, falling back to the previous one.
//
// The save path rotates `state.json` to `state.json.bak` before installing the
// new file, so a crash can leave the primary missing while the backup is still
// complete. A torn or unparsable primary is handled the same way instead of
// refusing to start: losing the last few seconds of state beats losing the
// engagement history.
func loadSnapshot(path string) (*snapshot, string, error) {
	var firstErr error
	for _, candidate := range []string{path, backupPath(path)} {
		raw, err := os.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("store: read %s: %w", candidate, err)
			}
			continue
		}
		var snap snapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("store: parse %s: %w", candidate, err)
			}
			continue
		}
		if snap.Agents == nil && snap.Tasks == nil && snap.Schedules == nil && snap.Version == 0 {
			// Structurally valid JSON but not one of our snapshots (a truncated
			// `{}` from a bad restore, say). Treat it like a parse failure.
			if firstErr == nil {
				firstErr = fmt.Errorf("store: %s is not an UmbraC2 snapshot", candidate)
			}
			continue
		}
		return &snap, candidate, nil
	}
	// Neither generation was usable. If nothing exists at all, that is a fresh
	// deployment, not a failure.
	if firstErr == nil {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if _, err := os.Stat(backupPath(path)); errors.Is(err, os.ErrNotExist) {
				return &snapshot{}, "", nil
			}
		}
	}
	return nil, "", firstErr
}

// Open loads (or initialises) the store at path.
func Open(path string) (*Store, error) {
	s := &Store{
		path:      path,
		agents:    make(map[string]*Agent),
		tasks:     make(map[string]*Task),
		schedules: make(map[string]*Schedule),
	}
	if path == "" {
		return s, nil
	}
	snap, from, err := loadSnapshot(path)
	if err != nil {
		return nil, err
	}
	if from == "" {
		return s, nil // fresh deployment
	}
	if from == backupPath(path) {
		s.recovered = true
	}
	if snap.Version > snapshotVersion {
		return nil, fmt.Errorf("store: %s was written by a newer server (schema %d, this build reads %d)",
			from, snap.Version, snapshotVersion)
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
	for _, sc := range snap.Schedules {
		if sc.ID == "" {
			continue
		}
		// A schedule whose time passed while the server was down must not fire
		// a burst of catch-up runs; push the next run to the future instead.
		if sc.Enabled && sc.NextRun.Before(time.Now().UTC()) {
			sc.NextRun = time.Now().UTC().Add(time.Duration(sc.EverySec) * time.Second)
		}
		s.schedules[sc.ID] = sc
		s.schedIDs = append(s.schedIDs, sc.ID)
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
	// The cadence belongs to the operator: a beacon that still reports its
	// old interval does not overwrite the policy that was pushed to it.
	cur.ReportedSleep, cur.ReportedJitter = in.Sleep, in.Jitter
	if in.Sleep > 0 && cur.Sleep == 0 {
		cur.Sleep, cur.Jitter = in.Sleep, in.Jitter
	}
	cur.LastSeen = now
	cur.State = StateOnline
	cur.Checkins++
	return cur.Clone()
}

// MarkOffline flips an agent to offline when it has been silent for longer
// than the grace period.
//
// It reports whether the agent really went offline: a link that ends while
// the agent is still within its check-in interval is a sleeping agent, not a
// dead one.
func (s *Store) MarkOffline(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return false
	}
	if agentOnline(a, time.Now().UTC()) {
		return false
	}
	a.State = StateOffline
	return true
}

// SetPolicy updates the beacon cadence for one agent.
func (s *Store) SetPolicy(id string, sleep, jitter int) bool {
	return s.SetPolicyFull(id, sleep, jitter, nil)
}

// SetPolicyFull updates the beacon cadence and, when obfuscate is not nil,
// the sleep obfuscation flag of one agent.
//
// A nil obfuscate leaves the flag alone: a caller that only wants to change
// the interval must not silently switch the obfuscation off.
func (s *Store) SetPolicyFull(id string, sleep, jitter int, obfuscate *bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return false
	}
	a.Sleep, a.Jitter = sleep, jitter
	if obfuscate != nil {
		a.NoObfuscate = !*obfuscate
	}
	return true
}

// Tag modes for SetTags.
const (
	// TagAdd adds the listed tags.
	TagAdd = "add"
	// TagRemove removes the listed tags.
	TagRemove = "remove"
	// TagSet replaces the whole set.
	TagSet = "set"
)

// SetTags changes the tags of one agent.
//
// The mode decides what happens to the tags that are not mentioned:
// "add" keeps them, "remove" drops the listed ones, "set" replaces the whole
// set.  Tags are compared case-insensitively and stored in lower case, so
// "DC-01" and "dc-01" are the same tag.
func (s *Store) SetTags(id string, tags []string, mode string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return false
	}
	wanted := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		wanted = append(wanted, t)
	}
	switch mode {
	case TagSet:
		a.Tags = wanted
	case TagRemove:
		kept := make([]string, 0, len(a.Tags))
		for _, have := range a.Tags {
			if !containsString(wanted, have) {
				kept = append(kept, have)
			}
		}
		a.Tags = kept
	default: // TagAdd
		for _, t := range wanted {
			if !containsString(a.Tags, t) {
				a.Tags = append(a.Tags, t)
			}
		}
		sort.Strings(a.Tags)
	}
	return true
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

// HasTag reports whether the agent carries the tag.
func (a *Agent) HasTag(tag string) bool {
	return containsString(a.Tags, strings.ToLower(strings.TrimSpace(tag)))
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
//
// The state is refreshed on the way out: an agent that has not checked in
// for longer than the grace period is offline, whatever its connection
// looked like when it was last open.
func (s *Store) Agents() []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	out := make([]*Agent, 0, len(s.agents))
	for _, a := range s.agents {
		clone := a.Clone()
		if agentOnline(a, now) {
			clone.State = StateOnline
		} else {
			clone.State = StateOffline
		}
		out = append(out, clone)
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
func (s *Store) Complete(taskID string, code int64, output []byte, errMsg string, meta map[string]any) (*Task, bool) {
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
	if len(meta) > 0 {
		t.Meta = make(map[string]any, len(meta))
		for k, v := range meta {
			t.Meta[k] = v
		}
	}
	t.Completed = time.Now().UTC()
	return t.Clone(), true
}

// Claim takes ownership of a task for one operator.
//
// Claiming is advisory: it orders human work, it does not gate execution, so a
// claim never blocks the beacon. Re-claiming your own task is a no-op, and a
// finished task can no longer be claimed.
func (s *Store) Claim(taskID, by string) (*Task, error) {
	if by == "" {
		return nil, errors.New("claim needs an operator")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[taskID]
	if !ok {
		return nil, ErrNoSuchTask
	}
	switch t.State {
	case TaskDone, TaskFailed, TaskCancelled:
		return nil, fmt.Errorf("task %s is already %s", taskID, t.State)
	}
	if t.ClaimedBy != "" && t.ClaimedBy != by {
		return nil, fmt.Errorf("task %s is claimed by %s", taskID, t.ClaimedBy)
	}
	if t.ClaimedBy == "" {
		t.ClaimedBy = by
		t.ClaimedAt = time.Now().UTC()
	}
	return t.Clone(), nil
}

// Release drops a claim. Only the holder (or an admin, decided by the caller)
// may release it; releasing an unclaimed task is a no-op.
func (s *Store) Release(taskID, by string) (*Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[taskID]
	if !ok {
		return nil, ErrNoSuchTask
	}
	if t.ClaimedBy == "" {
		return t.Clone(), nil
	}
	if t.ClaimedBy != by {
		return nil, fmt.Errorf("task %s is claimed by %s", taskID, t.ClaimedBy)
	}
	t.ClaimedBy = ""
	t.ClaimedAt = time.Time{}
	return t.Clone(), nil
}

// Cancel marks a queued or delivered task as cancelled and reports the state it
// was in, so the caller can tell "it never shipped" from "the beacon may already
// be running it".
func (s *Store) Cancel(taskID string) (previous string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, found := s.tasks[taskID]
	if !found {
		return "", false
	}
	// A task that already finished cannot be cancelled; reporting success would
	// tell the operator something that is not true.
	switch t.State {
	case TaskDone, TaskFailed, TaskCancelled:
		return t.State, false
	}
	previous = t.State
	t.State = TaskCancelled
	return previous, true
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
	return s.FilteredTasks(agentID, "", "", limit)
}

// FilteredTasks returns the newest tasks that match the filters.
//
// An empty filter matches everything, so the call degrades into "the task
// history" when an operator does not narrow it down.  The tasks come back
// newest first, which is the order an operator reads them in.
func (s *Store) FilteredTasks(agentID, kind, state string, limit int) []*Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Task, 0, 16)
	for i := len(s.order) - 1; i >= 0; i-- {
		t := s.tasks[s.order[i]]
		if t == nil {
			continue
		}
		if agentID != "" && t.AgentID != agentID {
			continue
		}
		if kind != "" && t.Kind != kind {
			continue
		}
		if state != "" && t.State != state {
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
	now := time.Now().UTC()
	for _, a := range s.agents {
		if agentOnline(a, now) {
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
	snap := snapshot{
		Version:   snapshotVersion,
		SavedAt:   time.Now().UTC(),
		Agents:    make([]*Agent, 0, len(s.agents)),
		Tasks:     make([]*Task, 0, len(s.order)),
		Schedules: make([]*Schedule, 0, len(s.schedIDs)),
	}
	for _, a := range s.agents {
		snap.Agents = append(snap.Agents, a.Clone())
	}
	for _, id := range s.order {
		if t := s.tasks[id]; t != nil {
			snap.Tasks = append(snap.Tasks, t.Clone())
		}
	}
	for _, id := range s.schedIDs {
		if sc := s.schedules[id]; sc != nil {
			snap.Schedules = append(snap.Schedules, sc.Clone())
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
	// Keep the generation we are about to replace. If the machine dies between
	// this rename and the next one, Open falls back to the backup instead of
	// starting empty.
	if _, statErr := os.Stat(s.path); statErr == nil {
		if err := os.Rename(s.path, backupPath(s.path)); err != nil {
			_ = os.Remove(tmp)
			return err
		}
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
	s.mu.Lock()
	s.recovered = false
	s.mu.Unlock()
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

// AddSchedule stores a schedule and returns a copy.
func (s *Store) AddSchedule(sc *Schedule) (*Schedule, error) {
	if sc.AgentID == "" || sc.Kind == "" {
		return nil, errors.New("store: schedule needs an agent and a kind")
	}
	if sc.EverySec < MinScheduleInterval || sc.EverySec > MaxScheduleInterval {
		return nil, fmt.Errorf("store: schedule interval must be %d..%d seconds",
			MinScheduleInterval, MaxScheduleInterval)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.schedIDs) >= MaxSchedules {
		return nil, errors.New("store: too many schedules")
	}
	now := time.Now().UTC()
	if sc.ID == "" {
		sc.ID = NewID("s")
	}
	sc.Created = now
	sc.Enabled = true
	sc.NextRun = now.Add(time.Duration(sc.EverySec) * time.Second)
	if sc.Args == nil {
		sc.Args = map[string]any{}
	}
	s.schedules[sc.ID] = sc
	s.schedIDs = append(s.schedIDs, sc.ID)
	return sc.Clone(), nil
}

// Schedules returns every schedule in creation order.
func (s *Store) Schedules() []*Schedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Schedule, 0, len(s.schedIDs))
	for _, id := range s.schedIDs {
		if sc := s.schedules[id]; sc != nil {
			out = append(out, sc.Clone())
		}
	}
	return out
}

// Schedule returns one schedule by id.
func (s *Store) Schedule(id string) (*Schedule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.schedules[id]
	if !ok {
		return nil, false
	}
	return sc.Clone(), true
}

// RemoveSchedule deletes a schedule.
func (s *Store) RemoveSchedule(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.schedules[id]; !ok {
		return false
	}
	delete(s.schedules, id)
	for i, existing := range s.schedIDs {
		if existing == id {
			s.schedIDs = append(s.schedIDs[:i], s.schedIDs[i+1:]...)
			break
		}
	}
	return true
}

// DueSchedules advances every schedule whose time has come and returns them.
//
// Advancing NextRun rather than the caller doing it means a slow tick can never
// cause the same schedule to fire twice, and a schedule that is minutes late
// (a paused server, a long GC) fires once instead of N times.
func (s *Store) DueSchedules(now time.Time) []*Schedule {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Schedule
	for _, id := range s.schedIDs {
		sc := s.schedules[id]
		if sc == nil || !sc.Enabled || sc.NextRun.After(now) {
			continue
		}
		sc.NextRun = now.Add(time.Duration(sc.EverySec) * time.Second)
		sc.Runs++
		out = append(out, sc.Clone())
	}
	return out
}

// MarkScheduleRan records the task id a schedule produced.
func (s *Store) MarkScheduleRan(id, taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sc := s.schedules[id]; sc != nil {
		sc.LastTask = taskID
	}
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
