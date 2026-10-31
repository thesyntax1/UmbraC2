// Package approval is the two-person rule of the engagement.
//
// A destructive operation -- the wipe of a host, the end of an
// engagement, the removal of the persistence -- is not run on the word
// of one operator.  It needs a second one.  The operator who wants it
// writes a request, another operator decides, and the decision does
// the work: the approved request becomes the task that is queued on the
// host.
//
// The rule is a policy of the deployment and not a law of the
// framework: the server carries the queue and the rule, and the
// configuration says which operations need it.  A team of one turns the
// rule off and the queue is still there, waiting.
//
// Three things are always true:
//
//   - the operator who asked for an operation cannot decide it: the
//     second pair of eyes has to be another pair of eyes;
//   - a request that nobody decided goes stale: it expires, and an
//     expired request decides nothing;
//   - the decision is written down: who asked, who decided, when, and
//     what was asked for.
package approval

import (
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

// Limits.
//
// The queue is a queue of people waiting for each other, so it is
// small: a hundred open requests is already a team that does not talk
// to itself.
const (
	// MaxRequests bounds the queue.
	MaxRequests = 512
	// MaxNoteLen bounds the reason of a request and the note of a
	// decision.
	MaxNoteLen = 1024
	// MaxArgs bounds the number of the arguments of a request.
	MaxArgs = 32
	// DefaultTTL is how long a request waits for a decision.
	DefaultTTL = 30 * time.Minute
	// MaxTTL is the longest life a request may be given.
	MaxTTL = 24 * time.Hour
)

// The states of a request.
const (
	// StatePending is a request that waits for a decision.
	StatePending = "pending"
	// StateApproved is a request that was approved.
	StateApproved = "approved"
	// StateDenied is a request that was refused.
	StateDenied = "denied"
	// StateExpired is a request that nobody decided in time.
	StateExpired = "expired"
)

// Errors of the package.
var (
	// ErrNoSuchRequest is the answer for a request nobody made.
	ErrNoSuchRequest = errors.New("approval: no such request")
	// ErrOwnRequest is the answer when the operator who asked for the
	// operation tries to decide it.
	ErrOwnRequest = errors.New("approval: the operator who asked for it cannot decide it")
	// ErrNotPending is the answer when a request was already decided.
	ErrNotPending = errors.New("approval: the request was already decided")
	// ErrNoKind is the answer when a request names no operation.
	ErrNoKind = errors.New("approval: a request needs the kind of the operation")
	// ErrNoOperator is the answer when nobody is named.
	ErrNoOperator = errors.New("approval: a request needs the name of the operator")
)

// Request is one operation that waits for a second pair of eyes.
//
// The request carries the task kind and the arguments of the operation,
// so the decision does the same thing the requester meant and not
// something that merely sounds like it.
type Request struct {
	// ID is the short name the operator types: "a-3f7a".
	ID string `json:"id"`
	// Kind is the task kind of the operation: "forensics.wipe", ...
	Kind string `json:"kind"`
	// AgentID is the host the operation is about.
	AgentID string `json:"agent_id,omitempty"`
	// Args are the arguments of the operation.
	Args map[string]any `json:"args,omitempty"`
	// Reason says why the operation is wanted: the ticket, the word of
	// the customer, the end of the engagement.
	Reason string `json:"reason,omitempty"`
	// RequestedBy is the operator who asked for it.
	RequestedBy string `json:"requested_by"`
	// RequestedAt is when it was asked for.
	RequestedAt time.Time `json:"requested_at"`
	// State is "pending", "approved", "denied" or "expired".
	State string `json:"state"`
	// DecidedBy is the operator who decided it.
	DecidedBy string `json:"decided_by,omitempty"`
	// DecidedAt is when it was decided.
	DecidedAt time.Time `json:"decided_at,omitempty"`
	// Note is what the decider wrote.
	Note string `json:"note,omitempty"`
	// ExpiresAt is when the request goes stale.
	ExpiresAt time.Time `json:"expires_at"`
}

// Clone returns a copy with its own argument map.
func (r Request) Clone() Request {
	c := r
	c.Args = make(map[string]any, len(r.Args))
	for k, v := range r.Args {
		c.Args[k] = v
	}
	return c
}

// Pending says whether the request still waits for a decision.
func (r Request) Pending() bool { return r.State == StatePending }

// Queue holds the requests of one deployment.
type Queue struct {
	mu   sync.RWMutex
	byID map[string]Request
	seq  int
	// path is where the queue is kept between two runs of the server.
	// The queue is shared by the team: the request of one operator is
	// the request of the others.
	path string
	// ttl is how long a request waits for a decision.
	ttl time.Duration
}

// New creates an empty queue.
func New() *Queue {
	return &Queue{byID: make(map[string]Request), ttl: DefaultTTL}
}

// SetPath tells the queue where to keep itself.
func (q *Queue) SetPath(path string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.path = path
}

// Path is where the queue is kept, empty when it is not kept.
func (q *Queue) Path() string {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.path
}

// SetTTL tells the queue how long a request waits.
//
// A ttl of zero is the default: a request that nobody decides goes
// stale, and a queue where nothing goes stale is a queue of ghosts.
func (q *Queue) SetTTL(ttl time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if ttl <= 0 || ttl > MaxTTL {
		ttl = DefaultTTL
	}
	q.ttl = ttl
}

// TTL is how long a request waits for a decision.
func (q *Queue) TTL() time.Duration {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.ttl
}

// Load reads the queue back.
//
// A file that cannot be read is reported and not swallowed: the
// operator has to know that the requests of yesterday are gone.
func (q *Queue) Load() error {
	q.mu.RLock()
	path := q.path
	q.mu.RUnlock()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("approval: read %s: %w", path, err)
	}
	var file queueFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("approval: parse %s: %w", path, err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.byID = make(map[string]Request, len(file.Requests))
	for _, req := range file.Requests {
		if req.ID == "" {
			continue
		}
		q.byID[req.ID] = req
	}
	q.seq = file.Seq
	return nil
}

// queueFile is what the queue looks like on the disk.
type queueFile struct {
	Version  int       `json:"version"`
	Seq      int       `json:"seq"`
	SavedAt  time.Time `json:"saved_at"`
	Requests []Request `json:"requests"`
}

// Save writes the queue to the disk.
//
// The file is written to a temporary name and renamed into place, so a
// crash never leaves a queue that is half written.
func (q *Queue) Save() error {
	q.mu.RLock()
	path := q.path
	list := make([]Request, 0, len(q.byID))
	for _, req := range q.byID {
		list = append(list, req.Clone())
	}
	seq := q.seq
	q.mu.RUnlock()
	if path == "" {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, err := json.MarshalIndent(queueFile{
		Version:  1,
		Seq:      seq,
		SavedAt:  time.Now().UTC(),
		Requests: list,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("approval: encode the queue: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("approval: create %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("approval: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("approval: save the queue: %w", err)
	}
	return nil
}

// Request puts an operation into the queue.
//
// The requester is named, the clock is set and the request waits.  The
// queue is bounded: a queue of a thousand open requests is a queue
// nobody reads.
func (q *Queue) Request(req Request) (Request, error) {
	req.Kind = strings.TrimSpace(req.Kind)
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.RequestedBy = strings.TrimSpace(req.RequestedBy)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Kind == "" {
		return Request{}, ErrNoKind
	}
	if req.RequestedBy == "" {
		return Request{}, ErrNoOperator
	}
	if len(req.Reason) > MaxNoteLen {
		return Request{}, fmt.Errorf("approval: the reason is longer than %d characters", MaxNoteLen)
	}
	if len(req.Args) > MaxArgs {
		return Request{}, fmt.Errorf("approval: a request carries at most %d arguments", MaxArgs)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	open := 0
	for _, existing := range q.byID {
		if existing.Pending() {
			open++
		}
	}
	if open >= MaxRequests {
		return Request{}, fmt.Errorf("approval: there are at most %d open requests", MaxRequests)
	}
	now := time.Now().UTC()
	q.seq++
	if req.ID == "" {
		req.ID = fmt.Sprintf("a-%04d", q.seq)
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = now
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = req.RequestedAt.Add(q.ttl)
	}
	req.State = StatePending
	req.DecidedBy = ""
	req.DecidedAt = time.Time{}
	q.byID[req.ID] = req.Clone()
	return req.Clone(), nil
}

// Decide answers a request.
//
// The requester cannot decide, an expired request decides nothing, and
// a request that was already decided stays decided.
func (q *Queue) Decide(id, by string, approve bool, note string) (Request, error) {
	by = strings.TrimSpace(by)
	note = strings.TrimSpace(note)
	if by == "" {
		return Request{}, ErrNoOperator
	}
	if len(note) > MaxNoteLen {
		return Request{}, fmt.Errorf("approval: the note is longer than %d characters", MaxNoteLen)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	req, ok := q.byID[id]
	if !ok {
		return Request{}, ErrNoSuchRequest
	}
	now := time.Now().UTC()
	if req.Pending() && !req.ExpiresAt.IsZero() && now.After(req.ExpiresAt) {
		req.State = StateExpired
		req.Note = "the request went stale before anybody decided it"
		q.byID[req.ID] = req.Clone()
		return req.Clone(), ErrNotPending
	}
	if !req.Pending() {
		return req.Clone(), ErrNotPending
	}
	if req.RequestedBy == by {
		return req.Clone(), ErrOwnRequest
	}
	if approve {
		req.State = StateApproved
	} else {
		req.State = StateDenied
	}
	req.DecidedBy = by
	req.DecidedAt = now
	req.Note = note
	q.byID[req.ID] = req.Clone()
	return req.Clone(), nil
}

// Get returns one request.
//
// A request that went stale while nobody looked at it says so: the
// answer is the same one a decision would give.
func (q *Queue) Get(id string) (Request, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	req, ok := q.byID[id]
	if !ok {
		return Request{}, false
	}
	q.expire(&req)
	q.byID[req.ID] = req.Clone()
	return req.Clone(), true
}

// List returns the requests, newest first.
//
// The state may be filtered: the operator who opens the queue wants
// the requests that still wait and not the ones that were decided
// yesterday.
func (q *Queue) List(state string) []Request {
	state = strings.TrimSpace(state)
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Request, 0, len(q.byID))
	for _, req := range q.byID {
		q.expire(&req)
		q.byID[req.ID] = req.Clone()
		if state != "" && req.State != state {
			continue
		}
		out = append(out, req.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RequestedAt.Equal(out[j].RequestedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].RequestedAt.After(out[j].RequestedAt)
	})
	return out
}

// Expire marks the requests that went stale and returns how many.
//
// The sweep is called by the server every minute; a request that nobody
// decided is not a request any more.
func (q *Queue) Expire() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now().UTC()
	count := 0
	for _, req := range q.byID {
		if !req.Pending() || req.ExpiresAt.IsZero() || now.Before(req.ExpiresAt) {
			continue
		}
		req.State = StateExpired
		req.Note = "the request went stale before anybody decided it"
		q.byID[req.ID] = req.Clone()
		count++
	}
	return count
}

// expire marks one request stale when its time is up.
//
// The caller holds the lock.
func (q *Queue) expire(req *Request) {
	if !req.Pending() || req.ExpiresAt.IsZero() {
		return
	}
	if time.Now().UTC().Before(req.ExpiresAt) {
		return
	}
	req.State = StateExpired
	req.Note = "the request went stale before anybody decided it"
}

// Remove takes a request out of the queue.
//
// A decided request may be removed: the queue is a working list and
// the audit ledger keeps the history.
func (q *Queue) Remove(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.byID[id]; !ok {
		return ErrNoSuchRequest
	}
	delete(q.byID, id)
	return nil
}
