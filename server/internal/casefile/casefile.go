// Package casefile keeps the evidence of an engagement.
//
// A case is the folder the operator hands to somebody else: the
// lawyer, the customer, the court.  It says what was found, where it
// was found, on which host, and it proves that nothing in it was
// changed after it was taken.
//
// Every artefact in a case is hashed when it enters, and the hash is
// kept beside it.  The chain of custody is the list of the hands the
// artefact passed through: who took it, when, why, and what they did
// to it.  The chain is append-only: an entry cannot be edited, and a
// broken chain is reported as a broken chain rather than hidden.
//
// The rule of the package is that a case is a record, not a container
// of live data: the artefacts are referenced by their hash and by the
// place they were taken from, and the bytes stay where the operator
// put them.
package casefile

import (
	"crypto/sha256"
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

// Limits.
const (
	// MaxCases bounds the number of open cases.
	MaxCases = 256
	// MaxArtefacts bounds the artefacts of one case.
	MaxArtefacts = 4096
	// MaxEvents bounds the chain of custody of one case.
	MaxEvents = 8192
	// MaxTitleLen bounds the title of a case.
	MaxTitleLen = 200
	// MaxNoteLen bounds the note of an event.
	MaxNoteLen = 1024
	// MaxRefLen bounds the reference of an artefact.
	MaxRefLen = 1024
)

// The states of a case.
const (
	StateOpen   = "open"
	StateClosed = "closed"
)

// Errors of the package.
var (
	ErrNoSuchCase = errors.New("case: no such case")
	ErrDuplicate  = errors.New("case: the case already exists")
	ErrClosed     = errors.New("case: the case is closed")
	ErrNoTitle    = errors.New("case: a case needs a title")
)

// Artefact is one piece of evidence.
//
// Ref is where the bytes are: a path on the disk of the server, a key
// in the armory, or a reference the operator wrote down.  Hash is the
// SHA-256 of the bytes at the moment they entered the case, and it is
// what proves they did not change since.
type Artefact struct {
	// ID is the short name of the artefact.
	ID string `json:"id"`
	// Kind is what it is: "screenshot", "registry", "report", ...
	Kind string `json:"kind"`
	// Ref is where the bytes are.
	Ref string `json:"ref"`
	// Hash is the SHA-256 of the bytes, in hex.
	Hash string `json:"hash"`
	// Size is the size of the bytes, in bytes.
	Size int64 `json:"size"`
	// AgentID is the host it was taken from.
	AgentID string `json:"agent_id,omitempty"`
	// TaskID is the task that took it.
	TaskID string `json:"task_id,omitempty"`
	// Taken is when it entered the case.
	Taken time.Time `json:"taken"`
	// TakenBy is the operator who took it.
	TakenBy string `json:"taken_by,omitempty"`
	// Note says what it is in the words of the operator.
	Note string `json:"note,omitempty"`
}

// Event is one hand in the chain of custody.
//
// The chain is append-only: the events are written once and read
// forever, and the previous hash of every event is the hash of the one
// before it, so a removed event breaks the chain.
type Event struct {
	// Seq is the number of the event in the chain.
	Seq int `json:"seq"`
	// At is when it happened.
	At time.Time `json:"at"`
	// Actor is who did it: an operator, or "system".
	Actor string `json:"actor"`
	// Action is what was done: "opened", "added", "verified", "closed".
	Action string `json:"action"`
	// Artefact is the artefact the event is about, if any.
	Artefact string `json:"artefact,omitempty"`
	// Note says why.
	Note string `json:"note,omitempty"`
	// Prev is the hash of the previous event, or empty for the first.
	Prev string `json:"prev,omitempty"`
	// Hash is the hash of this event, over the canonical bytes.
	Hash string `json:"hash"`
}

// Case is one engagement file.
type Case struct {
	// ID is the short name: "c-0001".
	ID string `json:"id"`
	// Title is what the operator calls it.
	Title string `json:"title"`
	// Notes are the free lines of the operator.
	Notes string `json:"notes,omitempty"`
	// Operator is who opened it.
	Operator string `json:"operator,omitempty"`
	// State is "open" or "closed".
	State string `json:"state"`
	// Opened and Closed are the times.
	Opened time.Time `json:"opened"`
	Closed time.Time `json:"closed,omitempty"`
	// Artefacts are the pieces of evidence.
	Artefacts []Artefact `json:"artefacts"`
	// Events are the chain of custody.
	Events []Event `json:"events"`
	// Head is the hash of the last event of the chain.
	Head string `json:"head,omitempty"`
}

// Chain returns the hash chain of the case.
//
// The hash of an event covers its own bytes and the hash of the event
// before it, so an event that is edited or removed breaks the chain at
// that point and at every point after it.
func Chain(events []Event) (string, []int) {
	head := ""
	broken := []int{}
	prev := ""
	for i, ev := range events {
		canonical := canonicalEvent(ev)
		if ev.Prev != prev {
			broken = append(broken, ev.Seq)
		}
		sum := sha256.Sum256([]byte(prev + "|" + canonical))
		want := hex.EncodeToString(sum[:])
		if ev.Hash != want {
			broken = append(broken, ev.Seq)
		}
		prev = want
		head = want
	}
	return head, broken
}

// Verify checks the chain of a case.
//
// It returns the number of the first event that does not fit and the
// reason.  A case with a broken chain is still shown: hiding it would
// be the one thing worse than showing it.
func Verify(c *Case) (bool, int, string) {
	prev := ""
	for _, ev := range c.Events {
		canonical := canonicalEvent(ev)
		if ev.Prev != prev {
			return false, ev.Seq, "the previous hash does not fit"
		}
		sum := sha256.Sum256([]byte(prev + "|" + canonical))
		want := hex.EncodeToString(sum[:])
		if ev.Hash != want {
			return false, ev.Seq, "the hash of the event does not fit"
		}
		prev = want
	}
	if c.Head != "" && c.Head != prev {
		return false, len(c.Events), "the head of the chain does not fit"
	}
	return true, 0, ""
}

// canonicalEvent is the bytes of an event that the hash covers.
//
// The hash of the event is taken over these bytes and not over the
// JSON of the whole event, so the formatting of the file cannot change
// the hash.
func canonicalEvent(ev Event) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s",
		ev.Seq,
		ev.At.UTC().Format(time.RFC3339Nano),
		ev.Actor,
		ev.Action,
		ev.Artefact,
		ev.Note,
		ev.Prev)
}

// File is the bundle the operator hands over.
//
// It is written as one JSON object: the chain of custody and the list
// of artefacts, and nothing that could be changed without breaking the
// hashes inside it.
type File struct {
	Version int        `json:"version"`
	Case    *Case      `json:"case"`
	Exports []Artefact `json:"exports,omitempty"`
}

// Registry holds the cases of one deployment.
type Registry struct {
	mu     sync.RWMutex
	byID   map[string]*Case
	seq    int
	path   string
	loaded bool
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{byID: make(map[string]*Case)}
}

// SetPath tells the registry where to keep itself.
func (r *Registry) SetPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path = path
}

// Path is where the registry is kept.
func (r *Registry) Path() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.path
}

// registryFile is what the registry looks like on the disk.
type registryFile struct {
	Version int    `json:"version"`
	Seq     int    `json:"seq"`
	SavedAt time.Time `json:"saved_at"`
	Cases   []*Case `json:"cases"`
}

// Load reads the registry back.
//
// A file that cannot be read is reported and not swallowed: the
// operator has to know that the cases of last week are gone.
func (r *Registry) Load() error {
	r.mu.RLock()
	path := r.path
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("case: read %s: %w", path, err)
	}
	var file registryFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("case: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID = make(map[string]*Case, len(file.Cases))
	for _, c := range file.Cases {
		if c == nil || c.ID == "" {
			continue
		}
		r.byID[c.ID] = c
	}
	r.seq = file.Seq
	r.loaded = true
	return nil
}

// Save writes the registry to the disk.
//
// The file is written to a temporary name and renamed into place, so a
// crash never leaves half a case file behind.
func (r *Registry) Save() error {
	r.mu.RLock()
	path := r.path
	list := make([]*Case, 0, len(r.byID))
	for _, c := range r.byID {
		list = append(list, c)
	}
	seq := r.seq
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, err := json.MarshalIndent(registryFile{
		Version: 1,
		Seq:     seq,
		SavedAt: time.Now().UTC(),
		Cases:   list,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("case: encode the registry: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("case: create %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("case: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("case: save the registry: %w", err)
	}
	return nil
}

// Open creates a case and returns it.
//
// The first event of the chain is written here: the case is opened by
// somebody, at a time, and the chain starts with that.
func (r *Registry) Open(title, notes, operator string) (*Case, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		return nil, ErrNoTitle
	}
	if len(title) > MaxTitleLen {
		return nil, fmt.Errorf("case: the title is longer than %d characters", MaxTitleLen)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.byID) >= MaxCases {
		return nil, fmt.Errorf("case: there are at most %d cases", MaxCases)
	}
	r.seq++
	c := &Case{
		ID:       fmt.Sprintf("c-%04d", r.seq),
		Title:    title,
		Notes:    strings.TrimSpace(notes),
		Operator: strings.TrimSpace(operator),
		State:    StateOpen,
		Opened:   time.Now().UTC(),
	}
	r.byID[c.ID] = c
	r.appendEvent(c, "opened", "", operator, "the case was opened")
	return c, nil
}

// appendEvent writes one hand into the chain.
//
// The caller holds the lock.
func (r *Registry) appendEvent(c *Case, action, artefact, actor, note string) {
	note = strings.TrimSpace(note)
	if len(note) > MaxNoteLen {
		note = note[:MaxNoteLen]
	}
	prev := c.Head
	ev := Event{
		Seq:      len(c.Events) + 1,
		At:       time.Now().UTC(),
		Actor:    strings.TrimSpace(actor),
		Action:   action,
		Artefact: artefact,
		Note:     note,
		Prev:     prev,
	}
	sum := sha256.Sum256([]byte(prev + "|" + canonicalEvent(ev)))
	ev.Hash = hex.EncodeToString(sum[:])
	c.Events = append(c.Events, ev)
	c.Head = ev.Hash
}

// Add puts an artefact into a case.
//
// The bytes are hashed by the caller and the hash is given here: the
// package does not read files of its own accord, because what enters a
// case is decided by the operator and not by the framework.
func (r *Registry) Add(id, kind, ref, hash, agentID, taskID, operator, note string, size int64) (Artefact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return Artefact{}, ErrNoSuchCase
	}
	if c.State != StateOpen {
		return Artefact{}, ErrClosed
	}
	if len(c.Artefacts) >= MaxArtefacts {
		return Artefact{}, fmt.Errorf("case: a case holds at most %d artefacts", MaxArtefacts)
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Artefact{}, fmt.Errorf("case: an artefact needs a reference")
	}
	if len(ref) > MaxRefLen {
		return Artefact{}, fmt.Errorf("case: the reference is longer than %d characters", MaxRefLen)
	}
	art := Artefact{
		ID:      fmt.Sprintf("%s-a%03d", c.ID, len(c.Artefacts)+1),
		Kind:    strings.TrimSpace(kind),
		Ref:     ref,
		Hash:    strings.ToLower(strings.TrimSpace(hash)),
		Size:    size,
		AgentID: strings.TrimSpace(agentID),
		TaskID:  strings.TrimSpace(taskID),
		Taken:   time.Now().UTC(),
		TakenBy: strings.TrimSpace(operator),
		Note:    strings.TrimSpace(note),
	}
	if art.Kind == "" {
		art.Kind = "evidence"
	}
	c.Artefacts = append(c.Artefacts, art)
	r.appendEvent(c, "added", art.ID, operator, art.Kind+" "+art.Ref)
	return art, nil
}

// Touch writes one more hand into the chain.
//
// It is how the operator says "I looked at it" or "I copied it off the
// host": the chain is the story of what happened to the evidence, and
// the story is written as it happens.
func (r *Registry) Touch(id, action, artefact, operator, note string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return ErrNoSuchCase
	}
	if c.State != StateOpen {
		return ErrClosed
	}
	if len(c.Events) >= MaxEvents {
		return fmt.Errorf("case: the chain holds at most %d events", MaxEvents)
	}
	r.appendEvent(c, action, artefact, operator, note)
	return nil
}

// Close closes a case.
//
// The last event of the chain is the closing of the case itself, so
// the chain says who closed it and when.
func (r *Registry) Close(id, operator, note string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return ErrNoSuchCase
	}
	if c.State != StateOpen {
		return ErrClosed
	}
	c.State = StateClosed
	c.Closed = time.Now().UTC()
	r.appendEvent(c, "closed", "", operator, note)
	return nil
}

// Get returns one case.
func (r *Registry) Get(id string) (*Case, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[id]
	if !ok {
		return nil, false
	}
	return cloneCase(c), true
}

// List returns every case, newest first.
func (r *Registry) List() []*Case {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Case, 0, len(r.byID))
	for _, c := range r.byID {
		out = append(out, cloneCase(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// Export writes the case file of one case.
//
// The bundle is written next to the registry, with the name of the
// case, so the operator can hand the file over and keep the bytes.
func (r *Registry) Export(id, dir string) (string, error) {
	r.mu.RLock()
	c, ok := r.byID[id]
	path := r.path
	var copy *Case
	if ok {
		copy = cloneCase(c)
	}
	r.mu.RUnlock()
	if !ok {
		return "", ErrNoSuchCase
	}
	if dir == "" {
		if path == "" {
			return "", fmt.Errorf("case: there is nowhere to write the case file")
		}
		dir = filepath.Dir(path)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("case: create %s: %w", dir, err)
	}
	out := filepath.Join(dir, fmt.Sprintf("%s.json", copy.ID))
	raw, err := json.MarshalIndent(File{Version: 1, Case: copy}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("case: encode %s: %w", c.ID, err)
	}
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return "", fmt.Errorf("case: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, out); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("case: save %s: %w", out, err)
	}
	return out, nil
}

// cloneCase returns a copy of the case, so that the caller cannot
// change the chain of the registry by holding on to it.
func cloneCase(c *Case) *Case {
	out := *c
	out.Artefacts = append([]Artefact(nil), c.Artefacts...)
	out.Events = append([]Event(nil), c.Events...)
	return &out
}

// HashBytes is the hash of the bytes of an artefact.
//
// It is the helper the server and the console use to put the same
// hash into the case and into the note of the operator.
func HashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
