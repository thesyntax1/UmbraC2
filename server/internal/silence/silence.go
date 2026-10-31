// Package silence is the news of nothing.
//
// The alarms of the day fire when something happens: a wire was
// tripped, a baseline drifted, a task came back.  A host that went
// quiet does nothing, and nothing fires no alarm — so the watch of the
// silences turns it into news: name the host and the longest pause you
// accept, and the server says the word when the pause has been longer.
//
// The rules of the watch are small and kept:
//
//   - a watch is not a trap: it reads the moment of the last check-in,
//     it writes nothing to the host, and it never talks to the
//     implant;
//   - a fired watch goes quiet for its cooldown, because an absent
//     host is one problem, not a drumbeat of notifications;
//   - the ledger is a file next to the state file, written for the
//     server alone, so the question "who promised to worry about this
//     host" survives a restart.
package silence

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
// The watches are the promises to worry about a host; a team that
// watches a thousand hosts here has a dashboard for it already, and a
// pause shorter than five seconds is a panic, not a watch.
const (
	// MaxWatches bounds the ledger.
	MaxWatches = 512
	// MinSeconds is the shortest pause that can be watched for.
	MinSeconds = 5
	// MaxSeconds is the longest: a week of silence is asleep, not quiet.
	MaxSeconds = 7 * 24 * 3600
)

// The errors of the package.
var (
	// ErrNoAgent says that the host was not named.
	ErrNoAgent = errors.New("silence: the host was not named")
	// ErrBadWindow says that the pause is out of the bounds.
	ErrBadWindow = errors.New("silence: the pause is out of the bounds")
	// ErrTooMany says that the ledger is full.
	ErrTooMany = errors.New("silence: the team watches too many silences")
	// ErrNoSuchWatch says that the watch is not in the ledger.
	ErrNoSuchWatch = errors.New("silence: no such watch")
	// ErrTwiceWatched says that the silence of this host is watched
	// already: one promise per host, so nobody wonders which of the
	// two is the real one.
	ErrTwiceWatched = errors.New("silence: the silence of this host is watched already")
)

// Watch is one promise to worry: the host, the pause that is news,
// and the cooldown that keeps a fired watch from drumming.
type Watch struct {
	// ID is the short name the operator types: "s-0002".
	ID string `json:"id"`
	// AgentID is the host whose silence is watched.
	AgentID string `json:"agent_id"`
	// Seconds is the pause that is news: a host quiet for longer
	// becomes an event.
	Seconds int64 `json:"seconds"`
	// Cooldown is how long a fired watch holds its peace, in seconds.
	// Zero means ten times the pause.
	Cooldown int64 `json:"cooldown"`
	// Creator is the operator who promised to worry.
	Creator string `json:"creator,omitempty"`
	// Created is when the promise was made.
	Created time.Time `json:"created"`
	// LastFired is when the watch last spoke, zero when it never did.
	LastFired time.Time `json:"last_fired,omitempty"`
}

// Clone returns a copy of the watch.
func (w Watch) Clone() Watch { return w }

// Registry holds the watches of the silences.
type Registry struct {
	mu   sync.Mutex
	byID map[string]Watch
	seq  int
	path string
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{byID: make(map[string]Watch)}
}

// SetPath tells the registry where to keep itself.
func (r *Registry) SetPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path = path
}

// Path is where the registry is kept, empty when it is not kept.
func (r *Registry) Path() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.path
}

// ledgerFile is what the registry looks like on the disk.
type ledgerFile struct {
	Version int       `json:"version"`
	Seq     int       `json:"seq"`
	SavedAt time.Time `json:"saved_at"`
	Watches []Watch   `json:"watches"`
}

// Load reads the ledger back; a missing file is not fatal.
func (r *Registry) Load() error {
	r.mu.Lock()
	path := r.path
	r.mu.Unlock()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("silence: read %s: %w", path, err)
	}
	var file ledgerFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("silence: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID = make(map[string]Watch, len(file.Watches))
	for _, w := range file.Watches {
		if w.ID == "" {
			continue
		}
		r.byID[w.ID] = w.Clone()
	}
	r.seq = file.Seq
	return nil
}

// Save writes the ledger to the disk, atomically and for the server
// alone.
func (r *Registry) Save() error {
	r.mu.Lock()
	path := r.path
	watches := make([]Watch, 0, len(r.byID))
	for _, w := range r.byID {
		watches = append(watches, w.Clone())
	}
	seq := r.seq
	r.mu.Unlock()
	if path == "" {
		return nil
	}
	sort.Slice(watches, func(i, j int) bool { return watches[i].ID < watches[j].ID })
	raw, err := json.MarshalIndent(ledgerFile{
		Version: 1,
		Seq:     seq,
		SavedAt: time.Now().UTC(),
		Watches: watches,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("silence: the ledger could not be written: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("silence: %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("silence: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("silence: save the ledger: %w", err)
	}
	return nil
}

// Add writes one promise down.
func (r *Registry) Add(w Watch) (Watch, error) {
	w.AgentID = strings.TrimSpace(w.AgentID)
	w.Creator = strings.TrimSpace(w.Creator)
	if w.AgentID == "" {
		return Watch{}, ErrNoAgent
	}
	if w.Seconds < MinSeconds || w.Seconds > MaxSeconds {
		return Watch{}, fmt.Errorf("%w: %d not in [%d, %d]",
			ErrBadWindow, w.Seconds, MinSeconds, MaxSeconds)
	}
	if w.Cooldown <= 0 {
		w.Cooldown = w.Seconds * 10
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.byID) >= MaxWatches {
		return Watch{}, ErrTooMany
	}
	for _, existing := range r.byID {
		if existing.AgentID == w.AgentID {
			return Watch{}, fmt.Errorf("%w: %s", ErrTwiceWatched, w.AgentID)
		}
	}
	r.seq++
	w.ID = fmt.Sprintf("s-%04d", r.seq)
	if w.Created.IsZero() {
		w.Created = time.Now().UTC()
	}
	r.byID[w.ID] = w.Clone()
	return w.Clone(), nil
}

// List returns the watches, in the order they were promised.
func (r *Registry) List() []Watch {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Watch, 0, len(r.byID))
	for _, w := range r.byID {
		out = append(out, w.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Remove takes a promise out of the ledger.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		return ErrNoSuchWatch
	}
	delete(r.byID, id)
	return nil
}

// Due marks the watches whose host has been quiet for longer than the
// promised pause and returns them, so the caller can say the word.
//
// The lookup answers the last moment a host called home; a host the
// server has never seen has no moment, and its silence came into the
// world with the watch, so the clock starts at the watch's creation.
// A fired watch marks itself and holds its peace for its cooldown.
func (r *Registry) Due(now time.Time, lastSeen func(agentID string) (time.Time, bool)) []Watch {
	r.mu.Lock()
	defer r.mu.Unlock()
	var due []Watch
	for id, w := range r.byID {
		last, known := lastSeen(w.AgentID)
		if !known {
			last = w.Created
		}
		if last.IsZero() {
			last = w.Created
		}
		if now.Sub(last) < time.Duration(w.Seconds)*time.Second {
			continue
		}
		if !w.LastFired.IsZero() &&
			now.Sub(w.LastFired) < time.Duration(w.Cooldown)*time.Second {
			continue
		}
		w.LastFired = now.UTC()
		r.byID[id] = w
		due = append(due, w.Clone())
	}
	sort.Slice(due, func(i, j int) bool { return due[i].ID < due[j].ID })
	return due
}
