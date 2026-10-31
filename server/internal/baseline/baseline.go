// Package baseline holds the paths the team watches and what was last
// seen of them.
//
// A hunt looks for the indicators of somebody else.  A baseline asks a
// different question: is this host the host we saw yesterday?  The
// team names the paths that matter -- the configuration of the
// service, the script that starts it, the key that opens it -- and the
// server keeps the last look of each of them: the size, the time of
// the last change and the digest.
//
// The rules are the same as everywhere else:
//
//   - the baseline only reads.  It hashes a file and reports it; a
//     baseline that rewrote the file it watches would destroy the very
//     thing it is watching;
//   - the drift is kept, not just the state.  A file that was changed
//     twice does not look like a file that was changed once, because
//     the registry keeps the state, the time of the last look and the
//     number of the changes;
//   - what is not known is said.  A path that was never looked at is
//     `unknown`, not `present`: an operator who thinks a file is
//     untouched when nobody ever looked is an operator who is wrong.
package baseline

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
// The baseline is shared by the team and it grows with every path the
// team decides to watch, so it is bounded: a list of a thousand paths
// on one host is a list nobody reads.
const (
	// MaxEntries bounds the baseline.
	MaxEntries = 4096
	// MaxPathLen bounds the path of one entry.
	MaxPathLen = 1024
	// MaxNoteLen bounds the note of one entry.
	MaxNoteLen = 512
	// MaxLabelLen bounds the label of one entry.
	MaxLabelLen = 128
	// MaxSnapshots bounds the number of paths one look may carry.
	MaxSnapshots = 256
)

// The states a watched path can be in.
const (
	// StateUnknown means nobody ever looked at the path.
	StateUnknown = "unknown"
	// StatePresent means the path is as it was last seen.
	StatePresent = "present"
	// StateChanged means the path was touched since the last look.
	StateChanged = "changed"
	// StateMissing means the path is gone.
	StateMissing = "missing"
	// StateAppeared means the path was gone and is back.
	StateAppeared = "appeared"
)

// The errors of the package.
var (
	// ErrNoSuchEntry says that the entry is not in the baseline.
	ErrNoSuchEntry = errors.New("baseline: no such entry")
	// ErrDuplicate says that the path is already watched on the host.
	ErrDuplicate = errors.New("baseline: the path is already watched on that host")
	// ErrNoPath says that the path was not named.
	ErrNoPath = errors.New("baseline: the path was not named")
	// ErrNoAgent says that the host was not named.
	ErrNoAgent = errors.New("baseline: the host was not named")
)

// Entry is one path the team watches on one host.
type Entry struct {
	// ID is the short name the operator types: "b-0007".
	ID string `json:"id"`
	// AgentID is the host the path is on.
	AgentID string `json:"agent_id"`
	// Path is the path that is watched.
	Path string `json:"path"`
	// Label says what it is in the words of the team.
	Label string `json:"label,omitempty"`
	// Note says why it is watched.
	Note string `json:"note,omitempty"`
	// Added is when it entered the baseline.
	Added time.Time `json:"added"`
	// AddedBy is the operator who added it.
	AddedBy string `json:"added_by,omitempty"`
	// State is "unknown", "present", "changed", "missing" or
	// "appeared".
	State string `json:"state"`
	// Digest is the SHA-256 of the content of the last look.
	Digest string `json:"sha256,omitempty"`
	// Size is the size of the file of the last look.
	Size int64 `json:"size"`
	// ModTime is when the file was changed the last time the implant
	// looked at it.
	ModTime time.Time `json:"mtime,omitempty"`
	// Seen is when the last look was taken.
	Seen time.Time `json:"seen,omitempty"`
	// Changed is when the drift was noticed the last time.
	Changed time.Time `json:"changed,omitempty"`
	// Changes is how many times the path drifted.
	Changes int `json:"changes"`
	// LastNote says what the last look saw.
	LastNote string `json:"last_note,omitempty"`
}

// Clone returns a copy of the entry.
func (e Entry) Clone() Entry { return e }

// Snapshot is what one look at one path found.
//
// It travels in the metadata of the answer as one short JSON string,
// because the ledger of the server and the answer the operator reads
// cannot disagree.
type Snapshot struct {
	// Path is the path that was looked at.
	Path string `json:"path"`
	// Size is the size of the file.
	Size int64 `json:"size"`
	// ModTime is when the file was changed, in seconds.
	ModTime int64 `json:"mtime"`
	// SHA256 is the digest of the content.
	SHA256 string `json:"sha256,omitempty"`
	// Exists says whether the file was there at all.
	Exists bool `json:"exists"`
}

// Drift is one path that moved.
type Drift struct {
	// ID is the entry of the baseline.
	ID string `json:"id"`
	// AgentID is the host.
	AgentID string `json:"agent_id"`
	// Path is the path that moved.
	Path string `json:"path"`
	// State is the new state of the path.
	State string `json:"state"`
	// Before is the digest of the last look.
	Before string `json:"before,omitempty"`
	// After is the digest of this look.
	After string `json:"after,omitempty"`
	// Note says what the look saw.
	Note string `json:"note,omitempty"`
}

// Registry holds the paths the team watches.
type Registry struct {
	mu   sync.RWMutex
	byID map[string]Entry
	seq  int
	path string
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{byID: make(map[string]Entry)}
}

// SetPath tells the registry where to keep itself.
//
// The path is a file: the baseline is written as a JSON object with the
// entries and the counter of their ids.
func (r *Registry) SetPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path = path
}

// Path is where the registry is kept, empty when it is not kept.
func (r *Registry) Path() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.path
}

// Load reads the baseline back.
//
// A file that cannot be read is not fatal: the server starts with an
// empty baseline and says so.
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
		return fmt.Errorf("baseline: read %s: %w", path, err)
	}
	var file registryFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("baseline: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID = make(map[string]Entry, len(file.Entries))
	for _, entry := range file.Entries {
		if entry.ID == "" {
			continue
		}
		r.byID[entry.ID] = entry
	}
	r.seq = file.Seq
	return nil
}

// registryFile is what the baseline looks like on the disk.
//
// The version guards against a downgrade: a file written by a newer
// build may hold fields this one would silently drop.
type registryFile struct {
	Version int       `json:"version"`
	Seq     int       `json:"seq"`
	SavedAt time.Time `json:"saved_at"`
	Entries []Entry   `json:"entries"`
}

// Save writes the baseline to the disk.
//
// The write is atomic and the file belongs to the server alone: the
// baseline says what the team watches, and that is not for the world.
func (r *Registry) Save() error {
	r.mu.RLock()
	path := r.path
	entries := make([]Entry, 0, len(r.byID))
	for _, entry := range r.byID {
		entries = append(entries, entry)
	}
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	raw, err := json.MarshalIndent(registryFile{
		Version: 1,
		Seq:     r.Seq(),
		SavedAt: time.Now().UTC(),
		Entries: entries,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: the baseline could not be written: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("baseline: %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("baseline: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("baseline: save the baseline: %w", err)
	}
	return nil
}

// Seq is the counter of the ids.
func (r *Registry) Seq() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.seq
}

// Add puts a path into the baseline.
func (r *Registry) Add(entry Entry) (Entry, error) {
	entry.Path = strings.TrimSpace(entry.Path)
	entry.AgentID = strings.TrimSpace(entry.AgentID)
	entry.Label = strings.TrimSpace(entry.Label)
	entry.Note = strings.TrimSpace(entry.Note)
	entry.AddedBy = strings.TrimSpace(entry.AddedBy)
	if entry.Path == "" {
		return Entry{}, ErrNoPath
	}
	if entry.AgentID == "" {
		return Entry{}, ErrNoAgent
	}
	if len(entry.Path) > MaxPathLen {
		return Entry{}, fmt.Errorf("baseline: the path is longer than %d characters", MaxPathLen)
	}
	if len(entry.Note) > MaxNoteLen {
		return Entry{}, fmt.Errorf("baseline: the note is longer than %d characters", MaxNoteLen)
	}
	if len(entry.Label) > MaxLabelLen {
		return Entry{}, fmt.Errorf("baseline: the label is longer than %d characters", MaxLabelLen)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.byID {
		if existing.AgentID == entry.AgentID && existing.Path == entry.Path {
			return Entry{}, ErrDuplicate
		}
	}
	if len(r.byID) >= MaxEntries {
		return Entry{}, fmt.Errorf("baseline: there are at most %d watched paths", MaxEntries)
	}
	now := time.Now().UTC()
	r.seq++
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("b-%04d", r.seq)
	}
	if entry.Added.IsZero() {
		entry.Added = now
	}
	if entry.State == "" {
		entry.State = StateUnknown
	}
	r.byID[entry.ID] = entry.Clone()
	return entry.Clone(), nil
}

// Get returns one entry.
func (r *Registry) Get(id string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.byID[id]
	return entry.Clone(), ok
}

// List returns the entries, the host of each one and the state of the
// path.
//
// The state may be filtered: an operator who opens the baseline wants
// the paths that moved and not the ones that did not.
func (r *Registry) List(agentID, state string) []Entry {
	agentID = strings.TrimSpace(agentID)
	state = strings.TrimSpace(state)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, 0, len(r.byID))
	for _, entry := range r.byID {
		if agentID != "" && entry.AgentID != agentID {
			continue
		}
		if state != "" && entry.State != state {
			continue
		}
		out = append(out, entry.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgentID != out[j].AgentID {
			return out[i].AgentID < out[j].AgentID
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// Remove takes a path out of the baseline.
//
// The file on the host stays where it is: this removes the watch, not
// the file.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		return ErrNoSuchEntry
	}
	delete(r.byID, id)
	return nil
}

// Paths returns the paths that are watched on a host.
//
// The paths are the ones the implant is asked about, and nothing else:
// the implant is told what to look at and not what the team knows.
func (r *Registry) Paths(agentID string) []string {
	entries := r.List(agentID, "")
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Path)
	}
	return out
}

// Record writes the findings of a look into the baseline.
//
// The findings travel as one short JSON string in the metadata of the
// answer, so the baseline and the answer the operator reads cannot
// disagree.  A finding about a path nobody watches is ignored: the
// look may have been run against a baseline that was replaced.
//
// The drift is returned, so the caller can say it out loud.
func (r *Registry) Record(agentID string, snaps []Snapshot) []Drift {
	if len(snaps) > MaxSnapshots {
		snaps = snaps[:MaxSnapshots]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	drifts := make([]Drift, 0, len(snaps))
	for _, snap := range snaps {
		entry, ok := r.findLocked(agentID, snap.Path)
		if !ok {
			continue
		}
		before := entry.Digest
		switch {
		case !snap.Exists:
			entry.State = StateMissing
			entry.Digest = ""
			entry.Size = 0
			entry.LastNote = "the file is gone"
		case entry.State == StateMissing:
			entry.State = StateAppeared
			entry.Digest = snap.SHA256
			entry.Size = snap.Size
			entry.LastNote = "the file is back"
		case before == "" || before == snap.SHA256:
			entry.State = StatePresent
			entry.Digest = snap.SHA256
			entry.Size = snap.Size
			entry.LastNote = "the file is as it was"
		default:
			entry.State = StateChanged
			entry.Digest = snap.SHA256
			entry.Size = snap.Size
			entry.Changes++
			entry.Changed = now
			entry.LastNote = "the file was touched"
		}
		if snap.ModTime > 0 {
			entry.ModTime = time.Unix(snap.ModTime, 0).UTC()
		}
		entry.Seen = now
		r.byID[entry.ID] = entry.Clone()
		if entry.State == StateChanged || entry.State == StateMissing ||
			entry.State == StateAppeared {
			drifts = append(drifts, Drift{
				ID:      entry.ID,
				AgentID: entry.AgentID,
				Path:    entry.Path,
				State:   entry.State,
				Before:  before,
				After:   entry.Digest,
				Note:    entry.LastNote,
			})
		}
	}
	return drifts
}

// findLocked finds the entry of a path on a host. The caller holds the
// lock.
func (r *Registry) findLocked(agentID, path string) (Entry, bool) {
	path = strings.TrimSpace(path)
	for _, entry := range r.byID {
		if entry.AgentID != agentID {
			continue
		}
		if entry.Path == path {
			return entry, true
		}
	}
	return Entry{}, false
}

// ParseSnapshots reads the findings of a look out of the metadata of
// the answer.
//
// A finding that does not fit is ignored: the operator sees the report
// of the look anyway, and a broken line must not stop the baseline
// from being written.
func ParseSnapshots(raw string) []Snapshot {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil
	}
	var snaps []Snapshot
	if err := json.Unmarshal([]byte(raw), &snaps); err != nil {
		return nil
	}
	out := snaps[:0]
	for _, snap := range snaps {
		if strings.TrimSpace(snap.Path) == "" {
			continue
		}
		out = append(out, snap)
	}
	return out
}
