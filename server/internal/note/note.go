// Package note holds the lines the team writes about a host.
//
// The dossier of a host is what the server knows; the notes are what
// the team says.  A note is one short line of words, the operator who
// wrote it and the moment it was written, and it travels with the host
// it is about, because a note that is not where the host is looked at
// is a note nobody finds.
//
// The rules are the ones the other ledgers keep:
//
//   - a mutex of its own, a file next to the state file, and a limit
//     on how much it holds;
//   - the file is written for the server alone: the lines are the
//     words of the team, not of the world;
//   - a note that cannot be removed is a note nobody dares to write.
package note

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
// The notes are the words of the team on the hosts, not a journal of
// the world: a host with a hundred lines of notes is a host the team
// explains to itself, and more than that is a book nobody reads.
const (
	// MaxNotes bounds the ledger.
	MaxNotes = 2048
	// MaxNoteLen bounds one line.
	MaxNoteLen = 512
	// MaxPerHost bounds the lines of one host.
	MaxPerHost = 128
)

// The errors of the package.
var (
	// ErrNoSuchNote says that the note is not in the ledger.
	ErrNoSuchNote = errors.New("note: no such note")
	// ErrNoAgent says that the host was not named.
	ErrNoAgent = errors.New("note: the host was not named")
	// ErrNoText says that the line was not written.
	ErrNoText = errors.New("note: the line was not written")
	// ErrTooLong says that the line is longer than the limit.
	ErrTooLong = errors.New("note: the line is too long")
)

// Note is one line the team wrote about a host.
type Note struct {
	// ID is the short name the operator types: "n-0007".
	ID string `json:"id"`
	// AgentID is the host the note is about.
	AgentID string `json:"agent_id"`
	// Text is the line of words.
	Text string `json:"text"`
	// Author is the operator who wrote it.
	Author string `json:"author"`
	// Written is when it was written.
	Written time.Time `json:"written"`
	// Pinned says that the note stays at the top of the page of the
	// host.
	Pinned bool `json:"pinned"`
}

// Clone returns a copy of the note.
func (n Note) Clone() Note { return n }

// Registry holds the notes of the team.
type Registry struct {
	mu   sync.RWMutex
	byID map[string]Note
	seq  int
	path string
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{byID: make(map[string]Note)}
}

// SetPath tells the registry where to keep itself.
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

// Load reads the ledger back.
//
// A file that cannot be read is not fatal: the server starts with an
// empty ledger and says so.
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
		return fmt.Errorf("note: read %s: %w", path, err)
	}
	var file ledgerFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("note: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID = make(map[string]Note, len(file.Notes))
	for _, note := range file.Notes {
		if note.ID == "" {
			continue
		}
		r.byID[note.ID] = note
	}
	r.seq = file.Seq
	return nil
}

// ledgerFile is what the registry looks like on the disk.
type ledgerFile struct {
	Version int       `json:"version"`
	Seq     int       `json:"seq"`
	SavedAt time.Time `json:"saved_at"`
	Notes   []Note    `json:"notes"`
}

// Save writes the ledger to the disk.
//
// The write is atomic and the file belongs to the server alone.
func (r *Registry) Save() error {
	r.mu.RLock()
	path := r.path
	notes := make([]Note, 0, len(r.byID))
	for _, note := range r.byID {
		notes = append(notes, note)
	}
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	sort.Slice(notes, func(i, j int) bool { return notes[i].ID < notes[j].ID })
	raw, err := json.MarshalIndent(ledgerFile{
		Version: 1,
		Seq:     r.SeqValue(),
		SavedAt: time.Now().UTC(),
		Notes:   notes,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("note: the ledger could not be written: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("note: %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("note: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("note: save the ledger: %w", err)
	}
	return nil
}

// SeqValue is the counter of the note ids.
func (r *Registry) SeqValue() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.seq
}

// Add puts one line into the ledger.
func (r *Registry) Add(note Note) (Note, error) {
	note.AgentID = strings.TrimSpace(note.AgentID)
	note.Text = strings.TrimSpace(note.Text)
	note.Author = strings.TrimSpace(note.Author)
	if note.AgentID == "" {
		return Note{}, ErrNoAgent
	}
	if note.Text == "" {
		return Note{}, ErrNoText
	}
	if len(note.Text) > MaxNoteLen {
		return Note{}, ErrTooLong
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	perHost := 0
	for _, existing := range r.byID {
		if existing.AgentID == note.AgentID {
			perHost++
		}
	}
	if perHost >= MaxPerHost {
		return Note{}, fmt.Errorf("note: the host carries at most %d notes", MaxPerHost)
	}
	if len(r.byID) >= MaxNotes {
		return Note{}, fmt.Errorf("note: there are at most %d notes", MaxNotes)
	}
	r.seq++
	if note.ID == "" {
		note.ID = fmt.Sprintf("n-%04d", r.seq)
	}
	if note.Written.IsZero() {
		note.Written = time.Now().UTC()
	}
	r.byID[note.ID] = note.Clone()
	return note.Clone(), nil
}

// Get returns one note.
func (r *Registry) Get(id string) (Note, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	note, ok := r.byID[id]
	return note.Clone(), ok
}

// List returns the notes of one host, pinned first and newest first.
func (r *Registry) List(agentID string) []Note {
	agentID = strings.TrimSpace(agentID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Note, 0, len(r.byID))
	for _, note := range r.byID {
		if agentID != "" && note.AgentID != agentID {
			continue
		}
		out = append(out, note.Clone())
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pinned != out[j].Pinned {
			return out[i].Pinned
		}
		if out[i].Written.Equal(out[j].Written) {
			return out[i].ID > out[j].ID
		}
		return out[i].Written.After(out[j].Written)
	})
	return out
}

// Remove takes a note out of the ledger.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		return ErrNoSuchNote
	}
	delete(r.byID, id)
	return nil
}
