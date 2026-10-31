// Package canary keeps the tripwires of the engagement.
//
// A canary is a small file with a random token in it, planted on a
// host.  Nobody knows it is there, so nobody touches it.  When the file
// changes or disappears, somebody else was on the machine -- and the
// operator learns about it while the engagement is still running.
//
// The rule of the package is that the server owns the ledger and the
// implant only plants and looks.  The facts of the plant -- the size,
// the time of the last change, the digest -- are kept by the implant
// that wrote the file, because it is the only one that knows what it
// wrote; the server keeps the verdict and the history of the verdicts,
// so a canary that was touched twice does not look like one that was
// touched once.
//
// The verdicts travel in the metadata of the task that checked them, as
// one short string: "a-0001=intact;a-0002=changed".  The server reads
// them out of it, so the ledger and the answer the operator read can
// never disagree.
package canary

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
const (
	// MaxCanaries bounds the ledger.
	MaxCanaries = 1024
	// MaxTokenLen bounds the token of one canary.
	MaxTokenLen = 128
	// MaxLabelLen bounds the label of one canary.
	MaxLabelLen = 128
	// MaxNoteLen bounds the note of one canary.
	MaxNoteLen = 512
)

// The states of a canary.
const (
	// StatePlanted is a canary that was planted and not looked at yet.
	StatePlanted = "planted"
	// StateIntact is a canary that is exactly as it was planted.
	StateIntact = "intact"
	// StateChanged is a canary that was touched.
	StateChanged = "changed"
	// StateMissing is a canary that is gone.
	StateMissing = "missing"
)

// Errors of the package.
var (
	// ErrNoSuchCanary is the answer for a canary nobody planted.
	ErrNoSuchCanary = errors.New("canary: no such canary")
	// ErrNoLabel is the answer when a canary has no name.
	ErrNoLabel = errors.New("canary: a canary needs a label")
	// ErrNoAgent is the answer when a canary names no host.
	ErrNoAgent = errors.New("canary: a canary needs the host it was planted on")
)

// Canary is one tripwire of the engagement.
//
// The token is the secret of the canary: it is what the file carries
// and what proves that the file is still the one the implant wrote.
type Canary struct {
	// ID is the short name the operator types: "c-3f7a".
	ID string `json:"id"`
	// Label says what the canary is for: "the web server", "the laptop
	// of the engineer".
	Label string `json:"label"`
	// Token is the secret of the file.
	Token string `json:"token,omitempty"`
	// AgentID is the host the canary was planted on.
	AgentID string `json:"agent_id"`
	// Kind is how it was planted: "file" for now.
	Kind string `json:"kind"`
	// State is "planted", "intact", "changed" or "missing".
	State string `json:"state"`
	// PlantedAt is when the canary was planted.
	PlantedAt time.Time `json:"planted_at"`
	// CheckedAt is when it was looked at last.
	CheckedAt time.Time `json:"checked_at,omitempty"`
	// Note says what happened to it, in the words of the framework.
	Note string `json:"note,omitempty"`
	// Verdict is the last verdict of the check, as the implant wrote it.
	Verdict string `json:"verdict,omitempty"`
}

// Clone returns a copy of the canary.
func (c Canary) Clone() Canary { return c }

// Registry holds the canaries of one deployment.
type Registry struct {
	mu   sync.RWMutex
	byID map[string]Canary
	seq  int
	// path is where the ledger is kept between two runs of the server.
	// The ledger outlives the engagement: a canary that was planted
	// last week is still a canary.
	path string
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{byID: make(map[string]Canary)}
}

// SetPath tells the registry where to keep itself.
func (r *Registry) SetPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path = path
}

// Path is where the ledger is kept, empty when it is not kept.
func (r *Registry) Path() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.path
}

// Load reads the ledger back.
//
// A file that cannot be read is reported and not swallowed: the
// operator has to know that the canaries of last week are gone.
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
		return fmt.Errorf("canary: read %s: %w", path, err)
	}
	var file ledgerFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("canary: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID = make(map[string]Canary, len(file.Canaries))
	for _, c := range file.Canaries {
		if c.ID == "" {
			continue
		}
		r.byID[c.ID] = c
	}
	r.seq = file.Seq
	return nil
}

// ledgerFile is what the ledger looks like on the disk.
type ledgerFile struct {
	Version  int       `json:"version"`
	Seq      int       `json:"seq"`
	SavedAt  time.Time `json:"saved_at"`
	Canaries []Canary  `json:"canaries"`
}

// Save writes the ledger to the disk.
//
// The file is written to a temporary name and renamed into place, so a
// crash never leaves a ledger that is half written.
func (r *Registry) Save() error {
	r.mu.RLock()
	path := r.path
	list := make([]Canary, 0, len(r.byID))
	for _, c := range r.byID {
		list = append(list, c.Clone())
	}
	seq := r.seq
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, err := json.MarshalIndent(ledgerFile{
		Version:  1,
		Seq:      seq,
		SavedAt:  time.Now().UTC(),
		Canaries: list,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("canary: encode the ledger: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("canary: create %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("canary: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("canary: save the ledger: %w", err)
	}
	return nil
}

// Plant puts a canary into the ledger.
//
// The token is the secret of the file: the implant writes it and nobody
// else ever reads it.  The ledger keeps it, because the server has to
// be able to tell the operator which canary is which.
func (r *Registry) Plant(c Canary) (Canary, error) {
	c.Label = strings.TrimSpace(c.Label)
	c.AgentID = strings.TrimSpace(c.AgentID)
	c.Token = strings.TrimSpace(c.Token)
	c.Note = strings.TrimSpace(c.Note)
	if c.Label == "" {
		return Canary{}, ErrNoLabel
	}
	if c.AgentID == "" {
		return Canary{}, ErrNoAgent
	}
	if len(c.Label) > MaxLabelLen {
		return Canary{}, fmt.Errorf("canary: the label is longer than %d characters", MaxLabelLen)
	}
	if len(c.Token) > MaxTokenLen {
		return Canary{}, fmt.Errorf("canary: the token is longer than %d characters", MaxTokenLen)
	}
	if len(c.Note) > MaxNoteLen {
		return Canary{}, fmt.Errorf("canary: the note is longer than %d characters", MaxNoteLen)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.byID) >= MaxCanaries {
		return Canary{}, fmt.Errorf("canary: there are at most %d canaries", MaxCanaries)
	}
	r.seq++
	if c.ID == "" {
		c.ID = fmt.Sprintf("c-%04d", r.seq)
	}
	if c.PlantedAt.IsZero() {
		c.PlantedAt = time.Now().UTC()
	}
	if c.Kind == "" {
		c.Kind = "file"
	}
	if c.State == "" {
		c.State = StatePlanted
	}
	r.byID[c.ID] = c.Clone()
	return c.Clone(), nil
}

// Get returns one canary.
func (r *Registry) Get(id string) (Canary, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[id]
	return c.Clone(), ok
}

// List returns every canary, newest first.
func (r *Registry) List() []Canary {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Canary, 0, len(r.byID))
	for _, c := range r.byID {
		out = append(out, c.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PlantedAt.Equal(out[j].PlantedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].PlantedAt.After(out[j].PlantedAt)
	})
	return out
}

// ForHost returns the canaries of one host.
func (r *Registry) ForHost(agentID string) []Canary {
	agentID = strings.TrimSpace(agentID)
	out := make([]Canary, 0)
	for _, c := range r.List() {
		if agentID == "" || c.AgentID == agentID {
			out = append(out, c)
		}
	}
	return out
}

// Remove takes a canary out of the ledger.
//
// The file on the host stays where it is: removing the canary from the
// ledger says that the operator stopped watching it, and it does not
// touch the host.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		return ErrNoSuchCanary
	}
	delete(r.byID, id)
	return nil
}

// RecordCheck writes the verdicts of a check into the ledger.
//
// The verdicts travel as one string: "c-0001=intact;c-0002=changed".
// A verdict for a canary nobody knows is ignored: the check may have
// been run against a ledger that was replaced.
func (r *Registry) RecordCheck(agentID, states string) int {
	verdicts := ParseVerdicts(states)
	if len(verdicts) == 0 {
		return 0
	}
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for id, verdict := range verdicts {
		c, ok := r.byID[id]
		if !ok {
			continue
		}
		if agentID != "" && c.AgentID != agentID {
			continue
		}
		c.State = verdict.State
		c.Verdict = verdict.Text
		c.CheckedAt = now
		if verdict.State == StateMissing {
			c.Note = "the file of the canary is gone"
		} else if verdict.State == StateChanged {
			c.Note = "the file of the canary was touched"
		} else {
			c.Note = ""
		}
		r.byID[id] = c.Clone()
		count++
	}
	return count
}

// Verdict is what a check says about one canary.
type Verdict struct {
	// ID is the canary the verdict is about.
	ID string
	// State is "intact", "changed" or "missing".
	State string
	// Text is what the implant wrote about it.
	Text string
}

// ParseVerdicts reads the verdicts out of the metadata of a check.
//
// The format is the format of every implant: the id of the canary, an
// equal sign, the state, and the words of the implant after a
// semicolon.  A verdict that does not fit is ignored: the operator
// sees the report of the check anyway, and a broken line must not stop
// the ledger from being written.
func ParseVerdicts(states string) map[string]Verdict {
	out := make(map[string]Verdict)
	for _, part := range strings.Split(states, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, rest, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		id = strings.TrimSpace(id)
		rest = strings.TrimSpace(rest)
		if id == "" || rest == "" {
			continue
		}
		state, text, _ := strings.Cut(rest, ":")
		state = strings.TrimSpace(state)
		switch state {
		case StateIntact, StateChanged, StateMissing:
		default:
			continue
		}
		out[id] = Verdict{ID: id, State: state, Text: strings.TrimSpace(text)}
	}
	return out
}
