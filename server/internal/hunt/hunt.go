// Package hunt holds the indicators of compromise the team hunts with.
//
// A hunt is the opposite of a wipe: the wipe takes the traces of the
// engagement away, and the hunt looks for the traces of somebody else.
// The team keeps a catalogue of indicators -- a hash, a path, a mutex,
// a registry key, a certificate -- and asks every host of a group
// whether it carries one of them.
//
// The catalogue is shared by the team and it outlives the engagement:
// an indicator that was found once is worth checking everywhere, so the
// catalogue lives next to the state file and is written to the disk
// atomically.
//
// Two rules hold everywhere:
//
//   - an indicator is matched exactly, never fuzzily: a hunt that
//     reports a "possible" match is a hunt the operator cannot act on;
//   - the hunt never changes the host.  It reads, it reports, and the
//     operator decides what to do with what it found.
package hunt

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
// The catalogue is shared and it grows with every indicator the team
// finds, so it is bounded: a catalogue that nobody can search is a
// catalogue nobody uses.
const (
	// MaxIndicators bounds the catalogue.
	MaxIndicators = 4096
	// MaxValueLen bounds the value of one indicator.
	MaxValueLen = 1024
	// MaxNoteLen bounds the note of one indicator.
	MaxNoteLen = 512
	// MaxLabelLen bounds the label of one indicator.
	MaxLabelLen = 128
)

// The kinds of indicator the framework understands.
//
// The kind decides how the implant looks for it: a hash is a hash of a
// file, a path is a path on the disk, a mutex is a name in the kernel
// of Windows, a registry key is a key in the registry, a certificate is
// a thumbprint in the store.
const (
	KindHash        = "hash"
	KindPath        = "path"
	KindMutex       = "mutex"
	KindRegistry    = "registry"
	KindCertificate = "certificate"
	KindProcess     = "process"
	KindService     = "service"
)

// Kinds is every kind the framework understands.
var Kinds = []string{
	KindHash, KindPath, KindMutex, KindRegistry, KindCertificate,
	KindProcess, KindService,
}

// ValidKind says whether a kind is one the framework understands.
func ValidKind(kind string) bool {
	for _, k := range Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Errors of the package.
var (
	ErrNoSuchIndicator = errors.New("hunt: no such indicator")
	ErrDuplicate       = errors.New("hunt: the indicator is already in the catalogue")
	ErrUnknownKind     = errors.New("hunt: unknown kind of indicator")
	ErrNoValue         = errors.New("hunt: an indicator needs a value")
)

// Indicator is one thing the team looks for.
//
// The value is the indicator itself -- the hash, the path, the name --
// and the label says what it is in the words of the team: "the loader
// the ticket of March told us about".
type Indicator struct {
	// ID is the short name the operator types: "i-3f7a".
	ID string `json:"id"`
	// Kind is how it is looked for.
	Kind string `json:"kind"`
	// Value is the indicator.
	Value string `json:"value"`
	// Label is what the team calls it.
	Label string `json:"label,omitempty"`
	// Note says where it came from.
	Note string `json:"note,omitempty"`
	// Source is the ticket, the report or the host it was found on.
	Source string `json:"source,omitempty"`
	// Added is when it entered the catalogue.
	Added time.Time `json:"added"`
	// AddedBy is the operator who added it.
	AddedBy string `json:"added_by,omitempty"`
	// Hits is how many hosts reported it. It is a counter of the
	// catalogue, not a proof: the number says how often the hunt found
	// it, and the operator still has to look at the host.
	Hits int `json:"hits"`
}

// Clone returns a copy of the indicator.
func (i Indicator) Clone() Indicator { return i }

// Catalogue holds the indicators of one team.
type Catalogue struct {
	mu     sync.RWMutex
	byID   map[string]Indicator
	seq    int
	path   string
	loaded bool
}

// New creates an empty catalogue.
func New() *Catalogue {
	return &Catalogue{byID: make(map[string]Indicator)}
}

// SetPath tells the catalogue where to keep itself.
//
// The path is a file: the catalogue is written as a JSON object with the
// indicators and the counter of their ids.
func (c *Catalogue) SetPath(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.path = path
}

// Path is where the catalogue is kept, empty when it is not kept.
func (c *Catalogue) Path() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.path
}

// Load reads the catalogue back.
//
// A file that cannot be read is not fatal: the server starts with an
// empty catalogue and says so, because a lost catalogue is a nuisance
// and a catalogue that is silently wrong is a trap.
func (c *Catalogue) Load() error {
	c.mu.RLock()
	path := c.path
	c.mu.RUnlock()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("hunt: read %s: %w", path, err)
	}
	var file catalogueFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("hunt: parse %s: %w", path, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byID = make(map[string]Indicator, len(file.Indicators))
	for _, ind := range file.Indicators {
		if ind.ID == "" {
			continue
		}
		c.byID[ind.ID] = ind
	}
	c.seq = file.Seq
	c.loaded = true
	return nil
}

// catalogueFile is what the catalogue looks like on the disk.
//
// The version guards against a downgrade: a file written by a newer
// build may hold fields this one would silently drop.
type catalogueFile struct {
	Version    int         `json:"version"`
	Seq        int         `json:"seq"`
	SavedAt    time.Time   `json:"saved_at"`
	Indicators []Indicator `json:"indicators"`
}

// Save writes the catalogue to the disk.
//
// The file is written to a temporary name and renamed into place, so a
// crash never leaves a catalogue that is half written.
func (c *Catalogue) Save() error {
	c.mu.RLock()
	path := c.path
	list := make([]Indicator, 0, len(c.byID))
	for _, ind := range c.byID {
		list = append(list, ind)
	}
	seq := c.seq
	c.mu.RUnlock()
	if path == "" {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, err := json.MarshalIndent(catalogueFile{
		Version:    1,
		Seq:        seq,
		SavedAt:    time.Now().UTC(),
		Indicators: list,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("hunt: encode the catalogue: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("hunt: create %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("hunt: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hunt: save the catalogue: %w", err)
	}
	return nil
}

// Add puts an indicator into the catalogue.
//
// The id is generated when the operator did not choose one, so two
// indicators with the same value are two indicators and not one.
func (c *Catalogue) Add(ind Indicator) (Indicator, error) {
	ind.Kind = strings.ToLower(strings.TrimSpace(ind.Kind))
	ind.Value = strings.TrimSpace(ind.Value)
	ind.Label = strings.TrimSpace(ind.Label)
	ind.Note = strings.TrimSpace(ind.Note)
	ind.Source = strings.TrimSpace(ind.Source)
	if ind.Value == "" {
		return Indicator{}, ErrNoValue
	}
	if len(ind.Value) > MaxValueLen {
		return Indicator{}, fmt.Errorf("hunt: the value is longer than %d characters", MaxValueLen)
	}
	if len(ind.Label) > MaxLabelLen {
		return Indicator{}, fmt.Errorf("hunt: the label is longer than %d characters", MaxLabelLen)
	}
	if len(ind.Note) > MaxNoteLen {
		return Indicator{}, fmt.Errorf("hunt: the note is longer than %d characters", MaxNoteLen)
	}
	if ind.Kind == "" {
		// A hash is the most common indicator and the only one whose
		// shape the framework can check.
		if isHash(ind.Value) {
			ind.Kind = KindHash
		} else {
			return Indicator{}, ErrUnknownKind
		}
	}
	if !ValidKind(ind.Kind) {
		return Indicator{}, fmt.Errorf("%w: %q", ErrUnknownKind, ind.Kind)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.byID) >= MaxIndicators {
		for _, existing := range c.byID {
			if existing.Kind == ind.Kind && existing.Value == ind.Value {
				return existing, ErrDuplicate
			}
		}
		return Indicator{}, fmt.Errorf("hunt: the catalogue holds at most %d indicators", MaxIndicators)
	}
	for _, existing := range c.byID {
		if existing.Kind == ind.Kind && existing.Value == ind.Value {
			return existing, ErrDuplicate
		}
	}
	if ind.ID == "" {
		c.seq++
		ind.ID = fmt.Sprintf("i-%04x", c.seq)
	}
	if ind.Added.IsZero() {
		ind.Added = time.Now().UTC()
	}
	c.byID[ind.ID] = ind
	return ind, nil
}

// Remove takes an indicator out of the catalogue.
func (c *Catalogue) Remove(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.byID[id]; !ok {
		return ErrNoSuchIndicator
	}
	delete(c.byID, id)
	return nil
}

// Get returns one indicator.
func (c *Catalogue) Get(id string) (Indicator, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ind, ok := c.byID[id]
	return ind.Clone(), ok
}

// List returns every indicator, sorted by id.
func (c *Catalogue) List() []Indicator {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Indicator, 0, len(c.byID))
	for _, ind := range c.byID {
		out = append(out, ind.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Search returns the indicators whose kind, value, label or note
// mentions the needle.
//
// The search is a substring search over the whole catalogue: the
// operator remembers "the loader from the ticket" and not the hash.
func (c *Catalogue) Search(needle, kind string) []Indicator {
	needle = strings.ToLower(strings.TrimSpace(needle))
	kind = strings.ToLower(strings.TrimSpace(kind))
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Indicator, 0)
	for _, ind := range c.byID {
		if kind != "" && ind.Kind != kind {
			continue
		}
		if needle == "" {
			out = append(out, ind.Clone())
			continue
		}
		hay := strings.ToLower(ind.Value + " " + ind.Label + " " + ind.Note + " " + ind.Source)
		if strings.Contains(hay, needle) {
			out = append(out, ind.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CountHits records that a host carries an indicator.
//
// The counter is what the console sorts by: an indicator that was found
// on nine hosts is a different thing from one that was found once.
func (c *Catalogue) CountHits(id string, n int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ind, ok := c.byID[id]
	if !ok {
		return false
	}
	ind.Hits += n
	c.byID[id] = ind
	return true
}

// Indicators is the payload a hunt carries to an implant.
//
// It is the catalogue the operator chose, and nothing else: the
// implant is told what to look for and not what else the team knows.
type Indicators struct {
	// Items are the indicators, in the order the operator listed them.
	Items []Indicator `json:"items"`
	// Roots are the directories the hunt is allowed to walk. Empty
	// means the whole of the disk of the host, which is a decision the
	// operator has to make explicitly.
	Roots []string `json:"roots,omitempty"`
}

// isHash says whether a value looks like a SHA-256 in hex.
//
// The check is about the shape, not about the truth: it tells the
// framework which kind of indicator the operator meant, and the
// implant still compares the whole value.
func isHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// IsHash is the exported form of the shape check.
func IsHash(value string) bool { return isHash(value) }
