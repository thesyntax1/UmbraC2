// Package onboard is the welcome of a new host.
//
// Every engagement has the same first five minutes on a new host: the
// survey, the security software, the networks, the file that proves
// the day.  The playbook is those five minutes written down once —
// the stages, the filter of which hosts they are for, and the memory
// of who already received them, so the pack lands on the new host the
// moment it first calls home and never twice by accident.
//
// The rules of the welcome are the rules of a servant, not a master:
//
//   - it queues tasks and never writes to the host directly: the pack
//     is work, and work goes through the same queue, the same
//     breakers and the same dead letters as a task an operator typed;
//   - a playbook that fails for one host says so in its counter and
//     keeps crying for nobody: the failure is recorded, not retried
//     into a storm;
//   - the ledger of the fire survives a restart: a host that already
//     received its pack does not receive it again because the server
//     was bounced.
package onboard

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
// A welcome pack is the first five minutes of a host, not its whole
// deployment: sixteen stages is a survey, not an installation, and a
// playbook that needs more is a workflow, which has its own home.
const (
	// MaxPlaybooks bounds the playbook shelf.
	MaxPlaybooks = 64
	// MaxStages bounds the stages of one playbook.
	MaxStages = 16
	// MaxNameLen bounds the name of a playbook.
	MaxNameLen = 64
	// MaxArgsLen bounds the JSON of the arguments of one stage.
	MaxArgsLen = 4096
)

// The errors of the package.
var (
	// ErrNoName says the playbook was not named.
	ErrNoName = errors.New("onboard: the playbook was not named")
	// ErrNoStages says the playbook has no stages.
	ErrNoStages = errors.New("onboard: a playbook without stages welcomes nobody")
	// ErrBadStage says a stage is not a task kind the server knows how
	// to queue.
	ErrBadStage = errors.New("onboard: a stage is not a task kind")
	// ErrTooMany says the shelf is full.
	ErrTooMany = errors.New("onboard: the shelf of the playbooks is full")
	// ErrNoSuchPlaybook says the playbook is not on the shelf.
	ErrNoSuchPlaybook = errors.New("onboard: no such playbook")
	// ErrDuplicate says the name is taken: a team that cannot tell two
	// packs apart will run the wrong one on a bad day.
	ErrDuplicate = errors.New("onboard: a playbook has this name already")
)

// Stage is one task of the welcome pack: the kind, and the arguments
// that go with it.
type Stage struct {
	// Kind is the task kind, e.g. "sysinfo".
	Kind string `json:"kind"`
	// Args are the arguments the task is queued with.
	Args map[string]any `json:"args,omitempty"`
}

// clone copies the stage and its arguments.
func (s Stage) clone() Stage {
	out := Stage{Kind: s.Kind}
	if s.Args != nil {
		out.Args = make(map[string]any, len(s.Args))
		for k, v := range s.Args {
			out.Args[k] = v
		}
	}
	return out
}

// Playbook is the written-down welcome: the stages, the filter of the
// hosts it is for, and whether it fires once or on every return.
type Playbook struct {
	// ID is the short name the operator types: "w-0001".
	ID string `json:"id"`
	// Name is the human name of the pack.
	Name string `json:"name"`
	// Stages are the tasks that make the welcome, in order.
	Stages []Stage `json:"stages"`
	// Tag, when set, gates the pack: only hosts carrying the tag
	// receive it.
	Tag string `json:"tag,omitempty"`
	// Prefix, when set, gates the pack: only hosts whose id begins
	// with it receive it.
	Prefix string `json:"prefix,omitempty"`
	// Once says the pack fires on the first call home of a host and
	// never again.  When false, the pack fires on every return of the
	// host, held back by its cooldown.
	Once bool `json:"once"`
	// Cooldown is the seconds between two fires of a pack that is not
	// once.  Zero means an hour.
	Cooldown int64 `json:"cooldown,omitempty"`
	// Creator is the operator who wrote the playbook down.
	Creator string `json:"creator,omitempty"`
	// Created is when it was written down.
	Created time.Time `json:"created"`

	// Fires, LastFire, LastAgent and Failed are the memory of the
	// firing: how often the pack went out, when and to whom last, and
	// how many stages failed to queue over all time.
	Fires     int       `json:"fires"`
	LastFire  time.Time `json:"last_fire,omitempty"`
	LastAgent string    `json:"last_agent,omitempty"`
	Failed    int       `json:"failed"`
}

// QueueFunc is the way the pack puts its stages into the world: the
// server's own task queue, so nothing a playbook does is invisible to
// the queue an operator reads.
type QueueFunc func(agentID, kind string, args map[string]any) (string, error)

// LookupFunc is the way the pack reads the tags of a host.
type LookupFunc func(agentID string) (tags []string, ok bool)

// Registry holds the playbooks and the memory of their firing.
type Registry struct {
	mu    sync.Mutex
	plays map[string]Playbook
	fired map[string]map[string]time.Time // playbook → agent → when
	seq   int
	path  string

	// queue and lookup are wired by the server when it starts; Dispatch
	// without a queue is silent, and a fire without one is an error.
	queue  QueueFunc
	lookup LookupFunc
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{
		plays: make(map[string]Playbook),
		fired: make(map[string]map[string]time.Time),
	}
}

// SetQueue wires the task queue of the server.
func (r *Registry) SetQueue(q QueueFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queue = q
}

// SetLookup wires the way to read the tags of a host.
func (r *Registry) SetLookup(fn LookupFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookup = fn
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
	Version int                  `json:"version"`
	Seq     int                  `json:"seq"`
	SavedAt time.Time            `json:"saved_at"`
	Plays   []Playbook           `json:"plays"`
	Fired   map[string][]string  `json:"fired"`
	FiredAt map[string]time.Time `json:"fired_at"`
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
		return fmt.Errorf("onboard: read %s: %w", path, err)
	}
	var file ledgerFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("onboard: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plays = make(map[string]Playbook, len(file.Plays))
	for _, play := range file.Plays {
		if play.ID == "" {
			continue
		}
		r.plays[play.ID] = clonePlay(play)
	}
	r.seq = file.Seq
	r.fired = make(map[string]map[string]time.Time)
	for key, agents := range file.Fired {
		r.fired[key] = make(map[string]time.Time, len(agents))
		for _, agentID := range agents {
			stamp := key + "/" + agentID
			if when, ok := file.FiredAt[stamp]; ok {
				r.fired[key][agentID] = when
			} else {
				r.fired[key][agentID] = time.Now().UTC()
			}
		}
	}
	return nil
}

// Save writes the ledger to the disk, atomically and for the server
// alone.
func (r *Registry) Save() error {
	r.mu.Lock()
	path := r.path
	plays := make([]Playbook, 0, len(r.plays))
	for _, play := range r.plays {
		plays = append(plays, clonePlay(play))
	}
	fired := make(map[string][]string, len(r.fired))
	firedAt := make(map[string]time.Time)
	for key, agents := range r.fired {
		for agentID, when := range agents {
			fired[key] = append(fired[key], agentID)
			firedAt[key+"/"+agentID] = when
		}
	}
	seq := r.seq
	r.mu.Unlock()
	if path == "" {
		return nil
	}
	sort.Slice(plays, func(i, j int) bool { return plays[i].ID < plays[j].ID })
	for _, agents := range fired {
		sort.Strings(agents)
	}
	raw, err := json.MarshalIndent(ledgerFile{
		Version: 1, Seq: seq, SavedAt: time.Now().UTC(),
		Plays: plays, Fired: fired, FiredAt: firedAt,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("onboard: the ledger could not be written: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("onboard: %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("onboard: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("onboard: save the ledger: %w", err)
	}
	return nil
}

// clonePlay copies a playbook with its stages.
func clonePlay(p Playbook) Playbook {
	out := p
	out.Stages = make([]Stage, 0, len(p.Stages))
	for _, stage := range p.Stages {
		out.Stages = appendStages(out.Stages, stage)
	}
	return out
}

// appendStages appends a copy of the stage.
func appendStages(stages []Stage, stage Stage) []Stage {
	return append(stages, stage.clone())
}

// validKindName reports whether the string has the shape of a task
// kind: small letters, digits, dots and dashes.
func validKindName(kind string) bool {
	if kind == "" || len(kind) > 32 {
		return false
	}
	for _, r := range kind {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// Add writes one playbook down.
func (r *Registry) Add(p Playbook) (Playbook, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return Playbook{}, ErrNoName
	}
	if len(p.Name) > MaxNameLen {
		return Playbook{}, fmt.Errorf("onboard: the name is longer than %d", MaxNameLen)
	}
	if len(p.Stages) == 0 {
		return Playbook{}, ErrNoStages
	}
	if len(p.Stages) > MaxStages {
		return Playbook{}, fmt.Errorf("onboard: a playbook holds at most %d stages", MaxStages)
	}
	stages := make([]Stage, 0, len(p.Stages))
	for _, stage := range p.Stages {
		stage.Kind = strings.TrimSpace(stage.Kind)
		if !validKindName(stage.Kind) {
			return Playbook{}, fmt.Errorf("%w: %q", ErrBadStage, stage.Kind)
		}
		if stage.Args != nil {
			if raw, err := json.Marshal(stage.Args); err != nil || len(raw) > MaxArgsLen {
				return Playbook{}, fmt.Errorf("onboard: the arguments of %q are too long", stage.Kind)
			}
		}
		stages = appendStages(stages, stage)
	}
	p.Stages = stages
	p.Tag = strings.TrimSpace(p.Tag)
	p.Prefix = strings.TrimSpace(p.Prefix)
	// The record says what the sweep does.  A pack that fires on every
	// return and carries no cooldown is held back for an hour; leaving
	// the field at zero would make the listing read as "no cooldown"
	// while the sweep quietly applied one.
	if !p.Once && p.Cooldown <= 0 {
		p.Cooldown = 3600
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.plays) >= MaxPlaybooks {
		return Playbook{}, ErrTooMany
	}
	for _, existing := range r.plays {
		if existing.Name == p.Name {
			return Playbook{}, fmt.Errorf("%w: %q", ErrDuplicate, p.Name)
		}
	}
	r.seq++
	p.ID = fmt.Sprintf("w-%04d", r.seq)
	if p.Created.IsZero() {
		p.Created = time.Now().UTC()
	}
	r.plays[p.ID] = clonePlay(p)
	return clonePlay(p), nil
}

// Get returns one playbook.
func (r *Registry) Get(id string) (Playbook, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.plays[id]
	return clonePlay(p), ok
}

// List returns the playbooks, in the order they were written down.
func (r *Registry) List() []Playbook {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Playbook, 0, len(r.plays))
	for _, p := range r.plays {
		out = append(out, clonePlay(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Remove takes a playbook off the shelf.  The tasks it already queued
// stay queued: queued work is the past of the queue, not of the
// playbook.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.plays[id]; !ok {
		return ErrNoSuchPlaybook
	}
	delete(r.plays, id)
	delete(r.fired, id)
	return nil
}

// wants reports whether the playbook is for this host: the prefix of
// the id and one tag are either absent or matched.
func wants(p Playbook, agentID string, tags []string) bool {
	if p.Prefix != "" && !strings.HasPrefix(agentID, p.Prefix) {
		return false
	}
	if p.Tag != "" {
		for _, tag := range tags {
			if tag == p.Tag {
				return true
			}
		}
		return false
	}
	return true
}

// Dispatch is the tap the hub calls for every event.  The pack fires
// on the first call home of a host — and when it is not "once", on
// every return of the host, held back by its cooldown.
//
// The work of the pack is queued through the same queue as the work an
// operator types, so the limits of the queue, the breakers and the
// dead letters all apply to it, and a playbook filled by an operator
// is not a second way into the fleet.
func (r *Registry) Dispatch(ev hubEvent) {
	agentID := ev.AgentID
	if agentID == "" {
		return
	}
	newHost := ev.Kind == "agent.new"
	returned := ev.Kind == "agent.online"
	if !newHost && !returned {
		return
	}
	r.fire(agentID, newHost)
}

// hubEvent is the shape of the event the dispatch reads.  The playbook
// does not import the hub — the server hands it the two fields it
// needs, so the welcome of a host stays a servant of the hub, never a
// part of it.
type hubEvent struct {
	Kind    string
	AgentID string
}

// Event hands the registry the shape of a hub event.  The server calls
// this from its tap; the registry does not import the hub so the two
// packages never tangle.
func (r *Registry) Event(kind, agentID string) {
	r.Dispatch(hubEvent{Kind: kind, AgentID: agentID})
}

// fire runs the matching playbooks over the host.
func (r *Registry) fire(agentID string, newHost bool) {
	r.mu.Lock()
	queue := r.queue
	lookup := r.lookup
	type job struct {
		id     string
		stages []Stage
	}
	var jobs []job
	var tags []string
	if lookup != nil {
		tags, _ = lookup(agentID)
	}
	for id, p := range r.plays {
		if p.Once && !newHost {
			continue
		}
		if !newHost && !p.Once {
			cooldown := p.Cooldown
			if cooldown <= 0 {
				cooldown = 3600
			}
			if when, ok := r.fired[id][agentID]; ok &&
				time.Since(when) < time.Duration(cooldown)*time.Second {
				continue
			}
		}
		if p.Once {
			if _, ok := r.fired[id][agentID]; ok {
				continue
			}
		}
		if !wants(p, agentID, tags) {
			continue
		}
		stages := make([]Stage, 0, len(p.Stages))
		for _, stage := range p.Stages {
			stages = appendStages(stages, stage)
		}
		jobs = append(jobs, job{id: id, stages: stages})
	}
	r.mu.Unlock()
	if queue == nil {
		return
	}
	for _, j := range jobs {
		queued := 0
		failed := 0
		for _, stage := range j.stages {
			if _, err := queue(agentID, stage.Kind, stage.clone().Args); err != nil {
				failed++
				continue
			}
			queued++
		}
		r.mu.Lock()
		if p, ok := r.plays[j.id]; ok {
			p.Fires++
			p.LastFire = time.Now().UTC()
			p.LastAgent = agentID
			p.Failed += failed
			r.plays[j.id] = p
			if r.fired[j.id] == nil {
				r.fired[j.id] = make(map[string]time.Time)
			}
			r.fired[j.id][agentID] = p.LastFire
		}
		r.mu.Unlock()
	}
}

// Run fires one playbook over a host on purpose, the manual way: the
// filters and the "once" do not apply, because the operator who runs a
// pack by hand means exactly that.
func (r *Registry) Run(id, agentID string) (queued int, failed int, err error) {
	r.mu.Lock()
	p, ok := r.plays[id]
	queue := r.queue
	r.mu.Unlock()
	if !ok {
		return 0, 0, ErrNoSuchPlaybook
	}
	if strings.TrimSpace(agentID) == "" {
		return 0, 0, errors.New("onboard: the host was not named")
	}
	if queue == nil {
		return 0, 0, errors.New("onboard: the queue of the server is not wired")
	}
	for _, stage := range p.Stages {
		if _, err := queue(agentID, stage.Kind, stage.clone().Args); err != nil {
			failed++
			continue
		}
		queued++
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.plays[id]; ok {
		p.Fires++
		p.LastFire = time.Now().UTC()
		p.LastAgent = agentID
		p.Failed += failed
		r.plays[id] = p
		if r.fired[id] == nil {
			r.fired[id] = make(map[string]time.Time)
		}
		r.fired[id][agentID] = p.LastFire
	}
	return queued, failed, nil
}
