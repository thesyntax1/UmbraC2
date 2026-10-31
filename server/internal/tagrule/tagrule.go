// Package tagrule is the sorting hat of the fleet.
//
// The team names the hosts by hand today: "this one is a domain
// controller", "that one is the laptop of the accountant".  The rule is
// that sentence written down once — the field it reads, what the field
// contains, and the tag the host earns — and the hat fits it on the
// head of every host the moment the host first calls home, so the
// segmenting of the fleet is the memory of the server and not the
// memory of an operator.
//
// The rules of the hat are the rules of a polite guest:
//
//   - it adds tags and never removes them: a tag an operator wrote by
//     hand is not the hat's to take away, and a rule that was deleted
//     leaves yesterday's tags standing;
//   - it works on arrival: a tag that settles between the first hello
//     and the first question saves the question, while a rule that ran
//     continuously would only find the hosts it already found;
//   - each rule answers once per host: the firing is remembered, so a
//     re-registered host does not get relabelled and the ledger of the
//     label is a ledger of facts, not of loops.
package tagrule

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
// The sorting hat is the colouring of the fleet, not its brain: 256
// rules is a taxonomy, more is a confusion.
const (
	// MaxRules bounds the shelf of the rules.
	MaxRules = 256
	// MaxNameLen bounds the name of a rule.
	MaxNameLen = 64
	// MaxTagLen bounds the tag a rule can hang on a host.
	MaxTagLen = 64
	// MaxMatchLen bounds the needle a rule looks for.
	MaxMatchLen = 128
)

// The errors of the package.
var (
	// ErrNoName says the rule was not named.
	ErrNoName = errors.New("tagrule: the rule was not named")
	// ErrNoTag says the rule hangs no tag.
	ErrNoTag = errors.New("tagrule: a rule without a tag colours nobody")
	// ErrNoMatch says the rule looks for nothing.
	ErrNoMatch = errors.New("tagrule: a rule that looks for nothing fires on everything")
	// ErrBadField says the field is not one the arrival of a host brings.
	ErrBadField = errors.New("tagrule: the field is not one the host tells on arrival")
	// ErrTooMany says the shelf is full.
	ErrTooMany = errors.New("tagrule: the shelf of the rules is full")
	// ErrNoSuchRule says the rule is not on the shelf.
	ErrNoSuchRule = errors.New("tagrule: no such rule")
	// ErrDuplicate says a rule with this name is already here.
	ErrDuplicate = errors.New("tagrule: a rule has this name already")
)

// Fields are what a host tells on arrival, and nothing else: the hat
// reads the facts the hello already carried, never the host itself.
var Fields = []string{"os", "arch", "host", "user", "transport", "version"}

// Rule is one sentence of the sorting hat: when the field of the host
// contains the needle, the host earns the tag.
type Rule struct {
	// ID is the short name the operator types: "r-0001".
	ID string `json:"id"`
	// Name is the human name of the rule.
	Name string `json:"name"`
	// Field is what the rule reads: os, arch, host, user, transport or
	// version.
	Field string `json:"field"`
	// Contains is the needle, matched without case: "windows", "-dc-".
	Contains string `json:"contains,omitempty"`
	// Prefix, when set, is matched against the start of the field
	// instead: "db-" for the database hosts, "win-" for the naming
	// scheme of the fleet.
	Prefix string `json:"prefix,omitempty"`
	// Tag is the label the host earns.
	Tag string `json:"tag"`
	// Creator is the operator who wrote the rule down.
	Creator string `json:"creator,omitempty"`
	// Created is when it was written down.
	Created time.Time `json:"created"`

	// Fires counts how often the rule coloured a host, LastFire and
	// LastAgent name the moment and the host of the last one.
	Fires     int       `json:"fires"`
	LastFire  time.Time `json:"last_fire,omitempty"`
	LastAgent string    `json:"last_agent,omitempty"`
}

// clone copies the rule, so a caller cannot reach the ledger.
func (r Rule) clone() Rule { return r }

// matches says whether the rule fires.  tags is what the host already
// carries: a host that already wears the tag is not told twice.
func (r Rule) matches(facts map[string]string, tags map[string]bool) bool {
	if r.Tag == "" {
		return false
	}
	if tags[strings.ToLower(r.Tag)] {
		return false
	}
	value := strings.ToLower(facts[r.Field])
	if r.Contains != "" && strings.Contains(value, strings.ToLower(r.Contains)) {
		return true
	}
	if r.Prefix != "" && strings.HasPrefix(value, strings.ToLower(r.Prefix)) {
		return true
	}
	return false
}

// LookupFunc reads the facts of a host on arrival: the os, arch, host,
// user, transport and version it told, and the tags it already wears.
type LookupFunc func(agentID string) (facts map[string]string, tags []string, ok bool)

// TagFunc hangs one tag on a host, as gently as the agents.tag command
// does: "add" mode, with its event and its audit line.
type TagFunc func(agentID string, tags []string, mode string) error

// hubEvent is the smallest piece of the hub the hat needs, so the
// package never imports the hub it is served by.
type hubEvent struct {
	Kind    string
	AgentID string
}

// Registry is the shelf of the rules plus the memory of the fires.
type Registry struct {
	mu    sync.Mutex
	rules map[string]Rule
	seq   int
	path  string

	// fired remembers who each rule already coloured, so the hat does
	// not loop on a returning host.
	fired map[string]map[string]time.Time

	lookup LookupFunc
	tag    TagFunc
}

// New creates an empty shelf.
func New() *Registry {
	return &Registry{
		rules: make(map[string]Rule),
		fired: make(map[string]map[string]time.Time),
	}
}

// SetLookup wires the way to read the arrival facts of a host.
func (r *Registry) SetLookup(fn LookupFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookup = fn
}

// SetTag wires the way to hang a tag on a host.
func (r *Registry) SetTag(fn TagFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tag = fn
}

// SetPath tells the shelf where to keep itself.
func (r *Registry) SetPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path = path
}

// Path is where the shelf is kept, empty when it is not kept.
func (r *Registry) Path() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.path
}

type ledgerRow struct {
	Rules []Rule `json:"rules"`
	// Fired keeps the memory of the fires as rule -> host list: the
	// whentime is recomputed on load, the hat only needs the fact.
	Fired map[string][]string `json:"fired,omitempty"`
}

// Load reads the ledger written by Save.  A missing ledger is an empty
// shelf, not an error.
func (r *Registry) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path == "" {
		return nil
	}
	raw, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var row ledgerRow
	if err := json.Unmarshal(raw, &row); err != nil {
		return fmt.Errorf("tagrule: read %s: %w", r.path, err)
	}
	maxSeq := 0
	for _, rule := range row.Rules {
		if rule.ID == "" {
			continue
		}
		r.rules[rule.ID] = rule
		var n int
		if _, err := fmt.Sscanf(rule.ID, "r-%04d", &n); err == nil && n > maxSeq {
			maxSeq = n
		}
	}
	r.seq = maxSeq
	for id, hosts := range row.Fired {
		set := map[string]time.Time{}
		for _, host := range hosts {
			set[host] = time.Now().UTC()
		}
		r.fired[id] = set
	}
	return nil
}

// Save writes the shelf atomically, for the server alone: the rules of
// the sorting hat tell a reader what the fleet is named after, which is
// an intelligence summary of its own.
func (r *Registry) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path == "" {
		return nil
	}
	row := ledgerRow{
		Rules: make([]Rule, 0, len(r.rules)),
		Fired: make(map[string][]string, len(r.fired)),
	}
	for _, rule := range r.rules {
		row.Rules = append(row.Rules, rule.clone())
	}
	for id, set := range r.fired {
		hosts := make([]string, 0, len(set))
		for host := range set {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		row.Fired[id] = hosts
	}
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// validField says whether the field is one the arrival of a host brings.
func validField(field string) bool {
	for _, f := range Fields {
		if field == f {
			return true
		}
	}
	return false
}

// Add writes a rule down.
func (r *Registry) Add(rule Rule) (Rule, error) {
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		return Rule{}, ErrNoName
	}
	if len(rule.Name) > MaxNameLen {
		return Rule{}, fmt.Errorf("tagrule: the name is longer than %d", MaxNameLen)
	}
	rule.Field = strings.ToLower(strings.TrimSpace(rule.Field))
	if !validField(rule.Field) {
		return Rule{}, ErrBadField
	}
	rule.Contains = strings.TrimSpace(rule.Contains)
	rule.Prefix = strings.TrimSpace(rule.Prefix)
	if rule.Contains == "" && rule.Prefix == "" {
		return Rule{}, ErrNoMatch
	}
	if len(rule.Contains) > MaxMatchLen || len(rule.Prefix) > MaxMatchLen {
		return Rule{}, fmt.Errorf("tagrule: the needle is longer than %d", MaxMatchLen)
	}
	rule.Tag = strings.TrimSpace(rule.Tag)
	if rule.Tag == "" {
		return Rule{}, ErrNoTag
	}
	if len(rule.Tag) > MaxTagLen {
		return Rule{}, fmt.Errorf("tagrule: the tag is longer than %d", MaxTagLen)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rules) >= MaxRules {
		return Rule{}, ErrTooMany
	}
	for _, other := range r.rules {
		if strings.EqualFold(other.Name, rule.Name) {
			return Rule{}, ErrDuplicate
		}
	}
	r.seq++
	rule.ID = fmt.Sprintf("r-%04d", r.seq)
	rule.Created = time.Now().UTC()
	r.rules[rule.ID] = rule.clone()
	return rule, nil
}

// Get reads one rule.
func (r *Registry) Get(id string) (Rule, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rule, ok := r.rules[id]
	if !ok {
		return Rule{}, false
	}
	return rule.clone(), true
}

// List reads the shelf.
func (r *Registry) List() []Rule {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Remove takes a rule out of the shelf.  The tags it hung yesterday
// stay where they are: the hat edits the future, not the past.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rules[id]; !ok {
		return ErrNoSuchRule
	}
	delete(r.rules, id)
	delete(r.fired, id)
	return nil
}

// Dispatch is what the tap calls with an event.
func (r *Registry) Dispatch(ev hubEvent) {
	switch ev.Kind {
	case "agent.new", "agent.online":
	default:
		return
	}
	if ev.AgentID == "" {
		return
	}
	r.fire(ev.AgentID)
}

// Event wires the hub events in without the hub: the server hands the
// kind and the host, the hat does the rest.
func (r *Registry) Event(kind, agentID string) {
	r.Dispatch(hubEvent{Kind: kind, AgentID: agentID})
}

// fire fits the rules on the host.  The tags are hung outside the lock,
// because a tag is work (it has its own event and its own audit line)
// and no lock in the world wants work done under it.
func (r *Registry) fire(agentID string) {
	r.mu.Lock()
	lookup, tag := r.lookup, r.tag
	if lookup == nil || tag == nil {
		r.mu.Unlock()
		return
	}
	facts, tags, ok := lookup(agentID)
	if !ok {
		r.mu.Unlock()
		return
	}
	worn := map[string]bool{}
	for _, t := range tags {
		worn[strings.ToLower(t)] = true
	}
	type job struct {
		id  string
		tag string
	}
	var jobs []job
	for id, rule := range r.rules {
		if r.fired[id] != nil {
			if _, done := r.fired[id][agentID]; done {
				continue
			}
		}
		if !rule.matches(facts, worn) {
			continue
		}
		jobs = append(jobs, job{id: id, tag: rule.Tag})
		worn[strings.ToLower(rule.Tag)] = true // two rules, one tag: one hang
	}
	r.mu.Unlock()
	for _, j := range jobs {
		if err := tag(agentID, []string{j.tag}, "add"); err != nil {
			continue
		}
		now := time.Now().UTC()
		r.mu.Lock()
		if rule, ok := r.rules[j.id]; ok {
			rule.Fires++
			rule.LastFire = now
			rule.LastAgent = agentID
			r.rules[j.id] = rule
		}
		if r.fired[j.id] == nil {
			r.fired[j.id] = make(map[string]time.Time)
		}
		r.fired[j.id][agentID] = now
		r.mu.Unlock()
	}
}
