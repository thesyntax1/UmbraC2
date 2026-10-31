// Package hook is the wire to the outside world.
//
// A console watches the events of the engagement by staying connected.
// The team that wants the events somewhere else — a chat room, a pager,
// a ticket queue, a logging pipeline — writes down a URL, and the
// server posts every event that matches to that URL.  The wire is
// one-way: the server tells, and never asks, so a machine the wire
// points at learns what the team chose to send and nothing more.
//
// The rules are the ones the other ledgers keep:
//
//   - a mutex of its own, a file next to the state file, and a limit
//     on how much it holds;
//   - the file is written for the server alone: the secrets in it sign
//     the words of the team, and a file the world can read is a wire
//     anybody can speak on;
//   - the wire never blocks the engagement: every event is carried in
//     its own goroutine, a wire that is busy is dropped and counted,
//     and the answer is in the book of deliveries either way.
package hook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/hub"
)

// Limits.
//
// The wires are the ways the server talks to the outside world, not a
// broadcast tower: a team with sixty-four places to tell the news is a
// team that already has too many, and a delivery book longer than a
// page of attention is a book nobody reads.
const (
	// MaxHooks bounds how many wires the team may write down.
	MaxHooks = 64
	// MaxURLLen bounds the length of one address.
	MaxURLLen = 512
	// MaxKinds bounds how many kinds one wire subscribes to.
	MaxKinds = 32
	// MaxKindLen bounds the name of one kind on a wire.
	MaxKindLen = 64
	// MaxDeliveries bounds the book of the deliveries the server keeps.
	MaxDeliveries = 256
	// inflight bounds how many posts run at the same moment.
	inflight = 16
	// postTimeout is how long one post to the outside may take.
	postTimeout = 4 * time.Second
)

// The errors of the package.
var (
	// ErrNoURL says that the address of the wire was not written.
	ErrNoURL = errors.New("hook: the URL was not written")
	// ErrBadURL says that the address is not one the server will post to:
	// http or https, a host, and nothing else clever.
	ErrBadURL = errors.New("hook: the URL is not one the server posts to")
	// ErrBadKind says that a kind name on the wire is not a kind name.
	ErrBadKind = errors.New("hook: a kind name on the wire is not a kind")
	// ErrTooMany says that the ledger is full.
	ErrTooMany = errors.New("hook: the team writes down too many wires")
	// ErrNoSuchHook says that the wire is not in the ledger.
	ErrNoSuchHook = errors.New("hook: no such wire")
)

// Hook is one wire: the address the server posts to, the kinds of the
// events it carries, and the secret that signs them.
//
// The kinds match a name exactly, or with a trailing star as a
// beginning: "task.*" carries every event of a task.  An empty list
// carries everything.
type Hook struct {
	// ID is the short name the operator types: "h-0003".
	ID string `json:"id"`
	// URL is where the post goes.
	URL string `json:"url"`
	// Kinds are the event kinds the wire carries; an empty list is all.
	Kinds []string `json:"kinds,omitempty"`
	// Secret signs the body the server posts: the receiver checks the
	// X-Umbra-Signature header against its own copy, and a post that
	// does not match is a post from somebody else.  The secret never
	// leaves the ledger: it is written for the server alone and never
	// appears in an answer.
	Secret string `json:"secret,omitempty"`
	// Creator is the operator who wrote the wire down.
	Creator string `json:"creator,omitempty"`
	// Created is when the wire was written down.
	Created time.Time `json:"created"`
}

// Clone returns a copy of the wire with its own list of kinds.
func (h Hook) Clone() Hook {
	c := h
	c.Kinds = append([]string(nil), h.Kinds...)
	return c
}

// Delivery is one post the server made down a wire: what it was, when
// it went, how the other end answered and how long it took.  The book
// of the deliveries is how the team checks the wires without asking
// the outside world anything.
type Delivery struct {
	// HookID is the wire the post went down.
	HookID string `json:"hook_id"`
	// Kind is the kind of the event that was posted.
	Kind string `json:"kind"`
	// Seq is the number of the event in the journal of the server.
	Seq uint64 `json:"seq,omitempty"`
	// When is when the post left.
	When time.Time `json:"when"`
	// Status is the answer of the other end, zero when there was none.
	Status int `json:"status"`
	// LatencyMS is how long the post took, in milliseconds.
	LatencyMS int64 `json:"latency_ms"`
	// Err is why the post failed, empty when it did not.
	Err string `json:"err,omitempty"`
}

// envelope is what one post carries: the event the console would have
// seen, numbered and timed the same way, so the outside record and the
// journal inside never disagree about what happened.
type envelope struct {
	Seq     uint64         `json:"seq,omitempty"`
	Kind    string         `json:"kind"`
	AgentID string         `json:"agent_id,omitempty"`
	TaskID  string         `json:"task_id,omitempty"`
	At      time.Time      `json:"at"`
	Data    map[string]any `json:"data,omitempty"`
	// Test marks the post that came from `hook.test`, so the receiver
	// can answer it without paging anybody.
	Test bool `json:"test,omitempty"`
}

// Registry holds the wires of the team and the book of the deliveries.
type Registry struct {
	mu         sync.Mutex
	byID       map[string]Hook
	seq        int
	path       string
	deliveries []Delivery
	sem        chan struct{}
	client     *http.Client
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{
		byID: make(map[string]Hook),
		sem:  make(chan struct{}, inflight),
		client: &http.Client{
			Timeout: postTimeout,
			// A wire is one post and one answer: following a redirect is
			// how the words of the team end up on a server nobody chose.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
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
	Hooks   []Hook    `json:"hooks"`
}

// Load reads the ledger back.
//
// A file that cannot be read is not fatal: the server starts with no
// wires and says so, because a wire the team forgot is better than a
// server that does not start.
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
		return fmt.Errorf("hook: read %s: %w", path, err)
	}
	var file ledgerFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("hook: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID = make(map[string]Hook, len(file.Hooks))
	for _, h := range file.Hooks {
		if h.ID == "" {
			continue
		}
		r.byID[h.ID] = h.Clone()
	}
	r.seq = file.Seq
	return nil
}

// Save writes the ledger to the disk.
//
// The secrets of the wires travel inside the file, so the write is
// atomic and belongs to the server alone.
func (r *Registry) Save() error {
	r.mu.Lock()
	path := r.path
	hooks := make([]Hook, 0, len(r.byID))
	for _, h := range r.byID {
		hooks = append(hooks, h.Clone())
	}
	seq := r.seq
	r.mu.Unlock()
	if path == "" {
		return nil
	}
	sort.Slice(hooks, func(i, j int) bool { return hooks[i].ID < hooks[j].ID })
	raw, err := json.MarshalIndent(ledgerFile{
		Version: 1,
		Seq:     seq,
		SavedAt: time.Now().UTC(),
		Hooks:   hooks,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("hook: the ledger could not be written: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("hook: %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("hook: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hook: save the ledger: %w", err)
	}
	return nil
}

// validURL reports whether the address is one the server posts to.
//
// The wire is for telling the news to a place the team chose: http and
// https only, a host the address names, no fragment, and no clever
// scheme the operator did not mean.
func validURL(raw string) bool {
	if raw == "" || len(raw) > MaxURLLen {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" || u.Fragment != "" {
		return false
	}
	return true
}

// validKind reports whether one pattern on a wire names events: small
// letters, digits, dots and dashes, with one star allowed at the end
// as a beginning-of-the-name match.
func validKind(pattern string) bool {
	if pattern == "" || len(pattern) > MaxKindLen {
		return false
	}
	body := pattern
	if strings.HasSuffix(pattern, "*") {
		body = pattern[:len(pattern)-1]
	}
	if body == "" {
		return false
	}
	for _, r := range body {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// carries reports whether the wire carries the event: a name matches
// exactly, or a name ending in a star matches the beginning of the
// kind, and the empty list carries everything.
func carries(patterns []string, kind string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if pattern == kind {
			return true
		}
		if strings.HasSuffix(pattern, "*") &&
			strings.HasPrefix(kind, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

// Add writes one wire down.
func (r *Registry) Add(h Hook) (Hook, error) {
	h.URL = strings.TrimSpace(h.URL)
	if h.URL == "" {
		return Hook{}, ErrNoURL
	}
	if !validURL(h.URL) {
		return Hook{}, ErrBadURL
	}
	kinds := make([]string, 0, len(h.Kinds))
	seen := make(map[string]bool, len(h.Kinds))
	for _, pattern := range h.Kinds {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if !validKind(pattern) {
			return Hook{}, fmt.Errorf("%w: %q", ErrBadKind, pattern)
		}
		if seen[pattern] {
			continue
		}
		seen[pattern] = true
		kinds = append(kinds, pattern)
	}
	if len(kinds) > MaxKinds {
		return Hook{}, fmt.Errorf("hook: a wire carries at most %d kinds", MaxKinds)
	}
	h.Kinds = kinds
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.byID) >= MaxHooks {
		return Hook{}, ErrTooMany
	}
	r.seq++
	h.ID = fmt.Sprintf("h-%04d", r.seq)
	if h.Created.IsZero() {
		h.Created = time.Now().UTC()
	}
	r.byID[h.ID] = h.Clone()
	return h.Clone(), nil
}

// Get returns one wire.
func (r *Registry) Get(id string) (Hook, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.byID[id]
	return h.Clone(), ok
}

// List returns the wires, in the order they were written down.
func (r *Registry) List() []Hook {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Hook, 0, len(r.byID))
	for _, h := range r.byID {
		out = append(out, h.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Remove takes a wire out of the ledger.  The posts the wire already
// delivered are not unsent: they are the past, and the book of the
// deliveries keeps them.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		return ErrNoSuchHook
	}
	delete(r.byID, id)
	return nil
}

// Last returns the newest delivery of one wire, so the answer that
// lists the wires can say how each one is doing without a second call.
func (r *Registry) Last(hookID string) (Delivery, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.deliveries) - 1; i >= 0; i-- {
		if r.deliveries[i].HookID == hookID {
			return r.deliveries[i], true
		}
	}
	return Delivery{}, false
}

// Deliveries returns the newest posts the server made, newest last.
func (r *Registry) Deliveries(limit int) []Delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]Delivery(nil), r.deliveries...)
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// record writes one delivery into the book.
func (r *Registry) record(d Delivery) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliveries = append(r.deliveries, d)
	if len(r.deliveries) > MaxDeliveries {
		copy(r.deliveries, r.deliveries[len(r.deliveries)-MaxDeliveries:])
		r.deliveries = r.deliveries[:MaxDeliveries]
	}
}

// Dispatch is the tap the hub calls for every event it emits.
//
// The wires that carry the kind each get their own goroutine, so a
// receiver that is slow keeps nothing waiting; when more posts are
// running than the server allows, the event is dropped down that wire
// and the book says so, because a quiet lie is worse than a loud drop.
func (r *Registry) Dispatch(ev hub.Event) {
	r.mu.Lock()
	var wires []Hook
	for _, h := range r.byID {
		if carries(h.Kinds, ev.Kind) {
			wires = append(wires, h.Clone())
		}
	}
	r.mu.Unlock()
	for _, h := range wires {
		select {
		case r.sem <- struct{}{}:
		default:
			r.record(Delivery{
				HookID: h.ID, Kind: ev.Kind, Seq: ev.Seq,
				When:   time.Now().UTC(),
				Err:    "the wire was busy; the event was dropped",
				Status: 0,
			})
			continue
		}
		go func(h Hook) {
			defer func() { <-r.sem }()
			// A wire is the outside world: nothing it does is allowed to
			// take the server down with it.
			defer func() { _ = recover() }()
			r.deliver(h, envelope{
				Seq: ev.Seq, Kind: ev.Kind, AgentID: ev.AgentID,
				TaskID: ev.TaskID, At: ev.At, Data: ev.Data,
			})
		}(h)
	}
}

// Test sends one synthetic event down one wire, right away, and waits
// for the answer.  The operator who just wrote the wire down learns
// from the book whether the other end is listening, instead of waiting
// for the engagement to make news.
func (r *Registry) Test(id, by string) (Delivery, error) {
	h, ok := r.Get(id)
	if !ok {
		return Delivery{}, ErrNoSuchHook
	}
	return r.deliver(h, envelope{
		Kind: "hook.test",
		At:   time.Now().UTC(),
		Data: map[string]any{"by": by},
		Test: true,
	}), nil
}

// deliver posts one event down one wire and writes the delivery into
// the book.  The post speaks JSON, names the event in a header, and
// signs the body when the wire has a secret: HMAC-SHA256 in hex, after
// the word "sha256=", the way the receivers of the world expect it.
func (r *Registry) deliver(h Hook, ev envelope) Delivery {
	started := time.Now()
	d := Delivery{HookID: h.ID, Kind: ev.Kind, Seq: ev.Seq, When: started.UTC()}
	body, err := json.Marshal(ev)
	if err != nil {
		d.Err = fmt.Sprintf("the event could not be packed: %v", err)
		r.record(d)
		return d
	}
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		d.Err = fmt.Sprintf("the address could not be used: %v", err)
		r.record(d)
		return d
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "umbra-hook/1")
	req.Header.Set("X-Umbra-Event", ev.Kind)
	if h.Secret != "" {
		mac := hmac.New(sha256.New, []byte(h.Secret))
		mac.Write(body)
		req.Header.Set("X-Umbra-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := r.client.Do(req)
	if err != nil {
		d.LatencyMS = time.Since(started).Milliseconds()
		d.Err = err.Error()
		r.record(d)
		return d
	}
	// The body of the answer is nobody's business: it is drained so the
	// connection can be reused, and then forgotten.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	d.Status = resp.StatusCode
	d.LatencyMS = time.Since(started).Milliseconds()
	r.record(d)
	return d
}
