// Package audit appends one JSON object per operator action to a file.
//
// A C2 server without an audit trail cannot answer the two questions that
// matter after an engagement: who ran what, and when. Every operator RPC is
// recorded before the reply is sent, so the log is authoritative even if the
// operator disappears mid-command.
//
// The log is append-only JSON Lines: one object per line, flushed and fsynced
// per entry, rotated by size. It is deliberately boring so that `jq`, `grep`
// and a spreadsheet can all read it.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxFieldLen bounds a single free-form field (a command, an error string) so
// one huge argument cannot make a log line unbounded.
const MaxFieldLen = 512

// Entry is one recorded operator action.
//
// Field order is fixed: JSON Lines readers care about stability, and a diff
// between two entries should show only what actually changed.
type Entry struct {
	At        time.Time `json:"at"`
	Operator  string    `json:"operator"`
	Peer      string    `json:"peer,omitempty"`
	Transport string    `json:"transport,omitempty"`
	Cmd       string    `json:"cmd"`
	OK        bool      `json:"ok"`
	Err       string    `json:"err,omitempty"`
	AgentID   string    `json:"agent_id,omitempty"`
	TaskID    string    `json:"task_id,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Millis    int64     `json:"ms"`
	// Hash is the link of the entry to the entry before it.  The chain
	// of the hashes is what makes the ledger tamper-evident: a line
	// that was edited after the fact breaks the chain, and the break
	// says where.
	Hash string `json:"hash,omitempty"`
}

// ChainHash computes the link of an entry to the one before it.
//
// The hash covers the bytes of the entry and the hash of the entry
// before it, so a line that was edited, removed or added breaks every
// link after it.  The head of the chain is the proof of the whole
// ledger: it can be written down, signed or given to a third party.
func ChainHash(head string, e Entry) string {
	// The hash of the entry is not part of the bytes it signs.
	e.Hash = ""
	body, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte(head+"|"), body...))
	return hex.EncodeToString(sum[:])
}

// Now stamps the entry and fills in the coarse outcome fields.
func (e *Entry) Now() { e.At = time.Now().UTC() }

// Clip shortens a free-form string to MaxFieldLen runes, marking truncation.
// Runes rather than bytes so a multi-byte command is not cut mid-character.
func Clip(s string) string {
	if len(s) <= MaxFieldLen {
		return s
	}
	r := []rune(s)
	if len(r) <= MaxFieldLen {
		return s
	}
	return string(r[:MaxFieldLen]) + "…"
}

// Redacted is what a secret looks like in the log.
const Redacted = "[redacted]"

// secretNames are the argument names whose value is a secret.
//
// The list is by name, not by value: the audit trail must be able to say
// *that* a credential was stored without saying what it was, and a value
// that looks like a secret is not a reliable signal (a password can be
// "x", a note can look like a token).
var secretNames = map[string]bool{
	"token":         true,
	"tokens":        true,
	"psk":           true,
	"password":      true,
	"pass":          true,
	"secret":        true,
	"secrets":       true,
	"credential":    true,
	"credentials":   true,
	"key":           true,
	"keys":          true,
	"api_key":       true,
	"private_key":   true,
	"session_key":   true,
	"vault_key":     true,
	"enc_key":       true,
	"encryption":    true,
	"content":       true,
	"contents":      true,
	"data":          true,
	"body":          true,
	"value":         true,
	"auth":          true,
	"authorization": true,
	"nonce":         true,
}

// secretKinds are the task kinds whose arguments are secret in full.
//
// A task that reads a file or stores a credential carries its material in
// an argument whose name nobody can guess, so the whole argument map is
// redacted for them.
var secretKinds = map[string]bool{
	"creds.add":    true,
	"creds.import": true,
	"cred.add":     true,
	"file.read":    true,
	"file.write":   true,
	"upload":       true,
	"exfil":        true,
}

// Redact returns a copy of the arguments with the secrets removed.
//
// It is used for the audit trail, and it is deliberately conservative: a
// secret is never written to the log, even when the log is the only place
// the operator would look for it.
func Redact(args map[string]any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		if secretNames[strings.ToLower(k)] {
			out[k] = Redacted
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

// redactValue redacts the secret-bearing parts of a nested value.
func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return Redact(x)
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, redactValue(item))
		}
		return out
	default:
		return v
	}
}

// RedactArgs redacts the arguments of a command.
//
// The command may be an RPC ("task.submit") or a task kind ("creds.add").
// Both are known: the secret kinds are the ones whose arguments carry
// material in full, and a task submitted through "task.submit" is
// redacted as a whole when its kind is one of them.
func RedactArgs(cmd string, args map[string]any) map[string]any {
	kind := strings.TrimSpace(cmd)
	if secretKinds[kind] {
		// The whole argument map is secret: only the keys survive, so
		// the log still says what was attempted.
		return redactAll(args)
	}
	out := Redact(args)
	// A task that is queued carries its own arguments, and the kind
	// that says whether they are secret in full.
	if taskKind, ok := args["kind"].(string); ok && secretKinds[strings.TrimSpace(taskKind)] {
		if inner, ok := args["args"].(map[string]any); ok {
			out["args"] = redactAll(inner)
		} else if _, present := args["args"]; present {
			// The arguments are not a map: they are still the
			// material of a secret task, so they go away whole.
			out["args"] = Redacted
		}
	}
	return out
}

// redactAll redacts every value of a map and keeps the keys.
func redactAll(args map[string]any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]any, len(args))
	for k := range args {
		out[k] = Redacted
	}
	return out
}

// Logger appends entries to a file. A nil *Logger is valid and does nothing,
// so callers never need to check whether auditing is enabled.
type Logger struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	size   int64
	maxLen int64
	lines  uint64
	keep   int

	// keep a bounded in-memory ring so audit.tail does not have to re-read the
	// file for the common "show me the last N" case.
	ring []Entry

	// head is the hash of the last entry written: the tip of the chain.
	head string
}

// Options configures a Logger.
type Options struct {
	// Path is the JSONL file. Empty disables auditing (Open returns nil, nil).
	Path string
	// MaxBytes triggers rotation (*.1, *.2, ...). Zero means 8 MiB.
	MaxBytes int64
	// RingSize is how many recent entries stay in memory for Tail. Zero means
	// 256.
	RingSize int
	// Keep is how many rotated files are kept next to the live one
	// (the .1, .2, ...).  Zero means DefaultKeep; a value above MaxKeep
	// is clamped.  A retention policy is a promise: the oldest file is
	// removed when a rotation makes a new one, so the ledger occupies a
	// bounded part of the disk for ever.
	Keep int
}

// DefaultMaxBytes is the rotation threshold when Options.MaxBytes is zero.
const DefaultMaxBytes = 8 << 20

// DefaultKeep is how many rotated files are kept when Options.Keep is zero:
// the bounded ledger of a lab, about 48 MiB at the default rotation size.
const DefaultKeep = 5

// MaxKeep is the most rotated files an operator may ask for.  A ledger
// nobody can afford to keep is a ledger that gets deleted by hand.
const MaxKeep = 100

// DefaultRingSize is the in-memory tail when Options.RingSize is zero.
const DefaultRingSize = 256

// Open prepares the audit log. A nil Logger with a nil error means "auditing is
// disabled", which is what an empty path asks for.
func Open(opts Options) (*Logger, error) {
	if opts.Path == "" {
		return nil, nil
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.RingSize <= 0 {
		opts.RingSize = DefaultRingSize
	}
	if opts.Keep <= 0 {
		opts.Keep = DefaultKeep
	}
	if opts.Keep > MaxKeep {
		opts.Keep = MaxKeep
	}
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create directory: %w", err)
	}
	l := &Logger{path: opts.Path, maxLen: opts.MaxBytes, keep: opts.Keep,
		ring: make([]Entry, 0, opts.RingSize)}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", l.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: stat %s: %w", l.path, err)
	}
	l.f = f
	l.size = info.Size()
	// The chain continues where the file left off: the head of the last
	// line is the head of the chain, or the empty string for a fresh
	// ledger.  A rotation reopens the file of a logger that already has
	// a head, and that head is the one of the chain.
	if l.head == "" {
		l.head = l.readHead()
	}
	return nil
}

// readHead reads the ledger and returns the hash of its last entry.  A
// ledger that cannot be parsed has no head: the chain starts again, and
// the verification says so.
func (l *Logger) readHead() string {
	head := ""
	for _, file := range ledgerFiles(l.path) {
		if h := lastHash(file); h != "" {
			head = h
		}
	}
	return head
}

// ledgerFiles lists the files of a ledger, oldest first.
//
// The chain of a ledger continues through a rotation: the first entry of
// a fresh file follows the last entry of the file before it, so the
// verification has to walk the rotations before the current file.
func ledgerFiles(path string) []string {
	out := make([]string, 0, MaxKeep+1)
	for i := MaxKeep; i >= 1; i-- {
		name := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(name); err == nil {
			out = append(out, name)
		}
	}
	return append(out, path)
}

// ledgerGaps says which generations the chain is missing.
//
// A rotation walks the files up one step, so the generations of a ledger
// are a run: .1, .2, .3 without a hole.  A hole is either a file that was
// deleted after the fact — which is exactly the thing the ledger exists
// to survive — or a rotation that failed half way.  Either way the
// verification has to say it instead of walking on quietly.
func ledgerGaps(path string) []int {
	present := map[int]bool{}
	highest := 0
	for i := 1; i <= MaxKeep; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", path, i)); err == nil {
			present[i] = true
			highest = i
		}
	}
	gaps := make([]int, 0, 2)
	for i := 1; i <= highest; i++ {
		if !present[i] {
			gaps = append(gaps, i)
		}
	}
	return gaps
}

// lastHash returns the hash of the last entry of a file of the ledger.
func lastHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	head := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return ""
		}
		head = e.Hash
	}
	return head
}

// Path returns the configured file ("" when disabled).
func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Enabled reports whether anything will be written.
func (l *Logger) Enabled() bool { return l != nil && l.f != nil }

// Record appends one entry. It never panics and never blocks the caller on a
// disk error: a failed write is returned so the caller can log it, but the
// operator request itself must not be aborted because of the audit file.
func (l *Logger) Record(e Entry) error {
	if !l.Enabled() {
		return nil
	}
	if e.At.IsZero() {
		e.Now()
	}
	e.Err = Clip(e.Err)
	e.Detail = Clip(e.Detail)

	l.mu.Lock()
	defer l.mu.Unlock()

	// The entry is linked to the one before it before it is written, so
	// the chain on the disk is the chain in the memory.
	e.Hash = ChainHash(l.head, e)
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encode entry: %w", err)
	}
	raw = append(raw, '\n')

	if l.size+int64(len(raw)) > l.maxLen {
		if err := l.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := l.f.Write(raw); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	// fsync per entry: an audit line that is lost in a crash is worse than a
	// slow log. The volume is one line per operator command.
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("audit: sync: %w", err)
	}
	l.size += int64(len(raw))
	l.lines++
	l.head = e.Hash
	l.pushLocked(e)
	// The anchor is written every so often and at every stop: it is the
	// one line of the ledger that is cheap to carry home, and the check
	// that survives a rewrite of the rest.
	if l.lines%anchorEvery == 0 {
		if err := WriteAnchor(l.path, l.head); err != nil {
			// A ledger that cannot write its anchor is still a ledger:
			// the chain is on the disk, and the next stop tries again.
			_ = err
		}
	}
	return nil
}

// anchorEvery is how many entries pass between two anchors.
//
// One anchor per few hundred commands is a file small enough to copy into
// a ticket by hand, and recent enough that a rewrite of yesterday's tail
// cannot hide behind it.
const anchorEvery = 256

// VerifyResult is the answer of the verification of a ledger.
type VerifyResult struct {
	// Entries is the number of the entries that were checked.
	Entries int `json:"entries"`
	// OK says whether the chain holds from the first line to the last.
	OK bool `json:"ok"`
	// BrokenAt is the number of the line where the chain breaks.
	BrokenAt int `json:"broken_at,omitempty"`
	// Head is the hash of the last entry: the tip of the chain.
	Head string `json:"head"`
	// Reason says why the chain broke.
	Reason string `json:"reason,omitempty"`
	// Files is how many files of the ledger were walked, rotations
	// included: the check covers the whole policy, not the current file.
	Files int `json:"files"`
	// Gaps are the generations the chain is missing (a deleted rotation).
	Gaps []int `json:"gaps,omitempty"`
	// Anchor is the head the anchor file remembers, when there is one.
	Anchor string `json:"anchor,omitempty"`
	// Anchored says whether the anchor was compared, and AnchorOK
	// whether the ledger still agrees with it.
	Anchored bool `json:"anchored"`
	AnchorOK bool `json:"anchor_ok"`
	// Expected is the head the caller brought from the outside, and
	// Matched says whether the ledger ends where that head said it did.
	Expected string `json:"expected,omitempty"`
	Matched  *bool  `json:"matched,omitempty"`
}

// Verify walks a ledger and checks the chain of its hashes.
//
// The walk stops at the first broken link and says which line it was:
// an entry that was edited, removed or added after the fact cannot be
// put back without breaking every link after it, and that is the whole
// point of the chain.
func Verify(path string) (VerifyResult, error) { return VerifyAgainst(path, "") }

// VerifyAgainst walks a ledger and compares its end with a head the caller
// brought from the outside.
//
// `expect` is the answer to the question the chain alone cannot answer:
// a chain that was rebuilt from the first line to the last is a chain
// that verifies.  A head that was written down somewhere the server
// cannot reach — a ticket, a board, another machine — is what turns the
// ledger from tamper-evident into tamper-checked.  An empty `expect`
// asks the chain alone.
func VerifyAgainst(path, expect string) (VerifyResult, error) {
	out := VerifyResult{OK: true}
	if strings.TrimSpace(path) == "" {
		return out, errors.New("audit: the ledger has no file")
	}
	files := ledgerFiles(path)
	out.Files = len(files)
	out.Gaps = ledgerGaps(path)
	head := ""
	line := 0
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return out, fmt.Errorf("audit: open %s: %w", file, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line++
			text := strings.TrimSpace(scanner.Text())
			if text == "" {
				continue
			}
			var e Entry
			if err := json.Unmarshal([]byte(text), &e); err != nil {
				_ = f.Close()
				out.OK = false
				out.BrokenAt = line
				out.Reason = "the line is not a ledger entry"
				return out, nil
			}
			if want := ChainHash(head, e); want != e.Hash {
				_ = f.Close()
				out.OK = false
				out.BrokenAt = line
				out.Reason = "the entry does not follow the one before it"
				return out, nil
			}
			head = e.Hash
			out.Entries++
		}
		err = scanner.Err()
		_ = f.Close()
		if err != nil {
			return out, fmt.Errorf("audit: read %s: %w", file, err)
		}
	}
	out.Head = head
	// The anchor: the head the logger wrote down the last time it
	// stopped, and whether the ledger still ends there.
	if anchor, ok := readAnchor(path); ok && anchor.Head != "" {
		out.Anchored = true
		out.Anchor = anchor.Head
		// The anchor is the head of an earlier moment, so it is a prefix
		// of the chain, not its end: the ledger agrees when the line the
		// anchor counted at still hashes to what the anchor says.
		out.AnchorOK = anchorAgrees(path, anchor)
	}
	if expected := strings.TrimSpace(expect); expected != "" {
		out.Expected = expected
		matched := expected == head
		out.Matched = &matched
		if !matched {
			out.OK = false
			if out.Reason == "" {
				out.Reason = "the ledger does not end where the expected head said it did"
			}
		}
	}
	return out, nil
}

// Matcher is the verdict of an expected head, nil when none was given.
//
// It is a pointer because the difference between "the caller brought no
// head" and "the caller's head did not match" is the whole answer.
func (r VerifyResult) Matcher() *bool { return r.Matched }

// anchor is the line the server wrote down, in plain sight.
//
// The file lives next to the ledger, so it is a consistency check and not
// a defence on its own: an attacker who can rewrite the ledger can
// rewrite the anchor beside it.  What makes it worth writing is the
// ordinary failure — a truncated file, a restore from a backup that is
// older than the ledger, a rotation that was deleted — and what makes it
// worth shipping is the head the operator carries home.
type anchor struct {
	Head string    `json:"head"`
	At   time.Time `json:"at"`
}

// anchorPath is where the head of the ledger is written down.
func anchorPath(path string) string { return path + ".head" }

// readAnchor reads the head the logger wrote down.
func readAnchor(path string) (anchor, bool) {
	raw, err := os.ReadFile(anchorPath(path))
	if err != nil {
		return anchor{}, false
	}
	var a anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		return anchor{}, false
	}
	return a, true
}

// WriteAnchor writes the head of the chain down beside the ledger.
//
// It is the check the operator can carry: a head written into a ticket
// before a long night is the one thing a rewrite of the ledger cannot
// satisfy.
func WriteAnchor(path, head string) error {
	if strings.TrimSpace(path) == "" || head == "" {
		return nil
	}
	raw, err := json.Marshal(anchor{Head: head, At: time.Now().UTC()})
	if err != nil {
		return err
	}
	tmp := anchorPath(path) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("audit: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, anchorPath(path)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: write the anchor: %w", err)
	}
	return nil
}

// anchorAgrees says whether the chain still passes through the head the
// anchor remembers.
//
// The anchor names one link of the chain, not its end: the ledger keeps
// growing after the anchor was written.  A chain that was rewritten from
// the first line to the last never produces that link again — the
// attacker cannot forge a line whose hash is a hash they were given — so
// the walk either meets the anchor or proves the ledger is not the one
// that was anchored.  A ledger that was cut before the anchor fails the
// same way, because the walk never reaches it.
func anchorAgrees(path string, a anchor) bool {
	if a.Head == "" {
		return false
	}
	for _, file := range ledgerFiles(path) {
		f, err := os.Open(file)
		if err != nil {
			return false
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text == "" {
				continue
			}
			var e Entry
			if err := json.Unmarshal([]byte(text), &e); err != nil {
				_ = f.Close()
				return false
			}
			if e.Hash == a.Head {
				_ = f.Close()
				return true
			}
		}
		_ = f.Close()
	}
	return false
}

// Head returns the hash of the last entry written: the tip of the chain.
func (l *Logger) Head() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

func (l *Logger) pushLocked(e Entry) {
	if cap(l.ring) == 0 {
		return
	}
	if len(l.ring) == cap(l.ring) {
		copy(l.ring, l.ring[1:])
		l.ring[len(l.ring)-1] = e
		return
	}
	l.ring = append(l.ring, e)
}

// rotateLocked renames the current file to <path>.1 (shifting older ones) and
// starts a fresh one. Rotation is best effort: if the rename fails the log keeps
// growing rather than dropping records.
func (l *Logger) rotateLocked() error {
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
	keep := l.keep
	if keep <= 0 {
		keep = DefaultKeep
	}
	for i := keep - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", l.path, i)
		to := fmt.Sprintf("%s.%d", l.path, i+1)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, to)
		}
	}
	_ = os.Rename(l.path, l.path+".1")
	// The policy is a bound: a file past the keep is from a day with a
	// longer policy, and the ledger does not keep what it promised not
	// to keep.
	for i := keep + 1; i <= MaxKeep+1; i++ {
		_ = os.Remove(fmt.Sprintf("%s.%d", l.path, i))
	}
	if err := l.open(); err != nil {
		// Reopen failed: keep the in-memory record but report it.
		return err
	}
	return nil
}

// Keep is how many rotated files the ledger keeps, for the reading of the
// policy: the operator should be able to ask what the server promises.
func (l *Logger) Keep() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.keep <= 0 {
		return DefaultKeep
	}
	return l.keep
}

// Lines returns how many entries this process has written.
func (l *Logger) Lines() uint64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines
}

// Tail returns up to n recent entries, newest first. It answers from the
// in-memory ring first and falls back to scanning the file, so a freshly
// restarted server can still show history.
func (l *Logger) Tail(n int) []Entry {
	if !l.Enabled() || n <= 0 {
		return nil
	}
	l.mu.Lock()
	ring := make([]Entry, len(l.ring))
	copy(ring, l.ring)
	l.mu.Unlock()

	if len(ring) >= n {
		out := make([]Entry, 0, n)
		for i := len(ring) - 1; i >= 0 && len(out) < n; i-- {
			out = append(out, ring[i])
		}
		return out
	}
	fromFile, err := l.readTail(n)
	if err != nil || len(fromFile) == 0 {
		// Fall back to whatever the ring holds.
		out := make([]Entry, 0, len(ring))
		for i := len(ring) - 1; i >= 0; i-- {
			out = append(out, ring[i])
		}
		return out
	}
	return fromFile
}

// readTail opens the log read-only and returns the last n entries, newest
// first. It deliberately does not touch the writer's file descriptor: the log
// may be rotating underneath us, and a scanner over an append handle is easy to
// get wrong.
func (l *Logger) readTail(n int) ([]Entry, error) {
	l.mu.Lock()
	path := l.path
	l.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]Entry, 0, n)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// A torn last line (crash mid-write) must not break the tail.
			continue
		}
		if len(buf) == n {
			copy(buf, buf[1:])
			buf[len(buf)-1] = e
			continue
		}
		buf = append(buf, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make([]Entry, 0, len(buf))
	for i := len(buf) - 1; i >= 0; i-- {
		out = append(out, buf[i])
	}
	return out, nil
}

// Close flushes and closes the file. Safe to call twice.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	// The last word of the process is written down before the file is
	// closed: an engagement that stops at the end of the day leaves the
	// head of its ledger behind, and the next morning starts against it.
	if l.head != "" {
		if err := WriteAnchor(l.path, l.head); err != nil {
			_ = l.f.Close()
			l.f = nil
			return err
		}
	}
	err := l.f.Close()
	l.f = nil
	return err
}
