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
	"encoding/json"
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

// Logger appends entries to a file. A nil *Logger is valid and does nothing,
// so callers never need to check whether auditing is enabled.
type Logger struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	size   int64
	maxLen int64
	lines  uint64

	// keep a bounded in-memory ring so audit.tail does not have to re-read the
	// file for the common "show me the last N" case.
	ring []Entry
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
}

// DefaultMaxBytes is the rotation threshold when Options.MaxBytes is zero.
const DefaultMaxBytes = 8 << 20

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
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create directory: %w", err)
	}
	l := &Logger{path: opts.Path, maxLen: opts.MaxBytes, ring: make([]Entry, 0, opts.RingSize)}
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
	return nil
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

	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encode entry: %w", err)
	}
	raw = append(raw, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

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
	l.pushLocked(e)
	return nil
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
	for i := 4; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", l.path, i)
		to := fmt.Sprintf("%s.%d", l.path, i+1)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, to)
		}
	}
	_ = os.Rename(l.path, l.path+".1")
	if err := l.open(); err != nil {
		// Reopen failed: keep the in-memory record but report it.
		return err
	}
	return nil
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
	err := l.f.Close()
	l.f = nil
	return err
}
