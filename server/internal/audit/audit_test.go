package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/audit"
)

func openTemp(t *testing.T, opts audit.Options) (*audit.Logger, string) {
	t.Helper()
	dir := t.TempDir()
	if opts.Path == "" {
		opts.Path = filepath.Join(dir, "audit.jsonl")
	}
	log, err := audit.Open(opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log, opts.Path
}

func readLines(t *testing.T, path string) []audit.Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []audit.Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line is not JSON: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func TestRecordAppendsJSONLines(t *testing.T) {
	log, path := openTemp(t, audit.Options{})
	for i := 0; i < 3; i++ {
		if err := log.Record(audit.Entry{Operator: "alice", Cmd: "agents.list", OK: true}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	entries := readLines(t, path)
	if len(entries) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Operator != "alice" || e.Cmd != "agents.list" || !e.OK {
			t.Errorf("entry lost data: %+v", e)
		}
		if e.At.IsZero() {
			t.Error("entry has no timestamp")
		}
	}
	if log.Lines() != 3 {
		t.Errorf("Lines() = %d, want 3", log.Lines())
	}
}

func TestNilLoggerIsSafe(t *testing.T) {
	var log *audit.Logger
	if err := log.Record(audit.Entry{Cmd: "ping"}); err != nil {
		t.Errorf("nil logger returned an error: %v", err)
	}
	if log.Enabled() {
		t.Error("nil logger reports enabled")
	}
	if got := log.Tail(5); got != nil {
		t.Errorf("nil logger returned entries: %v", got)
	}
	if err := log.Close(); err != nil {
		t.Errorf("nil logger close: %v", err)
	}

	// An empty path is the documented way to disable auditing.
	disabled, err := audit.Open(audit.Options{})
	if err != nil || disabled != nil {
		t.Fatalf("empty path should disable auditing, got %v / %v", disabled, err)
	}
}

func TestTailIsNewestFirstAndBounded(t *testing.T) {
	log, _ := openTemp(t, audit.Options{RingSize: 2})
	for i := 0; i < 5; i++ {
		if err := log.Record(audit.Entry{Cmd: "cmd", Detail: string(rune('a' + i))}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	got := log.Tail(3)
	if len(got) != 3 {
		t.Fatalf("Tail(3) returned %d entries", len(got))
	}
	if got[0].Detail != "e" || got[1].Detail != "d" || got[2].Detail != "c" {
		t.Fatalf("Tail is not newest-first: %v %v %v", got[0].Detail, got[1].Detail, got[2].Detail)
	}
	if tail := log.Tail(0); tail != nil {
		t.Errorf("Tail(0) returned %v", tail)
	}
}

// After a restart the in-memory ring is empty; the tail must fall back to the
// file, otherwise an operator sees an empty audit trail right after a deploy.
func TestTailReadsHistoryFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	first, err := audit.Open(audit.Options{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 4; i++ {
		if err := first.Record(audit.Entry{Cmd: "old"}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := audit.Open(audit.Options{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	got := second.Tail(10)
	if len(got) != 4 {
		t.Fatalf("expected 4 historical entries, got %d", len(got))
	}
}

func TestRotationKeepsTheTrail(t *testing.T) {
	log, path := openTemp(t, audit.Options{MaxBytes: 512})
	for i := 0; i < 40; i++ {
		if err := log.Record(audit.Entry{Operator: "alice", Cmd: "agents.list", Detail: strings.Repeat("x", 40)}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotation did not produce %s.1: %v", path, err)
	}
	// The current file must still be valid JSON Lines, and the newest record
	// must be in it (rotation moves the old data, never the new).
	entries := readLines(t, path)
	if len(entries) == 0 {
		t.Fatal("current file is empty after rotation")
	}
	if entries[len(entries)-1].Operator != "alice" {
		t.Errorf("unexpected last entry: %+v", entries[len(entries)-1])
	}
}

func TestConcurrentRecordsDoNotInterleave(t *testing.T) {
	log, path := openTemp(t, audit.Options{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				if err := log.Record(audit.Entry{Operator: "op", Cmd: "ping", OK: true}); err != nil {
					t.Errorf("record: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	entries := readLines(t, path) // fails if any line is torn
	if len(entries) != 128 {
		t.Fatalf("expected 128 entries, got %d", len(entries))
	}
}

func TestClipShortensLongFields(t *testing.T) {
	long := strings.Repeat("A", audit.MaxFieldLen*3)
	got := audit.Clip(long)
	if len([]rune(got)) > audit.MaxFieldLen+1 {
		t.Fatalf("Clip did not shorten: %d runes", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Error("truncation is not visible")
	}
	if short := "fine"; audit.Clip(short) != short {
		t.Error("Clip changed a short string")
	}
}
