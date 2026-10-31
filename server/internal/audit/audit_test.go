package audit_test

import (
	"bufio"
	"encoding/json"
	"fmt"
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

func TestTheSecretsAreRedactedBeforeTheyReachTheLog(t *testing.T) {
	args := map[string]any{
		"token":    "the-operator-token",
		"password": "the-password",
		"agent":    "host-1",
		"cmd":      "id",
	}
	got := audit.Redact(args)
	if got["token"] != audit.Redacted {
		t.Errorf("the token was not redacted: %v", got["token"])
	}
	if got["password"] != audit.Redacted {
		t.Errorf("the password was not redacted: %v", got["password"])
	}
	if got["agent"] != "host-1" {
		t.Errorf("a harmless argument was changed: %v", got["agent"])
	}
	if got["cmd"] != "id" {
		t.Errorf("a harmless argument was changed: %v", got["cmd"])
	}
	// The original map is untouched: the redaction copies.
	if args["token"] != "the-operator-token" {
		t.Error("the redaction changed the caller's map")
	}
}

func TestTheArgumentsOfASecretTaskAreRedactedInFull(t *testing.T) {
	args := map[string]any{
		"host": "server-1",
		"path": "/etc/shadow",
	}
	got := audit.RedactArgs("creds.add", args)
	for key, value := range got {
		if value != audit.Redacted {
			t.Errorf("the argument %q of a secret task survived: %v", key, value)
		}
	}
}

func TestAQueuedSecretTaskIsRedactedInFull(t *testing.T) {
	// The command is "task.submit" and the secret is in the arguments of
	// the task it carries: the redaction has to look inside.
	args := map[string]any{
		"id":   "server-1",
		"kind": "creds.add",
		"args": map[string]any{
			"name":     "the-domain-admin",
			"password": "the-password",
		},
	}
	got := audit.RedactArgs("task.submit", args)
	inner, ok := got["args"].(map[string]any)
	if !ok {
		t.Fatalf("the arguments of the task are gone: %v", got["args"])
	}
	for key, value := range inner {
		if value != audit.Redacted {
			t.Errorf("the argument %q of a secret task survived: %v", key, value)
		}
	}
	// The name of the host is not a secret: it stays, so the trail says
	// what was attempted.
	if got["id"] != "server-1" {
		t.Errorf("a harmless argument was changed: %v", got["id"])
	}
}

func TestAnOrdinaryTaskKeepsItsArguments(t *testing.T) {
	args := map[string]any{
		"id":   "server-1",
		"kind": "shell",
		"args": map[string]any{
			"cmd": "whoami",
		},
	}
	got := audit.RedactArgs("task.submit", args)
	inner, ok := got["args"].(map[string]any)
	if !ok {
		t.Fatalf("the arguments of the task are gone: %v", got["args"])
	}
	if inner["cmd"] != "whoami" {
		t.Errorf("a harmless argument was changed: %v", inner["cmd"])
	}
}

func TestTheNestedValuesAreRedacted(t *testing.T) {
	args := map[string]any{
		"options": map[string]any{"secret": "the-secret", "name": "the-name"},
	}
	got := audit.Redact(args)
	nested, ok := got["options"].(map[string]any)
	if !ok {
		t.Fatalf("the nested map is gone: %v", got["options"])
	}
	if nested["secret"] != audit.Redacted {
		t.Errorf("the nested secret was not redacted: %v", nested["secret"])
	}
	if nested["name"] != "the-name" {
		t.Errorf("a harmless nested value was changed: %v", nested["name"])
	}
}

func TestASecretTaskWhoseArgumentsAreNotAMapIsRedactedWhole(t *testing.T) {
	// The arguments of a task are usually a map, but a script may send
	// them as a list or as a string.  Whatever they are, they are the
	// material of a secret task, so they do not reach the log.
	args := map[string]any{
		"id":   "server-1",
		"kind": "file.read",
		"args": []any{"/etc/shadow"},
	}
	got := audit.RedactArgs("task.submit", args)
	if got["args"] != audit.Redacted {
		t.Errorf("the arguments of a secret task survived: %v", got["args"])
	}
	if got["id"] != "server-1" {
		t.Errorf("a harmless argument was changed: %v", got["id"])
	}
}

// The ledger of the operator is a chain of hashes: a line that was edited
// after the fact breaks every link after it, and the verification says
// where the chain broke.
func TestTheLedgerIsAChainOfHashes(t *testing.T) {
	log, path := openTemp(t, audit.Options{})
	for i := 0; i < 3; i++ {
		err := log.Record(audit.Entry{Operator: "alice", Cmd: "agents.list", OK: true})
		if err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	result, err := audit.Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("the chain of a fresh ledger must hold: %+v", result)
	}
	if result.Entries != 3 {
		t.Fatalf("the ledger holds %d entries, the test wrote 3", result.Entries)
	}
	if result.Head == "" || result.Head != log.Head() {
		t.Fatalf("the head of the chain is %q, the logger says %q", result.Head, log.Head())
	}

	// A line that was edited after the fact breaks the chain.
	lines := readLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("the ledger holds %d lines", len(lines))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	edited := strings.Replace(string(raw), `"cmd":"agents.list"`, `"cmd":"engagement.wipe"`, 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	result, err = audit.Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.OK {
		t.Fatalf("an edited line must break the chain")
	}
	if result.BrokenAt != 1 {
		t.Fatalf("the chain broke at line %d, the edit was on line 1", result.BrokenAt)
	}
	if result.Reason == "" {
		t.Fatalf("the verification must say why the chain broke")
	}
}

// The chain continues where the file left off: a server that is restarted
// does not start a new ledger.
func TestTheChainContinuesAfterARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	first, err := audit.Open(audit.Options{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := first.Record(audit.Entry{Operator: "alice", Cmd: "agents.list", OK: true}); err != nil {
		t.Fatalf("record: %v", err)
	}
	head := first.Head()
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	second, err := audit.Open(audit.Options{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if second.Head() != head {
		t.Fatalf("the head after the restart is %q, the ledger said %q", second.Head(), head)
	}
	if err := second.Record(audit.Entry{Operator: "bob", Cmd: "task.submit", OK: true}); err != nil {
		t.Fatalf("record: %v", err)
	}
	result, err := audit.Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.OK || result.Entries != 2 {
		t.Fatalf("the chain must hold across the restart: %+v", result)
	}
}

// The verification walks the whole retention policy, not the first five
// files of it.
//
// A policy that keeps thirty generations and a check that reads five is a
// check that says "the ledger is whole" about a quarter of it.
func TestTheVerificationWalksAsFarAsTheRecordGoes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// Eight generations of a ledger, written by hand in the order the
	// rotation writes them: .8 is the oldest, the live file the newest.
	head := ""
	line := 0
	write := func(name string, n int) {
		var body strings.Builder
		for i := 0; i < n; i++ {
			line++
			e := audit.Entry{Operator: "alice", Cmd: "agents.list", OK: true}
			e.Now()
			e.Hash = audit.ChainHash(head, e)
			head = e.Hash
			raw, err := json.Marshal(e)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			body.Write(raw)
			body.WriteString("\n")
		}
		if err := os.WriteFile(name, []byte(body.String()), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	for i := 8; i >= 1; i-- {
		write(fmt.Sprintf("%s.%d", path, i), 2)
	}
	write(path, 2)

	result, err := audit.Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("the chain of eight generations did not verify: %s", result.Reason)
	}
	if result.Entries != 18 {
		t.Fatalf("the verification walked %d lines, want 18", result.Entries)
	}
	if result.Files != 9 {
		t.Fatalf("the verification walked %d files, want 9", result.Files)
	}
	if result.Head != head {
		t.Fatalf("the head of the walk is not the head of the ledger")
	}
	if len(result.Gaps) != 0 {
		t.Fatalf("the walk invented the gaps %v", result.Gaps)
	}

	// A deleted generation is a hole in the chain, and the answer says
	// where the hole is instead of walking over it.
	if err := os.Remove(path + ".4"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	result, err = audit.Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(result.Gaps) != 1 || result.Gaps[0] != 4 {
		t.Fatalf("the deleted generation was not reported: %v", result.Gaps)
	}
	if result.OK {
		t.Fatal("a chain with a hole in it verified")
	}
}

// A head carried from the outside is the check a rewrite cannot pass.
func TestTheExpectedHeadIsTheCheckTheServerCannotPass(t *testing.T) {
	log, path := openTemp(t, audit.Options{})
	for i := 0; i < 4; i++ {
		if err := log.Record(audit.Entry{Operator: "alice", Cmd: "agents.list", OK: true}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	head := log.Head()
	if head == "" {
		t.Fatal("the ledger has no head")
	}
	// The operator writes the head into a ticket before the night.
	ok, err := audit.VerifyAgainst(path, head)
	if err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
	if !ok.OK || ok.Matched == nil || !*ok.Matched {
		t.Fatalf("the head the operator carried did not match: %+v", ok)
	}
	// Somebody adds a line and rebuilds the chain: the chain verifies,
	// and the head from the outside does not.
	if err := log.Record(audit.Entry{Operator: "mallory", Cmd: "agents.kill", OK: true}); err != nil {
		t.Fatalf("record: %v", err)
	}
	after, err := audit.VerifyAgainst(path, head)
	if err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
	if after.OK {
		t.Fatal("a ledger that grew past the carried head still passed the carried head")
	}
	if after.Matched == nil || *after.Matched {
		t.Fatalf("the carried head matched a ledger it does not describe: %+v", after)
	}
	// Without a head the chain alone is checked, which is what it can do.
	plain, err := audit.Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if plain.Matched != nil {
		t.Fatal("a verification without an expected head reported a match")
	}
}

// The anchor is written by the ledger and read back by the check.
func TestTheAnchorRemembersTheHead(t *testing.T) {
	log, path := openTemp(t, audit.Options{})
	for i := 0; i < 3; i++ {
		if err := log.Record(audit.Entry{Operator: "alice", Cmd: "agents.list", OK: true}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	result, err := audit.Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Anchored {
		t.Fatal("the ledger wrote no anchor")
	}
	if !result.AnchorOK {
		t.Fatal("the anchor does not agree with the ledger")
	}
	if result.Anchor == "" {
		t.Fatal("the anchor carries no head")
	}
	// A ledger that was rewritten from the first line is not the ledger
	// the anchor describes, even when every link of it is valid.
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var body strings.Builder
	head := ""
	for _, text := range strings.Split(strings.TrimSpace(string(original)), "\n") {
		var e audit.Entry
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			t.Fatalf("parse: %v", err)
		}
		e.Operator = "mallory"
		e.Hash = ""
		e.Hash = audit.ChainHash(head, e)
		head = e.Hash
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		body.Write(raw)
		body.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	rewritten, err := audit.Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rewritten.OK {
		t.Fatal("the rewritten chain does not chain; the test is not testing the anchor")
	}
	if rewritten.AnchorOK {
		t.Fatal("a rewritten ledger agreed with the anchor it was written before")
	}
}

// The retention policy is a bound, and the rotation enforces it.
func TestTheRetentionPolicyBoundsTheDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	log, err := audit.Open(audit.Options{Path: path, MaxBytes: 256, Keep: 2})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer log.Close()
	for i := 0; i < 80; i++ {
		if err := log.Record(audit.Entry{Operator: "alice", Cmd: "agents.list",
			Detail: strings.Repeat("x", 40)}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if log.Keep() != 2 {
		t.Fatalf("the logger reports a keep of %d, want 2", log.Keep())
	}
	for i := 1; i <= 2; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", path, i)); err != nil {
			t.Fatalf("the policy keeps .%d and it is not there: %v", i, err)
		}
	}
	// Everything past the policy was removed: this is what stops a year of
	// engagement from being a full disk.
	for i := 3; i <= 6; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", path, i)); err == nil {
			t.Fatalf(".%d is still on the disk although the policy keeps 2", i)
		}
	}
}
