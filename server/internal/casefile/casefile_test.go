package casefile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/casefile"
)

func TestTheChainOfCustodyHolds(t *testing.T) {
	r := casefile.New()
	c, err := r.Open("the ticket of March", "the loader of the ticket", "alice")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if c.State != casefile.StateOpen {
		t.Fatalf("the case is %q, want %q", c.State, casefile.StateOpen)
	}
	if len(c.Events) != 1 {
		t.Fatalf("the chain holds %d events, want 1", len(c.Events))
	}
	if _, err := r.Add(c.ID, "screenshot", "/var/lib/umbra/web-01.png",
		"aa11", "web-01", "t-1", "alice", "the screen of the host", 4096); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := r.Close(c.ID, "alice", "the engagement is over"); err != nil {
		t.Fatalf("close: %v", err)
	}
	got, ok := r.Get(c.ID)
	if !ok {
		t.Fatalf("the case is gone")
	}
	if got.State != casefile.StateClosed {
		t.Fatalf("the case is %q, want %q", got.State, casefile.StateClosed)
	}
	ok, brokenAt, reason := casefile.Verify(got)
	if !ok {
		t.Fatalf("the chain is broken at %d: %s", brokenAt, reason)
	}
	if len(got.Artefacts) != 1 {
		t.Fatalf("the case holds %d artefacts, want 1", len(got.Artefacts))
	}
	if got.Artefacts[0].Size != 4096 {
		t.Fatalf("the artefact is %d bytes, want 4096", got.Artefacts[0].Size)
	}
}

func TestAnEditedEventBreaksTheChain(t *testing.T) {
	r := casefile.New()
	c, err := r.Open("the case", "", "alice")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := r.Add(c.ID, "report", "/tmp/report.json", "bb22", "", "",
		"alice", "", 0); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, _ := r.Get(c.ID)
	// Somebody edits the note of an event after the fact.
	got.Events[0].Note = "the note somebody changed"
	ok, brokenAt, reason := casefile.Verify(got)
	if ok {
		t.Fatalf("the chain of an edited case holds")
	}
	if brokenAt != 1 {
		t.Fatalf("the chain breaks at %d, want 1", brokenAt)
	}
	if reason == "" {
		t.Fatalf("the broken chain has no reason")
	}
}

func TestARemovedEventBreaksTheChain(t *testing.T) {
	r := casefile.New()
	c, err := r.Open("the case", "", "alice")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := r.Add(c.ID, "report", "/tmp/report.json", "bb22", "", "",
		"alice", "", 0); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, _ := r.Get(c.ID)
	got.Events = got.Events[:1]
	ok, brokenAt, _ := casefile.Verify(got)
	if ok {
		t.Fatalf("the chain of a case with a removed event holds")
	}
	if brokenAt == 0 {
		t.Fatalf("the broken chain names no event")
	}
}

func TestAClosedCaseTakesNoMoreEvidence(t *testing.T) {
	r := casefile.New()
	c, err := r.Open("the case", "", "alice")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := r.Close(c.ID, "alice", ""); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := r.Add(c.ID, "report", "/tmp/report.json", "bb22", "", "",
		"alice", "", 0); err == nil {
		t.Fatalf("a closed case accepted another piece of evidence")
	}
	if err := r.Close(c.ID, "alice", "again"); err == nil {
		t.Fatalf("the case was closed twice")
	}
}

func TestTheCasesSurviveTheDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.json")
	r := casefile.New()
	r.SetPath(path)
	c, err := r.Open("the case of March", "", "alice")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := r.Add(c.ID, "report", "/tmp/report.json", "bb22", "web-01",
		"t-1", "alice", "", 12); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := r.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	back := casefile.New()
	back.SetPath(path)
	if err := back.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	got, ok := back.Get(c.ID)
	if !ok {
		t.Fatalf("the case is gone")
	}
	ok, brokenAt, reason := casefile.Verify(got)
	if !ok {
		t.Fatalf("the chain is broken at %d: %s", brokenAt, reason)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the registry is written with the mode %o, want 600", perm)
	}
}

func TestTheCaseFileIsWrittenForTheHandover(t *testing.T) {
	dir := t.TempDir()
	r := casefile.New()
	r.SetPath(filepath.Join(dir, "cases.json"))
	c, err := r.Open("the case of March", "", "alice")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := r.Add(c.ID, "report", "/tmp/report.json", "bb22", "", "",
		"alice", "", 0); err != nil {
		t.Fatalf("add: %v", err)
	}
	out, err := r.Export(c.ID, dir)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("the case file is missing: %v", err)
	}
}

func TestACaseNeedsATitle(t *testing.T) {
	r := casefile.New()
	if _, err := r.Open("   ", "", "alice"); err == nil {
		t.Fatalf("a case without a title was opened")
	}
}
