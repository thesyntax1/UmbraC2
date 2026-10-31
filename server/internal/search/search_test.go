package search

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/note"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

func TestSmallLettersMatchAnyCasing(t *testing.T) {
	tasks := []*store.Task{
		{ID: "t-1", AgentID: "web-01", Kind: "shell", State: store.TaskDone,
			Output:    []byte("the FLAG-TANGO token is printed here\n"),
			Completed: time.Now().UTC()},
	}
	hits := Tasks(tasks, "flag-tango", 10)
	if len(hits) != 1 {
		t.Fatalf("the box did not find the needle: %v", hits)
	}
	if hits[0].Field != "output" || !strings.Contains(hits[0].Snippet, "FLAG-TANGO") {
		t.Fatalf("the snippet is not the piece around the word: %+v", hits[0])
	}
	// A capital in the needle means what it says: the box compares the
	// way the operator typed, so a mixed needle only finds the text that
	// carries the same capitals.
	if hits := Tasks(tasks, "flag-TANGO", 10); len(hits) != 0 {
		t.Fatalf("a mixed needle folded when it should not have: %v", hits)
	}
	if hits := Tasks(tasks, "FLAG-TANGO", 10); len(hits) != 1 {
		t.Fatalf("the needle typed in capitals was not found: %v", hits)
	}
	mixed := []*store.Task{
		{ID: "t-2", AgentID: "web-01", Kind: "shell", State: store.TaskDone,
			Output:    []byte("the flag-Tango line, written exactly so\n"),
			Completed: time.Now().UTC()},
	}
	if hits := Tasks(mixed, "flag-Tango", 10); len(hits) != 1 {
		t.Fatalf("a mixed needle did not find its own casing: %v", hits)
	}
	if hits := Tasks(tasks, "tango-flag", 10); len(hits) != 0 {
		t.Fatalf("the box found words that were never written: %v", hits)
	}
}

func TestTheBoxLeavesTheScreenshotsAlone(t *testing.T) {
	binary := append([]byte("BM"), bytes.Repeat([]byte{0, 1, 2, 3}, 64)...)
	tasks := []*store.Task{
		{ID: "t-1", AgentID: "web-01", Kind: "screenshot", State: store.TaskDone,
			Output: binary, Completed: time.Now().UTC()},
	}
	if hits := Tasks(tasks, "BM", 10); len(hits) != 0 {
		t.Fatalf("the box dug through a picture: %v", hits)
	}
}

func TestTheBoxSearchesTheWordsAndTheNotes(t *testing.T) {
	tasks := []*store.Task{
		{ID: "t-9", AgentID: "web-01", Kind: "shell", State: store.TaskQueued,
			Args: map[string]any{"cmd": "cat /root/tango-plan.txt"}},
	}
	hits := Tasks(tasks, "tango-plan", 10)
	if len(hits) != 1 || hits[0].Field != "args" {
		t.Fatalf("the words of a queued task were not found: %v", hits)
	}

	notes := []note.Note{
		{ID: "n-0001", AgentID: "web-01", Text: "the tango plan lives under /root",
			Author: "alice", Written: time.Now().UTC()},
	}
	found := Notes(notes, "tango", 10)
	if len(found) != 1 || found[0].NoteID != "n-0001" || found[0].Field != "text" {
		t.Fatalf("the note was not found: %v", found)
	}
	// A capital in the needle means what it says: the note holds a small
	// tango, and an exact Tango is not it.
	if found := Notes(notes, "Tango", 10); len(found) != 0 {
		t.Fatalf("the exact needle matched what it does not say: %v", found)
	}
}

func TestTheSnippetIsOneLine(t *testing.T) {
	text := strings.Repeat("a", 100) + "\n the tango word \n" + strings.Repeat("b", 200)
	piece, found := snippet(text, "tango", true)
	if !found {
		t.Fatal("the needle was not found")
	}
	if strings.ContainsAny(piece, "\r\n") {
		t.Fatalf("the snippet is more than one line: %q", piece)
	}
	if !strings.HasPrefix(piece, "…") || !strings.HasSuffix(piece, "…") {
		t.Fatalf("a cut piece is not marked as one: %q", piece)
	}
	if !strings.Contains(piece, "tango") {
		t.Fatalf("the piece does not carry the needle: %q", piece)
	}
}
