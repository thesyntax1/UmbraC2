// Package search is the digging box of the team.
//
// An engagement accretes records faster than anybody can read them:
// the outputs of the tasks, the notes the team writes, the credentials
// that come home.  The digging box is the one place an operator types
// a word and is shown every record that carries it — the task that
// printed it, the note that said it, the credential that hides it —
// with the piece of the text around the word, so the answer can be
// read without opening a second window.
//
// The rules of the box are the rules of reading, not of writing:
//
//   - it finds and never changes;
//   - it watches its mouth: an answer that is all a screenshot is not
//     an answer, so bytes that do not look like text stay unsearched;
//   - it is polite about casing: a needle of small letters matches any
//     casing, and a needle with a capital means what it says.
package search

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/thesyntax1/UmbraC2/server/internal/note"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// Limits.
//
// The box reads records that are dead and written down, not the stream
// of the moment: a needle longer than a sentence is a paste mistake,
// and a text longer than a page is searched only at its start, which
// is where operators look anyway.
const (
	// MaxQuery bounds the needle.
	MaxQuery = 256
	// MaxText bounds how much of one text is searched.
	MaxText = 64 * 1024
	// contextBefore is how much of the text before the hit is shown.
	contextBefore = 48
	// contextAfter is how much of the text after the hit is shown.
	contextAfter = 96
)

// Hit is one record that carries the needle: where it lives, which
// field it was in, and the piece of the text around it.
type Hit struct {
	// Where is the book the record lives in: "task", "note" or "creds".
	Where string `json:"where"`
	// TaskID is set for the hits that are tasks.
	TaskID string `json:"task_id,omitempty"`
	// NoteID is set for the hits that are notes.
	NoteID string `json:"note_id,omitempty"`
	// CredID is set for the hits that are credentials.
	CredID string `json:"cred_id,omitempty"`
	// AgentID is the host the record belongs to, when there is one.
	AgentID string `json:"agent_id,omitempty"`
	// Kind is the kind of the task, when the hit is a task.
	Kind string `json:"kind,omitempty"`
	// State is the state of the task, when the hit is a task.
	State string `json:"state,omitempty"`
	// Field is the field of the record the needle was found in:
	// "output", "args", "meta", "error", "id" or "kind" for a task,
	// "text" or "author" for a note, the named fields for a credential.
	Field string `json:"field"`
	// Snippet is the piece of the text around the needle.
	Snippet string `json:"snippet"`
	// At is the moment the record belongs to.
	At time.Time `json:"at,omitempty"`
}

// Fold says how the needle matches the text: a needle of small letters
// matches any casing, and a needle that carries a capital is matched
// the way it was typed.  The operator who types lower case wants to
// find; the operator who types a capital wants to be exact, and the
// box should know the difference without being asked.
func Fold(query string) (fold bool) {
	return query == strings.ToLower(query)
}

// looksText reports whether the bytes are probably words.  A screen
// shot saved as a task output is many bytes and no words: the box does
// not search what it cannot show, and what it cannot show it does not
// pretend to have searched.
func looksText(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	peek := raw
	if len(peek) > 512 {
		peek = peek[:512]
	}
	odd := 0
	for _, b := range peek {
		switch {
		case b == '\t' || b == '\n' || b == '\r':
		case b >= 0x20 && b < 0x7f:
		case b >= 0x80: // the words of the world are wider than ASCII
		default:
			odd++
		}
	}
	return odd <= len(peek)/16
}

// indexOf finds the needle in the text and returns the byte place of
// the first hit, or -1.  With folding it compares rune by rune, each
// side lowered, so the byte places of the haystack stay true.
func indexOf(text, needle string, fold bool) int {
	if needle == "" {
		return -1
	}
	if !fold {
		return strings.Index(text, needle)
	}
	runes := []rune(strings.ToLower(needle))
	if len(runes) == 0 {
		return -1
	}
	first := runes[0]
	for at, r := range text {
		if r == first || unicode.ToLower(r) == first {
			if matchAt(text[at:], runes) {
				return at
			}
		}
	}
	return -1
}

// matchAt reports whether the text starts with the runes of the
// needle, each compared the lowered way.
func matchAt(text string, needle []rune) bool {
	i := 0
	for _, want := range needle {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size == 0 {
			return false
		}
		if unicode.ToLower(r) != want {
			return false
		}
		i += size
	}
	return true
}

// square collapses the whitespace of a snippet into single spaces: the
// piece around the hit is one line of the answer, and the line should
// read like one.
func square(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// snippet cuts the piece of the text around the first hit of the
// needle.  The cut is made in runes, so a word of the wider world is
// never torn in half.
func snippet(text, needle string, fold bool) (string, bool) {
	if len(text) > MaxText {
		text = text[:MaxText]
	}
	at := indexOf(text, needle, fold)
	if at < 0 {
		return "", false
	}
	beforeRunes := utf8.RuneCountInString(text[:at])
	needleRunes := utf8.RuneCountInString(needle)
	start := beforeRunes - contextBefore
	if start < 0 {
		start = 0
	}
	end := beforeRunes + needleRunes + contextAfter
	runes := []rune(text)
	if end > len(runes) {
		end = len(runes)
	}
	piece := square(string(runes[start:end]))
	if piece == "" {
		return "", false
	}
	head, tail := "", ""
	if start > 0 {
		head = "…"
	}
	if end < len(runes) {
		tail = "…"
	}
	return head + piece + tail, true
}

// Tasks digs through the tasks for the needle.  The identity of a task
// is searched with everything else — its id, its kind, its words and
// its error — because the half of a task id an operator remembers is
// still a way to find it.
func Tasks(tasks []*store.Task, query string, limit int) []Hit {
	fold := Fold(query)
	out := make([]Hit, 0, limit)
	for _, t := range tasks {
		if limit > 0 && len(out) >= limit {
			break
		}
		fields := []struct{ name, text string }{
			{"id", t.ID},
			{"kind", t.Kind},
			{"error", t.Err},
		}
		if raw, err := json.Marshal(t.Args); err == nil {
			fields = append(fields, struct{ name, text string }{"args", string(raw)})
		}
		if raw, err := json.Marshal(t.Meta); err == nil {
			fields = append(fields, struct{ name, text string }{"meta", string(raw)})
		}
		if looksText(t.Output) {
			fields = append(fields, struct{ name, text string }{"output", string(t.Output)})
		}
		for _, field := range fields {
			piece, found := snippet(field.text, query, fold)
			if !found {
				continue
			}
			when := t.Completed
			if when.IsZero() {
				when = t.Created
			}
			out = append(out, Hit{
				Where:   "task",
				TaskID:  t.ID,
				AgentID: t.AgentID,
				Kind:    t.Kind,
				State:   t.State,
				Field:   field.name,
				Snippet: piece,
				At:      when,
			})
			break
		}
	}
	return out
}

// Notes digs through the notes of the team for the needle.
func Notes(notes []note.Note, query string, limit int) []Hit {
	fold := Fold(query)
	out := make([]Hit, 0, limit)
	for _, entry := range notes {
		if limit > 0 && len(out) >= limit {
			break
		}
		for _, field := range []struct{ name, text string }{
			{"text", entry.Text},
			{"author", entry.Author},
		} {
			piece, found := snippet(field.text, query, fold)
			if !found {
				continue
			}
			out = append(out, Hit{
				Where:   "note",
				NoteID:  entry.ID,
				AgentID: entry.AgentID,
				Field:   field.name,
				Snippet: piece,
				At:      entry.Written,
			})
			break
		}
	}
	return out
}

// Creds digs through the credentials the team brought home.  The
// store has already narrowed the rows to the ones that carry the
// needle; the box names the place of it the way a console shows it.
func Creds(rows []store.Credential, query string, limit int) []Hit {
	fold := Fold(query)
	out := make([]Hit, 0, limit)
	for _, row := range rows {
		if limit > 0 && len(out) >= limit {
			break
		}
		for _, field := range []struct{ name, text string }{
			{"account", row.Account},
			{"target", row.Target},
			{"source", row.Source},
			{"kind", row.Kind},
			{"note", row.Note},
		} {
			piece, found := snippet(field.text, query, fold)
			if !found {
				continue
			}
			out = append(out, Hit{
				Where:   "creds",
				CredID:  row.ID,
				AgentID: row.AgentID,
				Field:   field.name,
				Snippet: piece,
				At:      row.Collected,
			})
			break
		}
	}
	return out
}

// SortHits orders the hits of one book by their moment, newest first:
// the answer an operator reads starts where the engagement is, not
// where it was.
func SortHits(hits []Hit) {
	sort.SliceStable(hits, func(i, j int) bool {
		return hits[i].At.After(hits[j].At)
	})
}
