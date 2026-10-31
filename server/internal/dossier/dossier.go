// Package dossier gathers what the server knows about one host.
//
// A dossier is the answer to the question an operator asks at the end of
// an engagement: "what do we know about this machine, and what did we
// do to it?".  The server already keeps the inventory, the tasks, the
// persistence, the posture, the health, the canaries and the approvals
// of every host, and the dossier puts the pieces of one host on one
// page.
//
// The package does not read the store: the caller hands over the
// records, so the rules of the dossier can be read and tested without
// the rest of the server.  The same is true of the health it carries:
// the score and its reasons are the score of the health package, and
// the dossier only puts them in the place where the operator reads
// them.
//
// Three rules hold:
//
//   - the work is counted, not described: the dossier says how many
//     tasks the host ran, how many failed and how many are still
//     waiting;
//   - a broken thing is named: a broken persistence entry, a canary
//     that was touched, an approval that nobody decided -- each of them
//     is a line of its own, because a line an operator reads is worth
//     more than a paragraph;
//   - what is missing is said as well: a host that never checked in
//     has no posture and no persistence, and the dossier says so
//     instead of showing empty tables.
package dossier

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/approval"
	"github.com/thesyntax1/UmbraC2/server/internal/canary"
	"github.com/thesyntax1/UmbraC2/server/internal/health"
)

// Task is one piece of work the server ran on the host.
type Task struct {
	// ID is the id of the task.
	ID string
	// Kind is what the task was.
	Kind string
	// State is "queued", "done" or "failed".
	State string
	// Created is when it was queued.
	Created time.Time
	// Completed is when it was answered.
	Completed time.Time
	// Err is what went wrong, when something did.
	Err string
	// Attested says that the answer carried the signature of the agent.
	Attested bool
}

// Persist is one entry of the persistence of the host.
type Persist struct {
	// Technique is the id of the technique.
	Technique string
	// Name is the label the operator gave it.
	Name string
	// Trigger is what starts it.
	Trigger string
	// Location is where it lives on the host.
	Location string
	// State is "installed" or "broken".
	State string
}

// Host is what the dossier needs to know about a host.
type Host struct {
	// ID is the host.
	ID string
	// Host is the name of the machine.
	Host string
	// OS and Arch are what the host runs.
	OS   string
	Arch string
	// User is the account the implant runs as.
	User string
	// Version is the version of the implant.
	Version string
	// Transport is how it reaches the server.
	Transport string
	// Addr is where it comes from.
	Addr string
	// Tags are the labels of the operator.
	Tags []string
	// State is "online" or "offline".
	State string
	// FirstSeen and LastSeen are the times of the host.
	FirstSeen time.Time
	LastSeen  time.Time
	// Checkins is how many times the host answered.
	Checkins uint64
	// Uptime is how long the implant said it had been running.
	Uptime int64
	// Impersonation is the account the implant took.
	Impersonation string
	// Posture is what the implant thinks of the machine.
	Posture string
	// Health is the score of the host, with its reasons.
	Health health.Report
	// Tasks are the pieces of work the server ran.
	Tasks []Task
	// Persist is the persistence of the host.
	Persist []Persist
	// Canaries are the tripwires planted on the host.
	Canaries []canary.Canary
	// Approvals are the requests about the host.
	Approvals []approval.Request
	// Notes are the lines the console wrote about the host.  They live
	// in the database of the console and not on the server, so they are
	// not part of the dossier: the server does not read them.
	Notes []string
}

// Dossier is the file of one host.
type Dossier struct {
	// ID is the host.
	ID string `json:"id"`
	// Host is the name of the machine.
	Host string `json:"host"`
	// OS, Arch and User say what it is.
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
	User string `json:"user,omitempty"`
	// Version is the version of the implant.
	Version string `json:"version,omitempty"`
	// Transport and Addr say how it reaches the server.
	Transport string `json:"transport,omitempty"`
	Addr      string `json:"addr,omitempty"`
	// Tags are the labels of the operator.
	Tags []string `json:"tags,omitempty"`
	// State is "online" or "offline".
	State string `json:"state"`
	// FirstSeen and LastSeen are the times of the host.
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	// Checkins is how many times the host answered.
	Checkins uint64 `json:"checkins"`
	// Uptime is how long the implant said it had been running.
	Uptime int64 `json:"uptime,omitempty"`
	// Impersonation is the account the implant took.
	Impersonation string `json:"impersonation,omitempty"`
	// Score and Grade are the health of the host.
	Score int    `json:"score"`
	Grade string `json:"grade"`
	// Parts are the components of the score.
	Parts []health.Part `json:"parts,omitempty"`
	// Tasks are the pieces of work the server ran on the host.
	Tasks []Task `json:"tasks,omitempty"`
	// Counts say how much work the host did.
	Done    int `json:"tasks_done"`
	Failed  int `json:"tasks_failed"`
	Pending int `json:"tasks_pending"`
	// Persist is the persistence of the host.
	Persist []Persist `json:"persist,omitempty"`
	// PersistBroken is how many of the entries are broken.
	PersistBroken int `json:"persist_broken"`
	// Posture is what the implant thinks of the machine.
	Posture string `json:"posture,omitempty"`
	// Canaries are the tripwires planted on the host.
	Canaries []canary.Canary `json:"canaries,omitempty"`
	// Approvals are the requests about the host.
	Approvals []approval.Request `json:"approvals,omitempty"`
	// Kinds says how much work of every kind the server ran on the host.
	Kinds map[string]int `json:"kinds,omitempty"`
	// Notes are the lines the console wrote about the host.
	Notes []string `json:"notes,omitempty"`
	// Summary is what the operator reads first.
	Summary []string `json:"summary,omitempty"`
	// Gaps are the things the server does not know.
	Gaps []string `json:"gaps,omitempty"`
}

// Build gathers the file of one host.
//
// The order of the work is the order of the time: the newest task
// first, because the task that ran last is the one the operator was
// waiting for.
func Build(h Host) Dossier {
	d := Dossier{
		ID:            h.ID,
		Host:          h.Host,
		OS:            h.OS,
		Arch:          h.Arch,
		User:          h.User,
		Version:       h.Version,
		Transport:     h.Transport,
		Addr:          h.Addr,
		Tags:          append([]string(nil), h.Tags...),
		State:         h.State,
		FirstSeen:     h.FirstSeen,
		LastSeen:      h.LastSeen,
		Checkins:      h.Checkins,
		Uptime:        h.Uptime,
		Impersonation: h.Impersonation,
		Posture:       h.Posture,
		Score:         h.Health.Score,
		Grade:         h.Health.Grade,
		Parts:         h.Health.Parts,
		Persist:       append([]Persist(nil), h.Persist...),
		Canaries:       append([]canary.Canary(nil), h.Canaries...),
		Approvals:      append([]approval.Request(nil), h.Approvals...),
		Notes:          append([]string(nil), h.Notes...),
		Kinds:          map[string]int{},
	}
	// The work of the host, counted.
	tasks := append([]Task(nil), h.Tasks...)
	sort.SliceStable(tasks, func(i, j int) bool {
		if tasks[i].Created.Equal(tasks[j].Created) {
			return tasks[i].ID > tasks[j].ID
		}
		return tasks[i].Created.After(tasks[j].Created)
	})
	d.Tasks = tasks
	for _, t := range tasks {
		switch t.State {
		case "done":
			d.Done++
		case "failed":
			d.Failed++
		default:
			d.Pending++
		}
		if t.Kind != "" {
			d.Kinds[t.Kind]++
		}
	}
	// The persistence of the host.
	for _, p := range h.Persist {
		if p.State == "broken" {
			d.PersistBroken++
		}
	}
	// The posture of the host: what the implant thinks of the machine.
	// The health package grades it, the dossier says what it was.
	// The summary and the gaps.
	d.Summary = summarise(d)
	d.Gaps = gaps(d)
	return d
}

// summarise writes the lines the operator reads first.
//
// The lines are short on purpose: a dossier is a page, and a page that
// needs a scroll is a page nobody reads.
func summarise(d Dossier) []string {
	out := make([]string, 0, 6)
	name := d.Host
	if name == "" {
		name = d.ID
	}
	state := d.State
	if state == "" {
		state = "unknown"
	}
	out = append(out, fmt.Sprintf("%s (%s, %s) is %s, score %d (%s)",
		name, d.OS, d.Arch, state, d.Score, d.Grade))
	if !d.LastSeen.IsZero() {
		out = append(out, fmt.Sprintf("the host answered %d times, the last one at %s",
			d.Checkins, d.LastSeen.UTC().Format(time.RFC3339)))
	}
	if d.Done > 0 || d.Failed > 0 || d.Pending > 0 {
		out = append(out, fmt.Sprintf("the work: %d done, %d failed, %d waiting",
			d.Done, d.Failed, d.Pending))
		out = append(out, "the kinds of the work: "+kindsLine(d.Kinds))
	}
	if d.PersistBroken > 0 {
		out = append(out, fmt.Sprintf("%d persistence entries are broken", d.PersistBroken))
	}
	for _, c := range d.Canaries {
		if c.State == canary.StateChanged {
			out = append(out, fmt.Sprintf("the canary %q was touched", c.Label))
		}
		if c.State == canary.StateMissing {
			out = append(out, fmt.Sprintf("the canary %q is gone", c.Label))
		}
	}
	for _, a := range d.Approvals {
		if a.State == approval.StatePending {
			out = append(out, fmt.Sprintf("the request %q waits for a decision", a.Kind))
		}
	}
	return out
}

// kindsLine writes the histogram of the work as one line.
//
// The kinds are ordered by how much work they were, and the line stays
// short: the console prints it as it is.
func kindsLine(kinds map[string]int) string {
	if len(kinds) == 0 {
		return "none"
	}
	names := make([]string, 0, len(kinds))
	for name := range kinds {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if kinds[names[i]] == kinds[names[j]] {
			return names[i] < names[j]
		}
		return kinds[names[i]] > kinds[names[j]]
	})
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s %d", name, kinds[name]))
	}
	return strings.Join(parts, ", ")
}

// gaps says what the server does not know about the host.
//
// A gap is not a failure: it is the place where the operator has to go
// and look.
func gaps(d Dossier) []string {	out := make([]string, 0, 4)
	if d.LastSeen.IsZero() {
		out = append(out, "the host has never answered")
	}
	if d.Version == "" {
		out = append(out, "the version of the implant is unknown")
	}
	if d.User == "" {
		out = append(out, "the account the implant runs as is unknown")
	}
	if len(d.Tasks) == 0 {
		out = append(out, "the server never ran a task on this host")
	}
	return out
}

// Line renders the dossier as the page the console prints.
//
// The format is one line per fact and a blank line between the
// sections, because the console is a terminal and a terminal is narrow.
func (d Dossier) Line() string {
	var sb strings.Builder
	name := d.Host
	if name == "" {
		name = d.ID
	}
	fmt.Fprintf(&sb, "%s  %s/%s  %s  score %d (%s)\n", name, d.OS, d.Arch,
		d.State, d.Score, d.Grade)
	if len(d.Tags) > 0 {
		fmt.Fprintf(&sb, "  tags: %s\n", strings.Join(d.Tags, ", "))
	}
	for _, line := range d.Summary {
		fmt.Fprintf(&sb, "  %s\n", line)
	}
	if len(d.Persist) > 0 {
		sb.WriteString("  the persistence:\n")
		for _, p := range d.Persist {
			fmt.Fprintf(&sb, "    %-18s %-10s %s\n", p.Technique, p.State, p.Location)
		}
	}
	if len(d.Canaries) > 0 {
		sb.WriteString("  the canaries:\n")
		for _, c := range d.Canaries {
			fmt.Fprintf(&sb, "    %-10s %-10s %s\n", c.ID, c.State, c.Label)
		}
	}
	if len(d.Notes) > 0 {
		sb.WriteString("  the notes:\n")
		for _, n := range d.Notes {
			fmt.Fprintf(&sb, "    %s\n", n)
		}
	}
	if len(d.Gaps) > 0 {
		sb.WriteString("  what is not known:\n")
		for _, gap := range d.Gaps {
			fmt.Fprintf(&sb, "    %s\n", gap)
		}
	}
	return sb.String()
}
