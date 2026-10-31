// Package health scores the fleet.
//
// A fleet of implants is not a fleet of equal parts: one host is slow,
// one beacon has been quiet for an hour, one implant lost its
// persistence and one answers every task in half a second.  The
// operator has to know which is which before the engagement ends,
// because the host that was never really there is the host that is
// still on the network.
//
// The score is made of five parts, and every part says why it is what
// it is:
//
//   - **reachability**: did the host answer at all, and how long ago;
//   - **cadence**: is the check-in of the host the one the operator
//     asked for, or is the beacon drifting;
//   - **capacity**: is the host doing the work, or is it the host that
//     never answers;
//   - **persistence**: does the host still carry what the operator
//     installed on it;
//   - **posture**: what does the implant itself think of the machine.
//
// The score is a number between 0 and 100 and a grade, and the parts
// are kept beside it: a score an operator cannot explain is a score
// nobody acts on.
package health

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The grades of the scale.
const (
	GradeHealthy = "healthy"
	GradeFair    = "fair"
	GradePoor    = "poor"
	GradeLost    = "lost"
	// GradeSuspect is the grade of a host that works perfectly and is
	// not what it claims to be: a laboratory machine, a virtual machine
	// or the sandbox of an analyst.  It is a grade of its own, because
	// "the host is healthy" is exactly the wrong thing to say about it.
	GradeSuspect = "suspect"
)

// The thresholds of the reachability.
//
// They are multiples of the check-in interval of the host: a host that
// has not answered for three of its own intervals is not busy, it is
// gone.
const (
	// SilentAfterIntervals is how many check-in intervals may pass
	// before the host counts as silent.
	SilentAfterIntervals = 3
	// LostAfterIntervals is how many may pass before it counts as
	// lost.
	LostAfterIntervals = 10
	// LostScoreCap is the highest score a host that is not answering
	// can reach.
	//
	// A host that is gone cannot be a healthy host, whatever its
	// history says: the operator has to see at a glance that this
	// machine cannot be reached any more.
	LostScoreCap = 24
	// SuspectScoreCap is the highest score a host that reports itself
	// as a laboratory machine can reach.
	//
	// The machinery of the host may be perfect; the host is still not
	// a host of the engagement.
	SuspectScoreCap = 24
)

// Part is one component of the score.
//
// Weight is how much the part is worth out of a hundred, and Value is
// what it scored out of its own weight.
type Part struct {
	// Name is the component: "reachability", "cadence", ...
	Name string `json:"name"`
	// Weight is what the component is worth.
	Weight int `json:"weight"`
	// Value is what it scored.
	Value int `json:"value"`
	// Note says why it scored that.
	Note string `json:"note,omitempty"`
}

// Report is the health of one host.
type Report struct {
	// AgentID is the host.
	AgentID string `json:"agent_id"`
	// Score is out of a hundred.
	Score int `json:"score"`
	// Grade is the word for the score.
	Grade string `json:"grade"`
	// Parts are the components, with their notes.
	Parts []Part `json:"parts"`
	// Notes are the things an operator has to look at.
	Notes []string `json:"notes,omitempty"`
	// LastSeen is when the host answered last.
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Interval is the check-in interval of the host, in seconds.
	Interval int `json:"interval"`
}

// Host is what the scorer needs to know about a host.
//
// The package does not import the store: the caller maps the record of
// the server onto this struct, so the rules of the score can be read
// and tested without the rest of the server.
type Host struct {
	ID     string
	Online bool
	// LastSeen is when the host answered last.
	LastSeen time.Time
	// Interval is the check-in interval in seconds.
	Interval int
	// Jitter is the jitter in seconds.
	Jitter int
	// TasksDone and TasksFailed count the work of the host.
	TasksDone   int
	TasksFailed int
	// TasksPending is the work that is still queued.
	TasksPending int
	// PersistExpected is how many persistence entries the operator
	// installed on the host.
	PersistExpected int
	// PersistBroken is how many of them are broken.
	PersistBroken int
	// Posture is the label the implant reported, if any.
	Posture string
	// Version is the version of the implant.
	Version string
}

// Score computes the health of one host.
//
// The rules are the ones the operations guide describes, and every part
// of the score carries the sentence that explains it.
func Score(h Host, now time.Time) Report {
	rep := Report{
		AgentID:  h.ID,
		Interval: h.Interval,
		LastSeen: h.LastSeen,
	}

	// ---- reachability -------------------------------------------------
	//
	// A host that has never answered is not scored on its cadence: the
	// absence of an answer is the whole of the story.
	interval := h.Interval
	if interval <= 0 {
		interval = 60
	}
	silence := time.Duration(0)
	if !h.LastSeen.IsZero() {
		silence = now.Sub(h.LastSeen)
	}
	// neverSeen says that the host was never there: nothing about it
	// is known, not even the parts that are usually remembered from the
	// reports of an earlier engagement.
	neverSeen := h.LastSeen.IsZero()
	// gone says that the host is not answering any more.  Its history
	// is known, but the host itself cannot be relied on.
	gone := false
	switch {
	case neverSeen:
		rep.Parts = append(rep.Parts, Part{Name: "reachability", Weight: 30, Value: 0,
			Note: "the host has never answered"})
		rep.Notes = append(rep.Notes, "the host has never checked in")
	case h.Online && silence < time.Duration(interval*SilentAfterIntervals)*time.Second:
		rep.Parts = append(rep.Parts, Part{Name: "reachability", Weight: 30, Value: 30,
			Note: fmt.Sprintf("the host answered %s ago", short(silence))})
	case silence < time.Duration(interval*LostAfterIntervals)*time.Second:
		rep.Parts = append(rep.Parts, Part{Name: "reachability", Weight: 30, Value: 12,
			Note: fmt.Sprintf("the host has been quiet for %s", short(silence))})
		rep.Notes = append(rep.Notes, fmt.Sprintf("the host has been quiet for %s", short(silence)))
	default:
		gone = true
		rep.Parts = append(rep.Parts, Part{Name: "reachability", Weight: 30, Value: 0,
			Note: fmt.Sprintf("the host has been quiet for %s", short(silence))})
		rep.Notes = append(rep.Notes, fmt.Sprintf("the host has been quiet for %s and is probably lost", short(silence)))
	}

	// ---- cadence ------------------------------------------------------
	//
	// The cadence the operator asked for is the one the host keeps. A
	// beacon that checks in far more often than it was told to is
	// noisy, and a beacon that checks in far less often is slow.
	cadence := 15
	switch {
	case neverSeen:
		rep.Parts = append(rep.Parts, Part{Name: "cadence", Weight: 15, Value: 0,
			Note: "the host has never answered, so its cadence is unknown"})
	case h.Interval <= 0:
		cadence = 10
		rep.Parts = append(rep.Parts, Part{Name: "cadence", Weight: 15, Value: cadence,
			Note: "the interval of the host is unknown"})
	case h.Jitter > h.Interval:
		cadence = 5
		rep.Parts = append(rep.Parts, Part{Name: "cadence", Weight: 15, Value: cadence,
			Note: fmt.Sprintf("the jitter (%ds) is larger than the interval (%ds)", h.Jitter, h.Interval)})
		rep.Notes = append(rep.Notes, "the jitter of the host is larger than its interval")
	default:
		rep.Parts = append(rep.Parts, Part{Name: "cadence", Weight: 15, Value: cadence,
			Note: fmt.Sprintf("the host checks in every %ds (+/- %ds)", h.Interval, h.Jitter)})
	}

	// ---- capacity -----------------------------------------------------
	//
	// A host that answers every task is a host that works. A host that
	// fails everything is a host that is broken, and a host with a
	// queue that never empties is a host the operator pushed too hard.
	capacity := 20
	total := h.TasksDone + h.TasksFailed
	switch {
	case neverSeen:
		rep.Parts = append(rep.Parts, Part{Name: "capacity", Weight: 20, Value: 0,
			Note: "the host has never answered, so its work is unknown"})
	case total == 0:
		capacity = 15
		rep.Parts = append(rep.Parts, Part{Name: "capacity", Weight: 20, Value: capacity,
			Note: "the host has not run a task yet"})
	case h.TasksFailed > h.TasksDone:
		capacity = 2
		rep.Parts = append(rep.Parts, Part{Name: "capacity", Weight: 20, Value: capacity,
			Note: fmt.Sprintf("%d of %d tasks failed", h.TasksFailed, total)})
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d of %d tasks failed", h.TasksFailed, total))
	case h.TasksFailed > 0:
		capacity = 12
		rep.Parts = append(rep.Parts, Part{Name: "capacity", Weight: 20, Value: capacity,
			Note: fmt.Sprintf("%d of %d tasks failed", h.TasksFailed, total)})
	default:
		rep.Parts = append(rep.Parts, Part{Name: "capacity", Weight: 20, Value: capacity,
			Note: fmt.Sprintf("%d tasks, none failed", total)})
	}
	if h.TasksPending > 20 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d tasks are still queued on the host", h.TasksPending))
	}

	// ---- persistence --------------------------------------------------
	//
	// What the operator installed on the host is what has to be there
	// at the end of the engagement. A broken entry is worse than no
	// entry: it points at a file that is not there.
	persist := 20
	switch {
	case neverSeen:
		rep.Parts = append(rep.Parts, Part{Name: "persistence", Weight: 20, Value: 0,
			Note: "the host has never answered, so its persistence is unknown"})
	case h.PersistExpected == 0:
		persist = 20
		rep.Parts = append(rep.Parts, Part{Name: "persistence", Weight: 20, Value: persist,
			Note: "nothing was installed on the host"})
	case h.PersistBroken == 0:
		rep.Parts = append(rep.Parts, Part{Name: "persistence", Weight: 20, Value: persist,
			Note: fmt.Sprintf("%d entries, none broken", h.PersistExpected)})
	case h.PersistBroken >= h.PersistExpected:
		persist = 0
		rep.Parts = append(rep.Parts, Part{Name: "persistence", Weight: 20, Value: persist,
			Note: fmt.Sprintf("all %d entries are broken", h.PersistExpected)})
		rep.Notes = append(rep.Notes, "every persistence entry of the host is broken")
	default:
		persist = 20 - (h.PersistBroken*20)/h.PersistExpected
		rep.Parts = append(rep.Parts, Part{Name: "persistence", Weight: 20, Value: persist,
			Note: fmt.Sprintf("%d of %d entries are broken", h.PersistBroken, h.PersistExpected)})
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d of %d persistence entries are broken", h.PersistBroken, h.PersistExpected))
	}

	// ---- posture ------------------------------------------------------
	//
	// The implant's own opinion of the machine: a virtual machine is a
	// sandbox, and a sandbox is not a host of the engagement.
	posture := 15
	label := strings.ToLower(strings.TrimSpace(h.Posture))
	suspect := false
	switch {
	case neverSeen:
		rep.Parts = append(rep.Parts, Part{Name: "posture", Weight: 15, Value: 0,
			Note: "the host has never answered, so its posture is unknown"})
	case label == "":
		posture = 10
		rep.Parts = append(rep.Parts, Part{Name: "posture", Weight: 15, Value: posture,
			Note: "the host did not report its posture"})
	case strings.Contains(label, "virtual"), strings.Contains(label, "lab"),
		strings.Contains(label, "sandbox"):
		posture = 2
		suspect = true
		rep.Parts = append(rep.Parts, Part{Name: "posture", Weight: 15, Value: posture,
			Note: fmt.Sprintf("the host reports itself as %q, so it is not a host of the engagement", h.Posture)})
		rep.Notes = append(rep.Notes, fmt.Sprintf("the host reports itself as %q, so it is not a host of the engagement", h.Posture))
	default:
		rep.Parts = append(rep.Parts, Part{Name: "posture", Weight: 15, Value: posture,
			Note: fmt.Sprintf("the host reports itself as %q", h.Posture)})
	}

	// ---- the total ----------------------------------------------------
	score := 0
	for _, p := range rep.Parts {
		score += p.Value
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	// A host that is not there cannot be a healthy host, whatever its
	// history says: the score of a lost host is capped so that the
	// grade says what the operator has to know.
	if neverSeen || gone {
		if score > LostScoreCap {
			score = LostScoreCap
		}
	}
	// A host that reports itself as a laboratory machine is not a host
	// of the engagement at all, however well it works.
	if suspect {
		if score > SuspectScoreCap {
			score = SuspectScoreCap
		}
	}
	rep.Score = score
	rep.Grade = Grade(score)
	if suspect {
		rep.Grade = GradeSuspect
	}
	return rep
}

// Grade turns a score into the word for it.
//
// The scale is strict on purpose: a host that fails most of the work it
// is given is broken, and a scale that still calls it healthy is a
// scale nobody reads.
func Grade(score int) string {
	switch {
	case score >= 90:
		return GradeHealthy
	case score >= 70:
		return GradeFair
	case score >= 40:
		return GradePoor
	default:
		return GradeLost
	}
}

// Fleet is the health of every host of the server.
type Fleet struct {
	// Reports are the hosts, worst first: the operator reads the top
	// of the list and not the bottom.
	Reports []Report `json:"reports"`
	// Average is the mean score of the fleet.
	Average int `json:"average"`
	// Counts is how many hosts are in each grade.
	Counts map[string]int `json:"counts"`
	// At is when the fleet was scored.
	At time.Time `json:"at"`
}

// ScoreFleet scores every host and sorts the result worst first.
//
// The order is the point: a fleet report that is sorted by the id of
// the host is a list, and a list of forty machines is not an answer to
// "which one do I look at".
func ScoreFleet(hosts []Host, now time.Time) Fleet {
	out := Fleet{At: now, Counts: map[string]int{}}
	reports := make([]Report, 0, len(hosts))
	total := 0
	for _, h := range hosts {
		rep := Score(h, now)
		total += rep.Score
		out.Counts[rep.Grade]++
		reports = append(reports, rep)
	}
	sort.SliceStable(reports, func(i, j int) bool {
		if reports[i].Score != reports[j].Score {
			return reports[i].Score < reports[j].Score
		}
		return reports[i].AgentID < reports[j].AgentID
	})
	out.Reports = reports
	if len(hosts) > 0 {
		out.Average = total / len(hosts)
	}
	return out
}

// short renders a duration the way an operator reads it.
func short(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
