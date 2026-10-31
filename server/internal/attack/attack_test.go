package attack

import (
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// doneTask is the finished piece of work the wall counts.
func doneTask(id, agent, kind string, when time.Time) *store.Task {
	return &store.Task{
		ID: id, AgentID: agent, Kind: kind,
		State: store.TaskDone, Completed: when,
	}
}

func TestTheWallCountsTheWork(t *testing.T) {
	now := time.Now().UTC()
	tasks := []*store.Task{
		doneTask("t-1", "web-01", "shell", now.Add(-time.Hour)),
		doneTask("t-2", "web-01", "shell", now),
		doneTask("t-3", "db-02", "shell", now),
		doneTask("t-4", "web-01", "ls", now),
		doneTask("t-5", "web-01", "cat", now),
		// A queued intention is not a technique that was used.
		{ID: "t-6", AgentID: "web-01", Kind: "shell", State: store.TaskQueued},
		// The trips of the watch are not the work of the adversary.
		doneTask("t-7", "web-01", "canary.check", now),
	}

	usages := Coverage(tasks)
	var shell, files, collection Usage
	for _, usage := range usages {
		switch usage.ID {
		case "T1059":
			shell = usage
		case "T1083":
			files = usage
		case "T1005":
			collection = usage
		}
	}
	if shell.Tasks != 3 {
		t.Fatalf("the wall counted %d shells, the queue ran three", shell.Tasks)
	}
	if len(shell.Agents) != 2 || shell.Agents[0] != "db-02" || shell.Agents[1] != "web-01" {
		t.Fatalf("the wall names the wrong hosts: %v", shell.Agents)
	}
	if !shell.Last.Equal(now) {
		t.Fatalf("the wall forgot the last time: %v", shell.Last)
	}
	if files.Tasks != 1 || collection.Tasks != 1 {
		t.Fatalf("the wall miscounted: %d ls, %d cat", files.Tasks, collection.Tasks)
	}
	if got := Covered(usages); got != 3 {
		t.Fatalf("three techniques were used, the wall says %d", got)
	}
}

func TestTheWallSaysWhatNobodyMapped(t *testing.T) {
	tasks := []*store.Task{
		doneTask("t-1", "web-01", "shell", time.Now().UTC()),
		doneTask("t-2", "web-01", "brand.new", time.Now().UTC()),
		doneTask("t-3", "web-01", "canary.check", time.Now().UTC()),
	}
	unmapped := Unmapped(tasks)
	if len(unmapped) != 1 || unmapped[0] != "brand.new" {
		t.Fatalf("the wall stayed silent about the new kind: %v", unmapped)
	}
}
