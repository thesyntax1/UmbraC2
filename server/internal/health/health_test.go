package health_test

import (
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/health"
)

func TestTheHostThatAnswersScoresWell(t *testing.T) {
	now := time.Now().UTC()
	rep := health.Score(health.Host{
		ID:        "web-01",
		Online:    true,
		LastSeen:  now.Add(-10 * time.Second),
		Interval:  60,
		Jitter:    10,
		TasksDone: 12,
		Posture:   "production server",
	}, now)
	if rep.Score < 80 {
		t.Fatalf("the score of a healthy host is %d, want at least 80: %+v", rep.Score, rep.Parts)
	}
	if rep.Grade != health.GradeHealthy {
		t.Fatalf("the grade of a healthy host is %q, want %q", rep.Grade, health.GradeHealthy)
	}
	if len(rep.Parts) != 5 {
		t.Fatalf("the score has %d parts, want 5", len(rep.Parts))
	}
	for _, p := range rep.Parts {
		if p.Note == "" {
			t.Fatalf("the part %q has no reason: %+v", p.Name, p)
		}
	}
}

func TestTheHostThatNeverAnsweredScoresZero(t *testing.T) {
	now := time.Now().UTC()
	rep := health.Score(health.Host{ID: "ghost-01", Interval: 60}, now)
	if rep.Score != 0 {
		t.Fatalf("the score of a host that never answered is %d, want 0", rep.Score)
	}
	if rep.Grade != health.GradeLost {
		t.Fatalf("the grade is %q, want %q", rep.Grade, health.GradeLost)
	}
	if len(rep.Notes) == 0 {
		t.Fatalf("a host that never answered has no note: %+v", rep)
	}
}

func TestTheHostThatIsGoneIsNamed(t *testing.T) {
	now := time.Now().UTC()
	rep := health.Score(health.Host{
		ID:       "quiet-01",
		Interval: 60,
		LastSeen: now.Add(-30 * time.Minute),
	}, now)
	if rep.Score > 30 {
		t.Fatalf("the score of a host that is gone is %d, want at most 30", rep.Score)
	}
	found := false
	for _, note := range rep.Notes {
		if note != "" && len(note) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("a host that is gone has no note: %+v", rep)
	}
}

func TestTheBrokenPersistenceCostsTheHost(t *testing.T) {
	now := time.Now().UTC()
	base := health.Host{
		ID: "web-02", Online: true, LastSeen: now, Interval: 60,
		TasksDone: 3, Posture: "production server",
	}
	good := health.Score(base, now)
	broken := base
	broken.PersistExpected = 2
	broken.PersistBroken = 2
	worse := health.Score(broken, now)
	if worse.Score >= good.Score {
		t.Fatalf("the broken persistence did not cost the host: %d against %d",
			worse.Score, good.Score)
	}
}

func TestTheVirtualMachineIsNotAHostOfTheEngagement(t *testing.T) {
	now := time.Now().UTC()
	rep := health.Score(health.Host{
		ID: "lab-01", Online: true, LastSeen: now, Interval: 60,
		Posture: "lab machine, virtual",
	}, now)
	if rep.Score > health.SuspectScoreCap {
		t.Fatalf("the score of a laboratory machine is %d, want at most %d",
			rep.Score, health.SuspectScoreCap)
	}
	if rep.Grade != health.GradeSuspect {
		t.Fatalf("the grade of a laboratory machine is %q, want %q",
			rep.Grade, health.GradeSuspect)
	}
	if len(rep.Notes) == 0 {
		t.Fatalf("the laboratory machine has no note: %+v", rep)
	}
}

func TestTheFleetIsSortedWorstFirst(t *testing.T) {
	now := time.Now().UTC()
	fleet := health.ScoreFleet([]health.Host{
		{ID: "good-01", Online: true, LastSeen: now, Interval: 60, TasksDone: 5,
			Posture: "production server"},
		{ID: "lost-01", Interval: 60},
		{ID: "fair-01", Online: true, LastSeen: now, Interval: 60,
			TasksDone: 1, TasksFailed: 3, Posture: "workstation"},
	}, now)
	if len(fleet.Reports) != 3 {
		t.Fatalf("the fleet holds %d reports, want 3", len(fleet.Reports))
	}
	if fleet.Reports[0].AgentID != "lost-01" {
		t.Fatalf("the worst host is %q, want lost-01", fleet.Reports[0].AgentID)
	}
	if fleet.Reports[2].AgentID != "good-01" {
		t.Fatalf("the best host is %q, want good-01", fleet.Reports[2].AgentID)
	}
	if fleet.Counts[health.GradeHealthy] != 1 {
		t.Fatalf("the fleet counts %d healthy hosts, want 1", fleet.Counts[health.GradeHealthy])
	}
	if fleet.Counts[health.GradeLost] != 1 {
		t.Fatalf("the fleet counts %d lost hosts, want 1", fleet.Counts[health.GradeLost])
	}
	if fleet.Average <= 0 {
		t.Fatalf("the average of the fleet is %d", fleet.Average)
	}
}

func TestTheGradeOfTheScale(t *testing.T) {
	cases := map[int]string{
		100: health.GradeHealthy,
		90:  health.GradeHealthy,
		89:  health.GradeFair,
		70:  health.GradeFair,
		69:  health.GradePoor,
		40:  health.GradePoor,
		39:  health.GradeLost,
		0:   health.GradeLost,
	}
	for score, want := range cases {
		if got := health.Grade(score); got != want {
			t.Fatalf("the grade of %d is %q, want %q", score, got, want)
		}
	}
}

func TestTheHostThatFailsItsWorkIsNotHealthy(t *testing.T) {
	now := time.Now().UTC()
	rep := health.Score(health.Host{
		ID: "broken-01", Online: true, LastSeen: now, Interval: 60,
		TasksDone: 1, TasksFailed: 9, Posture: "production server",
	}, now)
	if rep.Grade == health.GradeHealthy {
		t.Fatalf("a host that fails its work is healthy: %+v", rep)
	}
	if len(rep.Notes) == 0 {
		t.Fatalf("a host that fails its work has no note: %+v", rep)
	}
}
