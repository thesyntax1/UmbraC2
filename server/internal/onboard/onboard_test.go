// welcome_test.go: exercises the shelf of the welcome packs.
package onboard

import (
	"path/filepath"
	"testing"
	"time"
)

// newReg builds a registry on a temp file and counts its queues.
func newReg(t *testing.T) (*Registry, *[]queuedCall) {
	t.Helper()
	calls := &[]queuedCall{}
	reg := New()
	reg.SetPath(filepath.Join(t.TempDir(), "onboard.json"))
	reg.SetQueue(func(agentID, kind string, args map[string]any) (string, error) {
		*calls = append(*calls, queuedCall{agentID, kind})
		return "t-" + kind, nil
	})
	reg.SetLookup(func(agentID string) ([]string, bool) { return []string{}, true })
	return reg, calls
}

type queuedCall struct{ agent, kind string }

func TestWelcomeFiresOnTheFirstHello(t *testing.T) {
	reg, calls := newReg(t)
	_, err := reg.Add(Playbook{Name: "welcome", Stages: []Stage{
		{Kind: "sysinfo"},
		{Kind: "survey.installed"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	reg.Event("agent.new", "agent-1")
	if len(*calls) != 2 {
		t.Fatalf("queued=%d, want the two stages", len(*calls))
	}
	// "Once" is per host: the return of the same host is not welcomed
	// again, but the first hello of another host is.
	reg.Event("agent.online", "agent-1")
	if len(*calls) != 2 {
		t.Fatalf("a once-pack answered a return: queued=%d", len(*calls))
	}
	reg.Event("agent.new", "agent-2")
	if len(*calls) != 4 {
		t.Fatalf("the second host was not welcomed: queued=%d", len(*calls))
	}
}

func TestTheReturningHostIsWelcomedWithCooldown(t *testing.T) {
	reg, calls := newReg(t)
	_, err := reg.Add(Playbook{Name: "rounds", Once: false, Cooldown: 60,
		Stages: []Stage{{Kind: "sysinfo"}}})
	if err != nil {
		t.Fatal(err)
	}
	reg.Event("agent.online", "agent-1")
	reg.Event("agent.online", "agent-1") // inside the glass: no encore
	reg.Event("agent.online", "agent-2") // a different agent gets its own
	if len(*calls) != 2 {
		t.Fatalf("queued=%d, want 2 (cooldown per agent)", len(*calls))
	}
}

func TestTheGateAndTheCityBothSpeak(t *testing.T) {
	reg, calls := newReg(t)
	reg.SetLookup(func(agentID string) ([]string, bool) {
		if agentID == "agent-win" {
			return []string{"windows"}, true
		}
		return []string{}, false
	})
	reg.Add(Playbook{Name: "win", Tag: "windows", Once: true,
		Stages: []Stage{{Kind: "sysinfo"}}})
	reg.Add(Playbook{Name: "city", Prefix: "agent-", Once: true,
		Stages: []Stage{{Kind: "sysinfo"}}})
	reg.Event("agent.new", "agent-win")
	if len(*calls) != 2 {
		t.Fatalf("tag+prefix should both have fired, got %d", len(*calls))
	}
	reg.Event("agent.new", "stranger")
	if len(*calls) != 2 {
		t.Fatalf("a stranger must not meet the gated packs")
	}
	reg.Event("agent.new", "agent-mac")
	if len(*calls) != 3 {
		t.Fatalf("the city-prefix pack must answer an agent-* id")
	}
}

func TestTheShelfPersistsAndTheFailuresAll(t *testing.T) {
	reg, _ := newReg(t)
	reg.SetQueue(func(a, k string, m map[string]any) (string, error) { return "", ErrForced })
	p, err := reg.Add(Playbook{Name: "p", Once: true, Stages: []Stage{{Kind: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	reg.Event("agent.new", "agent-1")
	reg.Save()
	// Reload: name, gate and the memory of the failure survive the restart.
	again := New()
	again.SetPath(reg.Path())
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	got, ok := again.Get(p.ID)
	if !ok || got.Name != "p" || got.Failed != 1 || got.Fires != 1 {
		t.Fatalf("reload lost the pack: %+v", got)
	}
}

func TestManualRunAnswersTheCallerNotTheGate(t *testing.T) {
	reg, calls := newReg(t)
	p, _ := reg.Add(Playbook{Name: "manual", Tag: "nosuch", Once: true,
		Stages: []Stage{{Kind: "a"}, {Kind: "b"}}, Creator: "rms"})
	// The tag would never pass — the manual welcome does not ask.
	ok, _, err := reg.Run(p.ID, "agent-any")
	if err != nil || ok != 2 {
		t.Fatalf("run: ok=%d err=%v calls=%v", ok, err, *calls)
	}
	if _, err = reg.Run("w-9999", "agent-any"); err == nil {
		t.Fatalf("a missing pack must not pretend to run")
	}
}

var errForced = &forcedErr{}

type forcedErr struct{}

func (e *forcedErr) Error() string { return "forced" }

// ErrForced stands in for a queue that is full.
var ErrForced = errForced

func TestCooldownDefaultIsOneHour(t *testing.T) {
	reg, _ := newReg(t)
	p, _ := reg.Add(Playbook{Name: "d", Once: false, Stages: []Stage{{Kind: "a"}}})
	if p.Cooldown != 3600 {
		t.Fatalf("cooldown=%d want 3600", p.Cooldown)
	}
	if p.ID != "w-0001" {
		t.Fatalf("id=%s want w-0001", p.ID)
	}
}

// Silence the unused-import vet when time is only used through t.
var _ = time.Now
