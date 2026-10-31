package link

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
)

// freezeMoment is the engagement while the hands are tied.
//
// A freeze is the answer to the question every engagement asks at some
// point: "stop everyone, I need to look at this."  The quiet window stops
// the beacons; a freeze stops the hands.  A viewer may still read the
// engagement — reading is how an incident is understood — but every
// command that would change anything is refused until the freeze lifts.
type freezeMoment struct {
	By    string    `json:"by"`
	Note  string    `json:"note,omitempty"`
	Since time.Time `json:"since"`
	Until time.Time `json:"until,omitempty"`
}

// freezeState guards the moment and counts the hands that were stopped.
//
// The refusal count is not a punishment: it is the record of how loud the
// engagement was while it was held, and it is what tells an admin whether
// the team was waiting politely or fighting the lock.
type freezeState struct {
	mu       sync.Mutex
	moment   *freezeMoment
	refusals uint64
	last     string
	thawedBy string
}

// Freeze ties the hands of the engagement.
//
// `until` may be zero, which means the freeze stands until an admin lifts
// it by hand; a freeze with an end is the one an operator can set before
// leaving a screen, and the sweep of the server thaws it when the moment
// passes.
func (s *Server) Freeze(by, note string, until time.Time) freezeMoment {
	state := &s.freezeState
	state.mu.Lock()
	defer state.mu.Unlock()
	state.moment = &freezeMoment{
		By:    strings.TrimSpace(by),
		Note:  strings.TrimSpace(note),
		Since: time.Now().UTC(),
		Until: until.UTC(),
	}
	state.refusals = 0
	state.last = ""
	return *state.moment
}

// Thaw lifts the freeze and returns the moment that was ended.
func (s *Server) Thaw(by string) (freezeMoment, bool) {
	state := &s.freezeState
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.moment == nil {
		return freezeMoment{}, false
	}
	moment := *state.moment
	state.thawedBy = strings.TrimSpace(by)
	state.moment = nil
	return moment, true
}

// FreezeState is the freeze in force, if any, and how many hands it stopped.
func (s *Server) FreezeState() (freezeMoment, bool, uint64) {
	state := &s.freezeState
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.moment == nil {
		return freezeMoment{}, false, state.refusals
	}
	return *state.moment, true, state.refusals
}

// SweepFreeze thaws a freeze whose moment has passed and returns it.
//
// Only a freeze with an end can run out: a lock set by hand stands until a
// hand lifts it, because the person who set it meant it.
func (s *Server) SweepFreeze(now time.Time) (freezeMoment, bool) {
	state := &s.freezeState
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.moment == nil || state.moment.Until.IsZero() {
		return freezeMoment{}, false
	}
	if now.Before(state.moment.Until) {
		return freezeMoment{}, false
	}
	moment := *state.moment
	state.moment = nil
	return moment, true
}

// FrozenRefusal says why a command is refused, or nothing at all.
//
// Reading is never refused: the engagement under a freeze is exactly the
// engagement a viewer has to be able to look at.  The command that lifts
// the freeze is never refused either, or the lock would be final, and the
// command that set it may update its end while it stands.
func (s *Server) FrozenRefusal(cmd string) string {
	state := &s.freezeState
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.moment == nil {
		return ""
	}
	cmd = strings.TrimSpace(cmd)
	if cmd == "engagement.freeze" || rbac.MinRole(cmd) == "viewer" {
		return ""
	}
	state.refusals++
	state.last = cmd
	moment := *state.moment
	until := "until it is lifted by hand"
	if !moment.Until.IsZero() {
		until = "until " + moment.Until.Format(time.RFC3339)
	}
	return fmt.Sprintf(
		"the engagement is frozen by %s since %s, %s: %q is refused",
		moment.By, moment.Since.Format(time.RFC3339), until, cmd)
}

// ThawedBy is who lifted the last freeze; it is read back by the state
// command so the record of the lock names both hands.
func (s *Server) ThawedBy() string {
	state := &s.freezeState
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.thawedBy
}

// LastRefused is the last command the freeze stopped, for the state reading.
func (s *Server) LastRefused() string {
	state := &s.freezeState
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.last
}
