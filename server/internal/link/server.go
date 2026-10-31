// Package link contains the transports (TCP and HTTP) and the framing-agnostic
// session handling for agents and operators.
package link

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/alias"
	"github.com/thesyntax1/UmbraC2/server/internal/armory"
	"github.com/thesyntax1/UmbraC2/server/internal/artifact"
	"github.com/thesyntax1/UmbraC2/server/internal/approval"
	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/baseline"
	"github.com/thesyntax1/UmbraC2/server/internal/canary"
	"github.com/thesyntax1/UmbraC2/server/internal/casefile"
	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/dnstun"
	"github.com/thesyntax1/UmbraC2/server/internal/dossier"
	"github.com/thesyntax1/UmbraC2/server/internal/health"
	"github.com/thesyntax1/UmbraC2/server/internal/hook"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/hunt"
	"github.com/thesyntax1/UmbraC2/server/internal/keyring"
	"github.com/thesyntax1/UmbraC2/server/internal/note"
	"github.com/thesyntax1/UmbraC2/server/internal/onboard"
	"github.com/thesyntax1/UmbraC2/server/internal/otp"
	"github.com/thesyntax1/UmbraC2/server/internal/tagrule"
	"github.com/thesyntax1/UmbraC2/server/internal/pivot"
	"github.com/thesyntax1/UmbraC2/server/internal/rhythm"
	"github.com/thesyntax1/UmbraC2/server/internal/silence"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/vpn"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// Server owns the listeners and the shared HTTP session table.
type Server struct {
	Cfg *config.Config
	Hub *hub.Hub
	Log *slog.Logger

	// taskLedger is the ledger of who asked: a bounded ring of the
	// questions the fleet carried, hashed line over line, so two
	// consoles can agree the queue they look at is the queue there is.
	taskLedger   []ledgerAsk
	taskLedgerSeq int
	taskLedgerMu  sync.Mutex

	// freezeState is the engagement while the hands are tied: a freeze
	// stops every command that would change anything and leaves the
	// readings alone, so an incident can be understood before it is
	// touched.
	freezeState freezeState

	// Keys is the runtime keyring: the credentials the server accepts and
	// the ones it accepts while a rotation is settling.  It is built out
	// of the configuration at start-up and rotated by the `keys.rotate`
	// and `tokens.rotate` commands, without a restart.
	Keys *keyring.Keyring

	guard *guard
	audit *audit.Logger

	// Pivot owns the agent callback sessions used for SOCKS5 proxies and
	// port forwards. It is optional: a server without pivoting never routes
	// an agent callback anywhere.
	Pivot *pivot.Manager

	// VPN is the WireGuard-style layer-3 tunnel server. Optional.
	VPN *vpn.Server
	// Armory is the signed extension registry. Optional.
	Armory *armory.Registry
	// Artifacts is the server-side file store. Optional: a server without
	// one refuses the artifact commands instead of pretending to have them.
	Artifacts *artifact.Store
	// Aliases is the runtime command namespace. Optional.
	Aliases *alias.Registry
	// DNS is the DNS tunnel endpoint. Optional: without it the server does
	// not answer any name.
	DNS *dnstun.Server
	// Hunt is the catalogue of the indicators the team hunts with.
	// Optional: without it the server refuses the hunt commands instead
	// of pretending to have a catalogue.
	Hunt *hunt.Catalogue
	// Cases is the registry of the evidence files. Optional.
	Cases *casefile.Registry
	// Approvals is the queue of the operations that wait for a second
	// pair of eyes. Optional.
	Approvals *approval.Queue
	// Canaries is the ledger of the tripwires of the engagement.
	// Optional.
	Canaries *canary.Registry
	// OTP is the registry of the second factors of the operators.
	// Optional: without it the console is asked for nothing more than
	// its token.
	OTP *otp.Registry
	// Baseline is the registry of the paths the team watches and what
	// was last seen of them.  Optional: without it the server refuses
	// the baseline commands instead of pretending to watch anything.
	Baseline *baseline.Registry
	// Notes is the ledger of the lines the team writes about a host.
	// Optional: without it the server refuses the note commands
	// instead of pretending they were written.
	Notes *note.Registry
	// Hooks is the ledger of the wires to the outside world: the URLs
	// the events of the day are posted to.  Optional: without it the
	// server keeps the news inside, and says so when it is asked for
	// a wire.
	Hooks *hook.Registry
	// Rhythm is the registry of the moments the beacons called home —
	// the shape of every check-in.  Optional: without it the rhythm
	// commands say that the breathing of the fleet is not watched.
	Rhythm *rhythm.Registry
	// Silences is the ledger of the watches of the silences: the
	// promises to say the word when a host has been quiet for too
	// long.  Optional: without it the silence commands refuse instead
	// of pretending to worry.
	Silences *silence.Registry
	// Onboards is the shelf of the welcome packs: the first five
	// minutes of a new host, written down once and queued the moment
	// the host first calls home.  Optional: without it the onboard
	// commands refuse instead of pretending to welcome.
	Onboards *onboard.Registry
	// TagRules is the sorting hat of the fleet: the rules that fit a
	// tag on the head of a host the moment it first calls home.
	// Optional: without it the tag.rule commands refuse instead of
	// pretending to colour.
	TagRules *tagrule.Registry

	httpMu       sync.Mutex
	httpSessions map[string]*httpSession
	httpSrv      *http.Server

	// The batch transports (mail and objects) keep the session of an agent
	// here: they have no connection to keep it in.
	batchMu       sync.Mutex
	batchSessions map[string]*batchSession

	mu        sync.Mutex
	listeners []net.Listener
	wg        sync.WaitGroup

	// tlsConf is the configuration of the mutual TLS listener. It is nil
	// when the server runs without TLS.
	tlsConf *tls.Config

	opMu    sync.Mutex
	opCount int
	opRate  map[string]*tokenBucket
}

// New creates a link server.
func New(cfg *config.Config, h *hub.Hub, log *slog.Logger) *Server {
	s := &Server{
		Cfg:           cfg,
		Hub:           h,
		Log:           log,
		Keys:          keyring.FromConfig(cfg.Keyring),
		guard:         newGuard(4096, 10*time.Minute),
		httpSessions:  make(map[string]*httpSession),
		batchSessions: make(map[string]*batchSession),
		opRate:        make(map[string]*tokenBucket),
	}
	// The subsystems that keep a ledger of their own follow the tasks
	// that finish.
	if h != nil {
		h.OnComplete(s.taskCompleted)
	}
	return s
}

// SetAudit attaches the operator audit log. A nil logger disables auditing.
func (s *Server) SetAudit(l *audit.Logger) { s.audit = l }

// SetPivot attaches the pivot manager. Without it the server refuses agent
// callbacks, so a deployment that does not want pivoting cannot be tricked
// into opening one.
func (s *Server) SetPivot(p *pivot.Manager) { s.Pivot = p }

// SetVPN attaches the layer-3 tunnel server.
func (s *Server) SetVPN(v *vpn.Server) { s.VPN = v }

// SetArmory attaches the extension registry.
func (s *Server) SetArmory(a *armory.Registry) { s.Armory = a }

// SetArtifact attaches the server-side file store.
func (s *Server) SetArtifact(a *artifact.Store) { s.Artifacts = a }

// SetAliases attaches the runtime command namespace.
func (s *Server) SetAliases(a *alias.Registry) { s.Aliases = a }

// SetHunt attaches the catalogue of the indicators.
//
// Without a catalogue the server refuses the hunt commands: an empty
// catalogue that answers "no indicators" is a lie, because the team
// believes it has indicators and does not.
func (s *Server) SetHunt(h *hunt.Catalogue) { s.Hunt = h }

// SetCases attaches the registry of the evidence files.
func (s *Server) SetCases(c *casefile.Registry) { s.Cases = c }

// SetApprovals attaches the queue of the two-person rule.
//
// Without a queue the server refuses the approval commands: a server
// that answers "no queue" and lets the operation through anyway is a
// server that does not have the rule.
func (s *Server) SetApprovals(q *approval.Queue) { s.Approvals = q }

// SetCanaries attaches the ledger of the tripwires.
func (s *Server) SetCanaries(c *canary.Registry) { s.Canaries = c }

// SetBaseline attaches the registry of the paths the team watches.
func (s *Server) SetBaseline(b *baseline.Registry) { s.Baseline = b }

// SetNotes attaches the ledger of the notes of the team.
func (s *Server) SetNotes(n *note.Registry) { s.Notes = n }

// SetHooks attaches the ledger of the wires to the outside world and
// taps the hub with it, so every event the day brings is also posted
// down the wires that carry its kind.
func (s *Server) SetHooks(h *hook.Registry) {
	s.Hooks = h
	if h != nil && s.Hub != nil {
		s.Hub.AddTap(h.Dispatch)
	}
}

// SetRhythm attaches the registry of the beats — the moments the
// beacons called home — and taps the hub with it, so every heartbeat
// lands in the rhythm next to the ones before it.
func (s *Server) SetRhythm(r *rhythm.Registry) {
	s.Rhythm = r
	if r != nil && s.Hub != nil {
		s.Hub.AddTap(r.Dispatch)
	}
}

// SetSilences attaches the registry of the watches of the silences.
func (s *Server) SetSilences(v *silence.Registry) { s.Silences = v }

// ledgerAsk is one line of the ledger of who asked: the question and
// the one it came from.
//
// The ledger of the queue is not the audit trail — the audit trail is
// signed, appended to a file and kept forever; the ledger is a working
// answer to the working question "whose work is this?", bounded to the
// last 256 lines and hashed line over line so no two shelves can
// disagree about the queue without the digest disagreeing first.
type ledgerAsk struct {
	Seq     int    `json:"seq"`
	TaskID  string `json:"task_id"`
	AgentID string `json:"agent_id"`
	Kind    string `json:"kind"`
	By      string `json:"by"`
	Source  string `json:"source"`
	At      int64  `json:"at"`
}

// ledgerMax is how long the ledger runs before it forgets: long enough
// to answer for the day, short enough not to become the audit trail.
const ledgerMax = 256

// ledgerAdd writes one line into the ledger of who asked.
func (s *Server) ledgerAdd(taskID, agentID, kind, by, source string) {
	s.taskLedgerMu.Lock()
	defer s.taskLedgerMu.Unlock()
	s.taskLedgerSeq++
	s.taskLedger = append(s.taskLedger, ledgerAsk{
		Seq: s.taskLedgerSeq, TaskID: taskID, AgentID: agentID,
		Kind: kind, By: cut(by, 64), Source: cut(source, 64),
		At: time.Now().UTC().Unix(),
	})
	if len(s.taskLedger) > ledgerMax {
		s.taskLedger = append([]ledgerAsk(nil), s.taskLedger[len(s.taskLedger)-ledgerMax:]...)
	}
}

// cut bounds a word of the ledger: a line that grows without a bound is
// a line that is not a line.
func cut(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// ledgerDigest walks the chain of the ledger and tells its digest,
// length, and the first and last line numbers.
//
// The digest of every line is the hash of the digest of the line before
// it and the words of the line, so a tampered middle is visible from
// the end.
func (s *Server) ledgerDigest() (digest string, entries, first, last int) {
	s.taskLedgerMu.Lock()
	defer s.taskLedgerMu.Unlock()
	prev := strings.Repeat("0", 64)
	for _, e := range s.taskLedger {
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(append([]byte(prev), raw...))
		prev = hex.EncodeToString(sum[:])
	}
	digest = prev
	entries = len(s.taskLedger)
	if entries > 0 {
		first = s.taskLedger[0].Seq
		last = s.taskLedger[entries-1].Seq
	}
	return digest, entries, first, last
}

// SetOnboards attaches the shelf of the welcome packs, taps the hub
// with it, and wires its queue and its tag lookup to the store and the
// queue every other task lives and dies by — so a task a playbook
// queued is not a second, quieter way into the fleet, it is the same
// way.
func (s *Server) SetOnboards(o *onboard.Registry) {
	s.Onboards = o
	if o == nil || s.Hub == nil {
		return
	}
	s.Hub.AddTap(func(ev hub.Event) { o.Event(ev.Kind, ev.AgentID) })
	o.SetQueue(func(agentID, kind string, args map[string]any) (string, error) {
		task, err := s.Hub.SubmitTask(agentID, kind, args)
		if err != nil {
			return "", err
		}
		// The play wrote the question, and the ledger says so: the
		// rounds that nobody typed are still the work of the team.
		s.ledgerAdd(task.ID, agentID, kind, "", "onboard")
		return task.ID, nil
	})
	o.SetLookup(func(agentID string) ([]string, bool) {
		agent, ok := s.Hub.Store().Agent(agentID)
		if !ok {
			return nil, false
		}
		return append([]string(nil), agent.Tags...), true
	})
}

// SetTagRules attaches the shelf of the sorting rules and wires its two
// helpers: the hat reads what the hello of the host told and hangs the
// tags through the same path the agents.tag command uses, with its own
// event and its own audit line.
func (s *Server) SetTagRules(r *tagrule.Registry) {
	s.TagRules = r
	if r == nil || s.Hub == nil {
		return
	}
	s.Hub.AddTap(func(ev hub.Event) { r.Event(ev.Kind, ev.AgentID) })
	r.SetLookup(func(agentID string) (map[string]string, []string, bool) {
		agent, ok := s.Hub.Store().Agent(agentID)
		if !ok {
			return nil, nil, false
		}
		facts := map[string]string{
			"os": agent.OS, "arch": agent.Arch, "host": agent.Host,
			"user": agent.User, "transport": agent.Transport,
			"version": agent.Version,
		}
		return facts, append([]string(nil), agent.Tags...), true
	})
	r.SetTag(func(agentID string, tags []string, mode string) error {
		return s.Hub.SetTags(agentID, tags, mode)
	})
}

// SweepSilences says the word for every watch whose host has been quiet
// past its pause: one event per watch, named `agent.silent`, so the
// consoles and the wires learn of the nothing the same way they learn
// of everything.
//
// The sweep reads the memory of the day and writes down that the watch
// fired; it never talks to the host, because a watch for silence that
// knocked on the door would wake what it watches.
func (s *Server) SweepSilences(now time.Time) {
	if s.Silences == nil || s.Hub == nil {
		return
	}
	due := s.Silences.Due(now, func(agentID string) (time.Time, bool) {
		agent, ok := s.Hub.Store().Agent(agentID)
		if !ok {
			return time.Time{}, false
		}
		return agent.LastSeen, true
	})
	if len(due) == 0 {
		return
	}
	for _, w := range due {
		last, known := func() (time.Time, bool) {
			agent, ok := s.Hub.Store().Agent(w.AgentID)
			if !ok {
				return time.Time{}, false
			}
			return agent.LastSeen, true
		}()
		var quietFor int64
		switch {
		case known && !last.IsZero():
			quietFor = int64(now.Sub(last).Seconds())
		default:
			quietFor = int64(now.Sub(w.Created).Seconds())
		}
		s.Hub.Emit(hub.Event{Kind: "agent.silent", AgentID: w.AgentID,
			Data: map[string]any{
				"watch":     w.ID,
				"seconds":   w.Seconds,
				"quiet_for": quietFor,
				"promised":  w.Creator,
			}})
	}
	if err := s.Silences.Save(); err != nil && s.Log != nil {
		s.Log.Warn("the ledger of the silences could not be saved", "err", err)
	}
}

// SetOTP attaches the registry of the second factors.
//
// Without a registry every console is asked for its token alone, which
// is the way a lab runs.  With one, an operator that has a secret has
// to prove it with the code of the moment before the handshake is
// answered.
func (s *Server) SetOTP(o *otp.Registry) { s.OTP = o }

// checkSecondFactor asks the console that is connecting for the code
// of the moment, when its operator has a second factor.
//
// The check happens before the answer of the handshake is written, so
// a console without the right code never gets a session: the token
// alone is not enough, and the code alone is not enough either.
func (s *Server) checkSecondFactor(info *HelloInfo) error {
	if s.OTP == nil || info == nil {
		return nil
	}
	if !s.OTP.Enabled(info.ID) {
		return nil
	}
	code := ""
	if v, ok := info.Meta["otp"].(string); ok {
		code = v
	}
	if !s.OTP.Verify(info.ID, code, time.Now()) {
		return fmt.Errorf("the second factor of %q is missing or wrong", info.ID)
	}
	return nil
}

// taskCompleted keeps the ledger of the canaries in step with the
// tasks that checked them.
//
// The verdict of a check travels in the metadata of the task, as one
// short string, so the ledger and the answer the operator read can
// never disagree.
func (s *Server) taskCompleted(c hub.Completion) {
	if s.Canaries != nil && c.Kind == "canary.check" {
		if states, _ := c.Meta["canary_states"].(string); states != "" {
			if n := s.Canaries.RecordCheck(c.AgentID, states); n > 0 {
				if err := s.Canaries.Save(); err != nil && s.Log != nil {
					s.Log.Warn("the ledger of the canaries could not be saved", "err", err)
				}
			}
		}
	}
	if s.Baseline != nil && c.Kind == "baseline.look" {
		raw, _ := c.Meta["baseline_snaps"].(string)
		if raw != "" {
			snaps := baseline.ParseSnapshots(raw)
			if len(snaps) > 0 {
				drifts := s.Baseline.Record(c.AgentID, snaps)
				if err := s.Baseline.Save(); err != nil && s.Log != nil {
					s.Log.Warn("the baseline could not be saved", "err", err)
				}
				if len(drifts) > 0 && s.Hub != nil {
					s.Hub.Emit(hub.Event{
						Kind:    "baseline.drifted",
						AgentID: c.AgentID,
						TaskID:  c.TaskID,
						Data: map[string]any{
							"drifted": int64(len(drifts)),
							"paths":   driftPaths(drifts),
						},
					})
				}
			}
		}
	}
}

// driftPaths is the paths that moved, for the event the server pushes.
func driftPaths(drifts []baseline.Drift) []any {
	out := make([]any, 0, len(drifts))
	for _, d := range drifts {
		out = append(out, d.Path)
	}
	return out
}

// Dossier gathers the file of one host.
//
// The record of the host comes from the store, the score from the
// health package, and the ledgers of the canaries and of the approvals
// from the subsystems that keep them.
func (s *Server) Dossier(agentID string) (dossier.Dossier, bool) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return dossier.Dossier{}, false
	}
	var agent *store.Agent
	for _, a := range s.Hub.Store().Agents() {
		if a.ID == agentID {
			agent = a
			break
		}
	}
	if agent == nil {
		return dossier.Dossier{}, false
	}
	now := time.Now().UTC()
	// The work of the host: the history is read one time and split per
	// host, so the file of a hundred machines is not a hundred walks
	// through the queue.
	work := &hostWork{}
	records := s.Hub.Store().FilteredTasksFor(agentID, "", "", "", 0)
	tasks := make([]dossier.Task, 0, len(records))
	for _, t := range records {
		switch t.State {
		case store.TaskDone:
			work.done++
		case store.TaskFailed:
			work.failed++
		case store.TaskQueued, store.TaskDelivered:
			work.pending++
		}
		tasks = append(tasks, dossier.Task{
			ID:        t.ID,
			Kind:      t.Kind,
			State:     t.State,
			Created:   t.Created,
			Completed: t.Completed,
			Err:       t.Err,
			Attested:  taskAttested(t.Meta),
		})
	}
	// The persistence of the host.
	persist := make([]dossier.Persist, 0, len(agent.Persist))
	for _, p := range agent.Persist {
		persist = append(persist, dossier.Persist{
			Technique: p.Technique,
			Name:      p.Name,
			Trigger:   p.Trigger,
			Location:  p.Location,
			State:     p.State,
		})
	}
	// The posture of the host.
	posture := ""
	if agent.Posture != nil {
		posture = agent.Posture.Label
	}
	// The canaries planted on the host.
	canaries := []canary.Canary{}
	if s.Canaries != nil {
		canaries = s.Canaries.ForHost(agentID)
	}
	// The requests that are about the host.
	approvals := []approval.Request{}
	if s.Approvals != nil {
		for _, req := range s.Approvals.List("") {
			if req.AgentID == agentID {
				approvals = append(approvals, req)
			}
		}
	}
	// The notes of the team about the host: the dossier says what the
	// server knows and the notes say what the team remembers of it.
	notes := []string{}
	if s.Notes != nil {
		for _, line := range s.Notes.List(agentID) {
			notes = append(notes, line.Text)
		}
	}
	return dossier.Build(dossier.Host{
		ID:            agent.ID,
		Host:          agent.Host,
		OS:            agent.OS,
		Arch:          agent.Arch,
		User:          agent.User,
		Version:       agent.Version,
		Transport:     agent.Transport,
		Addr:          agent.Addr,
		Tags:          agent.Tags,
		State:         agent.State,
		FirstSeen:     agent.FirstSeen,
		LastSeen:      agent.LastSeen,
		Checkins:      agent.Checkins,
		Uptime:        agent.Uptime,
		Impersonation: agent.Impersonation,
		Posture:       posture,
		Health:        health.Score(s.healthHost(agent, work), now),
		Tasks:         tasks,
		Persist:       persist,
		Canaries:      canaries,
		Approvals:     approvals,
		Watches:       watches,
		Notes:         notes,
	}), true
}

// taskAttested says whether the answer of a task carried a signature of
// the agent that the server verified.
func taskAttested(meta map[string]any) bool {
	if meta == nil {
		return false
	}
	ok, _ := meta["attested"].(bool)
	return ok
}

// HealthFleet scores every host of the inventory.
//
// The scorer is a function of the store, not a subsystem: the rules of
// the score live in the health package and the server only feeds them
// the records of the hosts.
func (s *Server) HealthFleet() health.Fleet {
	agents := s.Hub.Store().Agents()
	// The work of every host, counted once: the history of the tasks
	// is read one time and split per host, so the score of a fleet of
	// a hundred machines does not walk the queue a hundred times.
	work := make(map[string]*hostWork, len(agents))
	for _, t := range s.Hub.Store().FilteredTasks("", "", "", 0) {
		c, ok := work[t.AgentID]
		if !ok {
			c = &hostWork{}
			work[t.AgentID] = c
		}
		switch t.State {
		case store.TaskDone:
			c.done++
		case store.TaskFailed:
			c.failed++
		case store.TaskQueued, store.TaskDelivered:
			c.pending++
		}
	}
	hosts := make([]health.Host, 0, len(agents))
	for _, a := range agents {
		hosts = append(hosts, s.healthHost(a, work[a.ID]))
	}
	return health.ScoreFleet(hosts, time.Now().UTC())
}

// hostWork counts the work of one host: what it did, what it failed
// and what is still waiting for it.
type hostWork struct {
	done    int
	failed  int
	pending int
}

// healthHost maps the record of an agent onto what the scorer needs.
func (s *Server) healthHost(a *store.Agent, work *hostWork) health.Host {
	h := health.Host{
		ID:       a.ID,
		Online:   a.State == store.StateOnline,
		LastSeen: a.LastSeen,
		Interval: a.Sleep,
		Jitter:   a.Jitter,
	}
	if work != nil {
		h.TasksDone = work.done
		h.TasksFailed = work.failed
		h.TasksPending = work.pending
	}
	// The persistence: what the operator installed and what is broken.
	for _, p := range a.Persist {
		h.PersistExpected++
		if p.State == "broken" {
			h.PersistBroken++
		}
	}
	// The posture: what the implant thinks of the machine.
	if a.Posture != nil && a.Posture.Label != "" {
		h.Posture = a.Posture.Label
	}
	h.Version = a.Version
	return h
}

// SetDNS attaches the DNS tunnel endpoint.
//
// Every agent that shows up in the tunnel gets a session of its own, exactly
// like an agent that connects over TCP.
func (s *Server) SetDNS(d *dnstun.Server) {
	s.DNS = d
	if d == nil {
		return
	}
	d.SetOnChannel(func(agentID string, ch *dnstun.Channel) {
		go s.ServeDNS(agentID, ch)
	})
}

// Audit exposes the audit log (used by the audit.tail RPC).
func (s *Server) Audit() *audit.Logger { return s.audit }

// Start binds every configured listener and begins serving.
func (s *Server) Start(ctx context.Context) error {
	if err := s.startTCP(ctx, s.Cfg.Server.AgentListen, s.serveAgentTCP, "agent"); err != nil {
		return err
	}
	if err := s.startTCP(ctx, s.Cfg.Server.OperatorListen, s.serveOperatorTCP, "operator"); err != nil {
		return err
	}
	if err := s.startTLS(ctx); err != nil {
		return err
	}
	if err := s.startHTTP(ctx); err != nil {
		return err
	}
	s.Log.Info("team server ready",
		"agent_listen", s.Cfg.Server.AgentListen,
		"operator_listen", s.Cfg.Server.OperatorListen,
		"http_listen", s.Cfg.Server.HTTPListen,
		"tls_listen", s.Cfg.Server.TLSListen,
		"suites", []string{"aes-256-gcm"},
		"protocol", fmt.Sprintf("umbra/v1 wire=%d", wire.Version),
	)
	return nil
}

// startTLS binds the mutual TLS listener.
//
// The listener is optional: without a certificate the server keeps running
// on the plain listeners, but a configuration that asks for TLS and cannot
// load the certificate is an error the operator has to see.
func (s *Server) startTLS(ctx context.Context) error {
	addr := s.Cfg.Server.TLSListen
	if addr == "" {
		return nil
	}
	conf := s.TLSConfig()
	if conf == nil {
		return errors.New("tls_listen is configured but no certificate was loaded")
	}
	return s.startListener(ctx, addr, s.serveTLS, "tls", conf)
}

func (s *Server) startTCP(ctx context.Context, addr string, handler func(net.Conn), kind string) error {
	return s.startListener(ctx, addr, handler, kind, nil)
}

// startListener binds an address and serves it in the background.
//
// A non-nil TLS configuration turns the listener into a mutual TLS
// listener; the handshake itself happens in the handler, which knows the
// timeout of the protocol.
func (s *Server) startListener(ctx context.Context, addr string, handler func(net.Conn), kind string, conf *tls.Config) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s (%s): %w", addr, kind, err)
	}
	if conf != nil {
		ln = listenTLS(ln, conf)
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	s.Log.Info("listener started", "kind", kind, "addr", ln.Addr().String())

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				s.Log.Warn("accept failed", "kind", kind, "err", err)
				return
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetNoDelay(true)
				_ = tcp.SetKeepAlive(true)
				_ = tcp.SetKeepAlivePeriod(30 * time.Second)
			}
			go handler(conn)
		}
	}()
	return nil
}

// claimOperatorSlot enforces limits.max_operators.
func (s *Server) claimOperatorSlot() bool {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.opCount >= s.Cfg.Server.Limits.MaxOperators {
		return false
	}
	s.opCount++
	return true
}

func (s *Server) releaseOperatorSlot() {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.opCount > 0 {
		s.opCount--
	}
}

// Shutdown stops accepting new work and closes established listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.listeners = nil
	s.mu.Unlock()

	if s.httpSrv != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
	}
	s.wg.Wait()
	return nil
}

// Addresses returns the bound addresses (useful for tests that use :0).
func (s *Server) Addresses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.listeners))
	for _, ln := range s.listeners {
		out = append(out, ln.Addr().String())
	}
	return out
}
