package link

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
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
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

// handleBeaconHandshake handles the bootstrap POST: HELLO in, HELLO_ACK out.
func (s *Server) handleBeaconHandshake(w http.ResponseWriter, r *http.Request) {
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
	sess, info, err := Handshake(stream, s.Cfg, s.Log.With("peer", addr, "transport", "http"), addr)
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

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Bytes())
	s.Log.Info("http agent registered", "agent", rec.ID, "peer", addr, "sid", sid)
}

// handleBeaconFrame handles an authenticated POST for an existing session.
// maxFramesPerRequest bounds how many frames one HTTP body may carry. A
// beacon normally sends one CHECKIN or a handful of RESULT frames per cycle.
const maxFramesPerRequest = 16

func (s *Server) handleBeaconFrame(w http.ResponseWriter, r *http.Request) {
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
	hs.mu.Unlock()

	if handleErr != nil {
		s.Log.Warn("http beacon frame rejected", "agent", hs.agentID, "err", handleErr)
		s.dropHTTPSession(sid)
		http.Error(w, "bad frame", http.StatusBadRequest)
		return
	}
	if len(out) > 0 {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	for _, f := range out {
		if _, err := w.Write(f); err != nil {
			return
		}
	}
	if closed {
		s.dropHTTPSession(sid)
	}
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
	s.Log.Info("http transport listening", "addr", addr, "path", s.httpPath(),
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

