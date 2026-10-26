// Package link contains the transports (TCP and HTTP) and the framing-agnostic
// session handling for agents and operators.
package link

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// Server owns the listeners and the shared HTTP session table.
type Server struct {
	Cfg *config.Config
	Hub *hub.Hub
	Log *slog.Logger

	guard *guard
	audit *audit.Logger

	httpMu       sync.Mutex
	httpSessions map[string]*httpSession
	httpSrv      *http.Server

	mu        sync.Mutex
	listeners []net.Listener
	wg        sync.WaitGroup

	opMu    sync.Mutex
	opCount int
	opRate  map[string]*tokenBucket
}

// New creates a link server.
func New(cfg *config.Config, h *hub.Hub, log *slog.Logger) *Server {
	return &Server{
		Cfg:          cfg,
		Hub:          h,
		Log:          log,
		guard:        newGuard(4096, 10*time.Minute),
		httpSessions: make(map[string]*httpSession),
		opRate:       make(map[string]*tokenBucket),
	}
}

// SetAudit attaches the operator audit log. A nil logger disables auditing.
func (s *Server) SetAudit(l *audit.Logger) { s.audit = l }

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
	if err := s.startHTTP(ctx); err != nil {
		return err
	}
	s.Log.Info("team server ready",
		"agent_listen", s.Cfg.Server.AgentListen,
		"operator_listen", s.Cfg.Server.OperatorListen,
		"http_listen", s.Cfg.Server.HTTPListen,
		"suites", []string{"aes-256-gcm"},
		"protocol", fmt.Sprintf("umbra/v1 wire=%d", wire.Version),
	)
	return nil
}

func (s *Server) startTCP(ctx context.Context, addr string, handler func(net.Conn), kind string) error {
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s (%s): %w", addr, kind, err)
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
