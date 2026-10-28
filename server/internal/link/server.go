// Package link contains the transports (TCP and HTTP) and the framing-agnostic
// session handling for agents and operators.
package link

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/alias"
	"github.com/thesyntax1/UmbraC2/server/internal/armory"
	"github.com/thesyntax1/UmbraC2/server/internal/artifact"
	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/dnstun"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/keyring"
	"github.com/thesyntax1/UmbraC2/server/internal/pivot"
	"github.com/thesyntax1/UmbraC2/server/internal/vpn"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// Server owns the listeners and the shared HTTP session table.
type Server struct {
	Cfg *config.Config
	Hub *hub.Hub
	Log *slog.Logger

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
	return &Server{
		Cfg:           cfg,
		Hub:           h,
		Log:           log,
		Keys:          keyring.FromConfig(cfg.Keyring),
		guard:         newGuard(4096, 10*time.Minute),
		httpSessions:  make(map[string]*httpSession),
		batchSessions: make(map[string]*batchSession),
		opRate:        make(map[string]*tokenBucket),
	}
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
