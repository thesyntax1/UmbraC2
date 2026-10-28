package link

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
)

// serveTLS runs a session on a connection that came in through the mutual
// TLS listener.
//
// The TLS layer only proves *who* the peer is; the umbra handshake still
// decides *what* the peer may do.  Both are needed: the certificate says the
// peer holds a key from the client CA, the handshake says which umbra
// identity it wants to use.
//
// The role in the HELLO picks the session: an agent gets a beacon session,
// an operator gets a control channel.  One listener therefore serves both
// kinds of peer, and an operator can be moved to TLS without moving the
// agents.
func (s *Server) serveTLS(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	log := s.Log.With("peer", addr, "transport", "tls")

	// The certificate is checked by the TLS stack, the identity by the
	// handshake below.  A peer that cannot present a certificate never
	// reaches this point.
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		log.Warn("the tls listener got a plain connection")
		return
	}
	if err := conn.SetDeadline(time.Now().Add(s.Cfg.HandshakeTimeout())); err != nil {
		return
	}
	if err := tconn.Handshake(); err != nil {
		if isTLSError(err) {
			log.Warn("tls handshake refused", "err", err)
		} else {
			log.Warn("tls handshake failed", "err", err)
		}
		return
	}
	log = tlsLogFields(log, conn)

	if !s.guard.Allow(addr) {
		log.Warn("connection refused by guard")
		return
	}
	stream := NewConnStream(conn)
	sub := &operatorSubscription{server: s, addr: addr, transport: "tls/operator"}
	sess, info, err := Handshake(stream, s.Cfg, log, addr, sub.pre)
	if err != nil {
		s.guard.Fail(addr)
		log.Warn("handshake failed", "err", err)
		return
	}
	switch info.Role {
	case crypt.RoleAgent:
		s.guard.Succeed(addr)
		s.runAgent(stream, conn, sess, info, addr, "tls", log)
	case crypt.RoleOperator:
		s.runOperator(stream, conn, sess, info, addr, "tls/operator", log, sub.op)
	default:
		log.Warn("unknown role on the tls listener", "id", info.ID)
		sub.release()
	}
}

// TLSConfig returns the TLS configuration of the listener, or nil when the
// server runs without TLS.
func (s *Server) TLSConfig() *tls.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsConf
}

// SetTLS installs the TLS configuration of the mutual TLS listener.
//
// A nil configuration disables the listener again; the plain TCP listeners
// keep working either way.
func (s *Server) SetTLS(conf *tls.Config) {
	s.mu.Lock()
	s.tlsConf = conf
	s.mu.Unlock()
}

// listenTLS wraps a listener in TLS.
//
// The handshake happens on the first read, so the caller has to set a
// deadline before it starts to talk.
func listenTLS(ln net.Listener, conf *tls.Config) net.Listener {
	if conf == nil {
		return ln
	}
	return tls.NewListener(ln, conf)
}

// isTLSError reports whether an error came out of the TLS layer.
//
// A peer that fails the handshake is not a protocol error; it is a peer that
// is not allowed in, and the server answers it with a log line instead of a
// stack trace.
func isTLSError(err error) bool {
	var alert tls.RecordHeaderError
	if errors.As(err, &alert) {
		return true
	}
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr)
}

// tlsLogFields adds the certificate details of a connection to a log line.
func tlsLogFields(log *slog.Logger, conn net.Conn) *slog.Logger {
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return log
	}
	state := tconn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return log
	}
	return log.With("peer_cn", state.PeerCertificates[0].Subject.CommonName)
}
