package link

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// HandshakeError explains why a peer was rejected.
type HandshakeError struct {
	Reason string
	Fatal  bool // true when the peer is abusive rather than merely wrong
}

func (e *HandshakeError) Error() string { return e.Reason }

func handshakeErr(format string, args ...any) *HandshakeError {
	return &HandshakeError{Reason: fmt.Sprintf(format, args...)}
}

// HelloInfo is the authenticated result of a handshake.
type HelloInfo struct {
	Role     byte
	ID       string
	Meta     map[string]any
	Suite    byte
	KeyName   string // which keyring entry authenticated the peer
	ClientIP  string
	SessionID []byte // 128-bit session id handed to the peer in HELLO_ACK
}

// candidate is one (suite, key) pair the server is willing to try.
type candidate struct {
	suite   byte
	psi     []byte
	keyName string
	role    byte // role this key is allowed to claim
}

// Handshake performs the server side of the protocol handshake.
//
// The server cannot know which PSK a peer used before decrypting the HELLO, so
// it tries every configured key against the offered suites. With a handful of
// operator tokens this is microseconds; the outer attempt limit keeps it from
// becoming an oracle.
func Handshake(stream FrameStream, cfg *config.Config, log *slog.Logger, peerAddr string) (*session.Session, *HelloInfo, error) {
	raw, err := stream.ReadFrame()
	if err != nil {
		return nil, nil, handshakeErr("read HELLO: %v", err)
	}

	cands := make([]candidate, 0, 4*(1+len(cfg.Keyring.Operators)))
	for _, suite := range crypt.ServerSuites() {
		if len(cfg.Keyring.AgentPSK) > 0 {
			cands = append(cands, candidate{suite: suite, psi: cfg.Keyring.AgentPSK, keyName: "agent", role: crypt.RoleAgent})
		}
		for name, tok := range cfg.Keyring.Operators {
			cands = append(cands, candidate{suite: suite, psi: tok, keyName: name, role: crypt.RoleOperator})
		}
	}

	var (
		hello    map[string]any
		boot     *session.Session
		chosen   candidate
		lastErr  error
		accepted bool
	)
	for _, cand := range cands {
		bs, err := session.NewBootstrap(cand.psi, cand.suite, true)
		if err != nil {
			lastErr = err
			continue
		}
		msgType, plain, err := bs.OpenFrame(raw)
		if err != nil {
			lastErr = err
			continue
		}
		if msgType != wire.MsgHello {
			return nil, nil, handshakeErr("expected HELLO, got %s", wire.TypeName(msgType))
		}
		if len(plain) < 2 || plain[0] != wire.MarkerHello {
			return nil, nil, handshakeErr("bad HELLO payload marker")
		}
		v, err := upk.DecodeExact(plain[1:])
		if err != nil {
			return nil, nil, handshakeErr("decode HELLO: %v", err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, nil, handshakeErr("HELLO body must be a map")
		}
		hello, boot, chosen, accepted = m, bs, cand, true
		break
	}
	if !accepted {
		return nil, nil, &HandshakeError{Reason: fmt.Sprintf("no key/suite accepted HELLO: %v", lastErr), Fatal: true}
	}

	info, err := verifyHello(hello, chosen, cfg)
	if err != nil {
		log.Warn("handshake rejected", "peer", peerAddr, "key", chosen.keyName, "reason", err)
		return nil, nil, err
	}
	info.ClientIP = peerAddr

	serverKP, err := crypt.NewX25519Keypair()
	if err != nil {
		return nil, nil, handshakeErr("generate keypair: %v", err)
	}
	serverNonce, err := crypt.RandomBytes(16)
	if err != nil {
		return nil, nil, handshakeErr("generate nonce: %v", err)
	}
	sessionID, err := crypt.RandomBytes(16)
	if err != nil {
		return nil, nil, handshakeErr("generate session id: %v", err)
	}
	clientPub := hello["pub"].([]byte)
	clientNonce := hello["cn"].([]byte)

	shared, err := serverKP.Shared(clientPub)
	if err != nil {
		return nil, nil, handshakeErr("x25519: %v", err)
	}
	prk, material, err := crypt.DeriveSession(shared, clientNonce, serverNonce)
	if err != nil {
		return nil, nil, handshakeErr("derive session: %v", err)
	}

	ackAuth, err := crypt.AckAuth(chosen.psi, []byte(info.ID), clientPub, serverKP.Pub, clientNonce, serverNonce, sessionID, info.Suite)
	if err != nil {
		return nil, nil, handshakeErr("ack auth: %v", err)
	}
	sleep, jitter := cfg.Server.Beacon.Sleep, cfg.Server.Beacon.Jitter
	ack := upk.Map{
		"v":     1,
		"pub":   serverKP.Pub,
		"sn":    serverNonce,
		"sid":   sessionID,
		"suite": info.Suite,
		"auth":  ackAuth,
		"name":  "umbra-server",
		"cfg":   upk.Map{"sleep": sleep, "jitter": jitter},
		"meta":  upk.Map{"ver": hub.Version},
	}
	body := append([]byte{wire.MarkerHelloAck}, mustEncode(ack)...)
	frame, err := boot.Encrypt(wire.MsgHelloAck, body)
	if err != nil {
		return nil, nil, handshakeErr("seal HELLO_ACK: %v", err)
	}
	if err := stream.WriteFrame(frame); err != nil {
		return nil, nil, handshakeErr("write HELLO_ACK: %v", err)
	}

	sess, err := session.New(info.Suite, material, true, false, prk)
	if err != nil {
		return nil, nil, handshakeErr("create session: %v", err)
	}
	info.SessionID = sessionID
	return sess, info, nil
}

// verifyHello validates every unauthenticated-then-authenticated field.
func verifyHello(hello map[string]any, cand candidate, cfg *config.Config) (*HelloInfo, error) {
	role, ok := number(hello["role"])
	if !ok {
		return nil, handshakeErr("missing role")
	}
	id, ok := hello["id"].(string)
	if !ok || id == "" || len(id) > 128 {
		return nil, handshakeErr("invalid identity")
	}
	pub, ok := hello["pub"].([]byte)
	if !ok || len(pub) != 32 {
		return nil, handshakeErr("invalid client public key")
	}
	cn, ok := hello["cn"].([]byte)
	if !ok || len(cn) != 16 {
		return nil, handshakeErr("invalid client nonce")
	}
	ts, ok := number(hello["ts"])
	if !ok {
		return nil, handshakeErr("missing timestamp")
	}
	skew := time.Since(time.Unix(ts, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > cfg.MaxSkew() {
		return nil, handshakeErr("handshake timestamp outside allowed skew (%s)", skew)
	}
	suiteID, ok := number(hello["suite"])
	if !ok || byte(suiteID) != cand.suite {
		return nil, handshakeErr("suite mismatch in HELLO")
	}

	// The key that decrypted the HELLO must match the claimed role, and an
	// operator token must match the identity it was issued for.
	if byte(role) != cand.role {
		return nil, handshakeErr("role %d not allowed for key %q", role, cand.keyName)
	}
	if cand.role == crypt.RoleOperator && id != cand.keyName {
		return nil, handshakeErr("operator token used by %q but issued to %q", id, cand.keyName)
	}
	if cand.role == crypt.RoleAgent && id == "" {
		return nil, handshakeErr("agent identity required")
	}

	want, err := crypt.HelloAuth(cand.psi, byte(role), []byte(id), pub, cn, ts, byte(suiteID))
	if err != nil {
		return nil, handshakeErr("hello auth: %v", err)
	}
	got, _ := hello["auth"].([]byte)
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return nil, handshakeErr("client authentication failed (bad PSK?)")
	}

	meta := map[string]any{}
	if m, ok := hello["meta"].(map[string]any); ok {
		meta = m
	}
	v, _ := number(hello["v"])
	if v != 1 {
		return nil, handshakeErr("unsupported HELLO version %d", v)
	}
	return &HelloInfo{Role: byte(role), ID: id, Meta: meta, Suite: byte(suiteID), KeyName: cand.keyName}, nil
}

func mustEncode(m upk.Map) []byte {
	b, err := upk.Encode(m)
	if err != nil {
		panic(fmt.Sprintf("link: encode ack: %v", err))
	}
	return b
}

// number converts the numeric types upk can return into uint64.
func number(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case int:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	default:
		return 0, false
	}
}

// asInt64 converts a upk number to int64.
func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}
