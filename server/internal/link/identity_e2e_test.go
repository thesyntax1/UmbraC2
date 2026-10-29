package link_test

import (
	"net"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/link"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// TestAKeyBoundToOneAgentMayNotClaimAnotherName proves that the identity
// of a host is proved by its key and not only by the name it says.
//
// A fleet key belongs to everybody: whoever holds it may claim any name.
// A key that is bound to one agent id may not claim another one, so a key
// that is stolen impersonates one machine and not the whole fleet.
func TestAKeyBoundToOneAgentMayNotClaimAnotherName(t *testing.T) {
	bound := []byte("bound-agent-key-0123456789")
	_, _, agentAddr, _ := newTestServerWithKeys(t, map[string][]byte{
		"host-bound": bound,
	})

	// The beacon that proves the bound key and claims its own name is
	// served.
	good := dial(t, agentAddr, bound, crypt.RoleAgent, "host-bound")
	good.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	if _, batch := good.recv(t); batch == nil {
		t.Fatal("the beacon with its own key was refused")
	}

	// The same key with another name is refused: the server drops the
	// connection instead of answering a HELLO_ACK.
	if helloAccepted(t, agentAddr, bound, crypt.RoleAgent, "host-other") {
		t.Fatal("a key that is bound to one agent may not claim another name")
	}

	// The fleet key still works for the beacons that were built before the
	// per-agent keys existed.
	fleet := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "host-fleet")
	fleet.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	if _, batch := fleet.recv(t); batch == nil {
		t.Fatal("the fleet key has to keep working")
	}
}

// helloAccepted sends a HELLO and says whether the server answered it.
//
// The server never answers a handshake it does not believe, so the
// absence of a HELLO_ACK is the refusal.
func helloAccepted(t *testing.T, addr string, psk []byte, role byte, id string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	stream := link.NewConnStream(conn)

	suite := wire.SuiteAES256GCM
	kp, err := crypt.NewX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	cn, err := crypt.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	ts := uint64(time.Now().Unix())
	auth, err := crypt.HelloAuth(psk, role, []byte(id), kp.Pub, cn, ts, suite)
	if err != nil {
		t.Fatal(err)
	}
	body, err := upk.Encode(upk.Map{
		"v": uint64(1), "role": role, "id": id, "pub": kp.Pub, "cn": cn,
		"ts": ts, "suite": suite, "auth": auth,
		"meta": upk.Map{"host": "testhost", "os": "linux"},
	})
	if err != nil {
		t.Fatal(err)
	}
	boot, err := session.NewBootstrap(psk, suite, false)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := boot.Encrypt(wire.MsgHello, append([]byte{wire.MarkerHello}, body...))
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.WriteFrame(frame); err != nil {
		t.Fatal(err)
	}
	raw, err := stream.ReadFrame()
	if err != nil {
		// The server dropped the connection: the handshake was refused.
		return false
	}
	msgType, _, err := boot.OpenFrame(raw)
	if err != nil {
		return false
	}
	return msgType == wire.MsgHelloAck
}
