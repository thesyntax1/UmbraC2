package keyring

import (
	"encoding/hex"
	"testing"
	"time"
)

func testRing() *Keyring {
	ring := New([]byte("0123456789abcdef0123456789abcdef"), "alice",
		[]byte("alice-token-0123456789"), "admin")
	ring.SetOperator("bob", "operator", []string{"agents.list"}, time.Time{},
		[]byte("bob-token-0123456789"))
	return ring
}

func TestTheAgentKeyIsRotatedAndTheOldOneKeepsWorking(t *testing.T) {
	ring := testRing()
	fresh, err := ring.RotateAgentPSK()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// The new key is a text: the operator copies it into the
	// configuration of the beacons, so it has to be typeable.
	if len(fresh) != TokenTextLen {
		t.Fatalf("the new key is %d bytes", len(fresh))
	}
	for _, b := range fresh {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			t.Fatalf("the new key is not a text: %q", fresh)
		}
	}
	cands := ring.AgentCandidates()
	if len(cands) != 2 {
		t.Fatalf("expected the old key to keep working, got %d candidates", len(cands))
	}
	// The candidate is the bytes behind the hex the operator saw: the
	// protocol uses the bytes, the operator copies the hex.
	if hex.EncodeToString(cands[0]) != string(fresh) {
		t.Fatal("the new key is not the first candidate")
	}
	// After the overlap the old key is gone.
	ring.SetOverlap(-time.Second)
	ring.RotateAgentPSK()
	cands = ring.AgentCandidates()
	if len(cands) != 2 {
		// The previous key of the previous rotation is still inside its
		// own (negative) window, so it is dropped as well.
		if len(cands) != 1 {
			t.Fatalf("the old keys did not go away: %d candidates", len(cands))
		}
	}
}

func TestTheTokenIsRotatedAndTheOldOneKeepsWorking(t *testing.T) {
	ring := testRing()
	fresh, err := ring.RotateOperator("bob")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	op, ok := ring.Operator("bob")
	if !ok {
		t.Fatal("bob is gone")
	}
	if string(op.Token) != string(fresh) {
		t.Fatal("the new token was not stored")
	}
	// The new token authenticates.
	if _, ok := ring.Authenticate("bob", fresh); !ok {
		t.Fatal("the new token does not authenticate")
	}
	// The old one still does, for the overlap.
	if _, ok := ring.Authenticate("bob", []byte("bob-token-0123456789")); !ok {
		t.Fatal("the old token stopped working before the overlap")
	}
	// A wrong token never does.
	if _, ok := ring.Authenticate("bob", []byte("wrong")); ok {
		t.Fatal("a wrong token authenticated")
	}
}

func TestTheScopesNarrowTheRoleAndNeverWidenIt(t *testing.T) {
	ring := testRing()
	// A viewer with the scope of an admin command: the role still wins.
	if err := ring.SetOperator("bob", "viewer", []string{"agents.kill"},
		time.Time{}, []byte("bob-token-0123456789")); err != nil {
		t.Fatalf("set: %v", err)
	}
	if ring.Allowed("bob", "agents.kill") {
		t.Fatal("the scope widened the role")
	}
	// The wildcard means "no narrowing": the role decides.
	if err := ring.SetOperator("bob", "operator", []string{"*"},
		time.Time{}, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if !ring.Allowed("bob", "agents.kill") {
		t.Fatal("the wildcard did not leave the role in charge")
	}
	if ring.Allowed("bob", "keys.rotate") {
		t.Fatal("the operator may rotate the keys of the server")
	}
}

func TestATokenThatExpiredIsRefused(t *testing.T) {
	ring := testRing()
	past := time.Now().Add(-time.Hour)
	if err := ring.SetOperator("bob", "operator", nil, past, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, ok := ring.Authenticate("bob", []byte("bob-token-0123456789")); ok {
		t.Fatal("an expired token authenticated")
	}
	// The state is still visible: an expired token is shown as expired.
	op, _ := ring.Operator("bob")
	if !op.Expired(time.Now()) {
		t.Fatal("the token is not reported as expired")
	}
}

func TestTheScopesNarrowTheRole(t *testing.T) {
	ring := testRing()
	if !ring.Allowed("bob", "agents.list") {
		t.Fatal("the scoped command was refused")
	}
	if ring.Allowed("bob", "agents.kill") {
		t.Fatal("a command outside the scopes was allowed")
	}
	// An operator without scopes is judged by the role alone.
	if !ring.Allowed("alice", "agents.kill") {
		t.Fatal("the admin was refused")
	}
}

func TestAnUnknownScopeIsRefused(t *testing.T) {
	ring := testRing()
	if err := ring.SetOperator("bob", "operator", []string{"not.a.command"}, time.Time{}, nil); err == nil {
		t.Fatal("an unknown scope was accepted")
	}
}

func TestTheLastUseIsStamped(t *testing.T) {
	ring := testRing()
	if _, ok := ring.Authenticate("alice", []byte("alice-token-0123456789")); !ok {
		t.Fatal("the token did not authenticate")
	}
	op, _ := ring.Operator("alice")
	if op.LastUsed.IsZero() {
		t.Fatal("the last use was not stamped")
	}
}
