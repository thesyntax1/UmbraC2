package config

import "testing"

// TestTheAgentKeyIsTheHexTheOperatorWrote proves that the server and the
// beacons end up with the same bytes.
//
// The server prints the key as hex and the beacons read it as hex.  If one
// side took the text and the other took the bytes behind it, the server and
// the implants would not share a key at all -- and nothing would say so
// until a beacon failed to check in.
func TestTheAgentKeyIsTheHexTheOperatorWrote(t *testing.T) {
	const hexKey = "00112233445566778899aabbccddeeff"
	decoded := DecodePSK(hexKey)
	if len(decoded) != 16 {
		t.Fatalf("the hex key decoded to %d bytes", len(decoded))
	}
	if decoded[0] != 0x00 || decoded[15] != 0xff {
		t.Fatalf("the hex key decoded to %x", decoded)
	}
	// A value that is not hex is taken as it is: a lab that puts raw bytes
	// in the environment needs that.
	const raw = "agent-psk-0123456789abcdef0123"
	if string(DecodePSK(raw)) != raw {
		t.Fatal("a key that is not hex must be taken as it is")
	}
	// An empty key is no key.
	if DecodePSK("   ") != nil {
		t.Fatal("an empty key must stay empty")
	}
}

// TestAPinIsOnlyAcceptedWhenItIsAFingerprint proves that a pin that is not
// a SHA-256 fingerprint is refused at the door.
//
// A typo in the configuration of a pin would otherwise leave the listener
// with a rule that never matches, and every console would be refused with a
// message that says nothing about the reason.
func TestAPinIsOnlyAcceptedWhenItIsAFingerprint(t *testing.T) {
	const good = "36a3e56f74fac2fdefc67e8eab8225eb6f1966e10d977b617331231a859ba50a"
	cfg := Default()
	cfg.Keyring.AgentPSK = []byte("0123456789abcdef0123456789abcdef")
	cfg.Keyring.Operators = map[string][]byte{
		"alice": []byte("operator-token-0123456789"),
	}
	cfg.Keyring.Roles = map[string]string{"alice": "admin"}
	cfg.Server.TLSListen = "127.0.0.1:4443"
	cfg.Server.TLSCert = "server.pem"
	cfg.Server.TLSKey = "server.key"
	cfg.Server.TLSClientCA = "ca.pem"
	cfg.Server.TLSClientSPKI = good
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a well formed pin must be accepted: %v", err)
	}
	// A pin that is not hex.
	cfg.Server.TLSClientSPKI = "not a fingerprint"
	if err := cfg.Validate(); err == nil {
		t.Fatal("a pin that is not hex must be refused")
	}
	// A pin of the wrong size.
	cfg.Server.TLSClientSPKI = "0011"
	if err := cfg.Validate(); err == nil {
		t.Fatal("a pin that is not a SHA-256 fingerprint must be refused")
	}
	// A pin without a listener to pin the clients on.
	cfg.Server.TLSClientSPKI = good
	cfg.Server.TLSListen = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("a pin without a listener must be refused")
	}
}
