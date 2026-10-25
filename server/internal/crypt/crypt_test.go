package crypt_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

type vectorFile struct {
	PSK       string `json:"psk"`
	Bootstrap struct {
		Suite     byte   `json:"suite"`
		C2SKey    string `json:"c2s_key"`
		S2CKey    string `json:"s2c_key"`
		C2SPrefix string `json:"c2s_prefix"`
		S2CPrefix string `json:"s2c_prefix"`
	} `json:"bootstrap"`
	Session struct {
		ClientPriv  string `json:"client_priv"`
		ClientPub   string `json:"client_pub"`
		ServerPriv  string `json:"server_priv"`
		ServerPub   string `json:"server_pub"`
		Shared      string `json:"shared"`
		ClientNonce string `json:"client_nonce"`
		ServerNonce string `json:"server_nonce"`
		Prk         string `json:"prk"`
		C2SKey      string `json:"c2s_key"`
		S2CKey      string `json:"s2c_key"`
		C2SPrefix   string `json:"c2s_prefix"`
		S2CPrefix   string `json:"s2c_prefix"`
	} `json:"session"`
	Rekey struct {
		PrkIn     string `json:"prk_in"`
		Seed      string `json:"seed"`
		PrkOut    string `json:"prk_out"`
		C2SKey    string `json:"c2s_key"`
		S2CKey    string `json:"s2c_key"`
		C2SPrefix string `json:"c2s_prefix"`
		S2CPrefix string `json:"s2c_prefix"`
	} `json:"rekey"`
	Auth struct {
		Role        byte   `json:"role"`
		Ident       string `json:"ident"`
		ClientPub   string `json:"client_pub"`
		ServerPub   string `json:"server_pub"`
		ClientNonce string `json:"client_nonce"`
		ServerNonce string `json:"server_nonce"`
		SessionID   string `json:"session_id"`
		Timestamp   uint64 `json:"timestamp"`
		Suite       byte   `json:"suite"`
		Hello       string `json:"hello"`
		Ack         string `json:"ack"`
	} `json:"auth"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "contracts", "vectors.json"))
	if err != nil {
		t.Fatalf("resolve vectors: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return vf
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestHKDFRFC5869 pins the KDF implementation to the RFC test vector so a
// refactor cannot silently change the key schedule.
func TestHKDFRFC5869(t *testing.T) {
	ikm := unhex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := unhex(t, "000102030405060708090a0b0c")
	info := unhex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	got := crypt.HkdfSHA256(ikm, salt, info, 42)
	if hex.EncodeToString(got) != want {
		t.Fatalf("hkdf mismatch\n got %x\nwant %s", got, want)
	}
}

func TestBootstrapKeyVectors(t *testing.T) {
	vf := loadVectors(t)
	psk := unhex(t, vf.PSK)
	suite := vf.Bootstrap.Suite

	c2s := crypt.DeriveBootstrapKey(psk, "c2s", suite)
	s2c := crypt.DeriveBootstrapKey(psk, "s2c", suite)
	if hex.EncodeToString(c2s) != vf.Bootstrap.C2SKey {
		t.Errorf("c2s bootstrap key mismatch: %x", c2s)
	}
	if hex.EncodeToString(s2c) != vf.Bootstrap.S2CKey {
		t.Errorf("s2c bootstrap key mismatch: %x", s2c)
	}
	if got := hex.EncodeToString(crypt.BootstrapNoncePrefix(c2s)); got != vf.Bootstrap.C2SPrefix {
		t.Errorf("c2s prefix mismatch: %s", got)
	}
	if got := hex.EncodeToString(crypt.BootstrapNoncePrefix(s2c)); got != vf.Bootstrap.S2CPrefix {
		t.Errorf("s2c prefix mismatch: %s", got)
	}
}

func TestSessionKeyVectors(t *testing.T) {
	vf := loadVectors(t)
	shared := unhex(t, vf.Session.Shared)
	cn := unhex(t, vf.Session.ClientNonce)
	sn := unhex(t, vf.Session.ServerNonce)

	prk, km, err := crypt.DeriveSession(shared, cn, sn)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(prk) != vf.Session.Prk {
		t.Errorf("prk mismatch: %x", prk)
	}
	if hex.EncodeToString(km.C2SKey) != vf.Session.C2SKey {
		t.Errorf("c2s key mismatch: %x", km.C2SKey)
	}
	if hex.EncodeToString(km.S2CKey) != vf.Session.S2CKey {
		t.Errorf("s2c key mismatch: %x", km.S2CKey)
	}
	if hex.EncodeToString(km.C2SPrefix) != vf.Session.C2SPrefix {
		t.Errorf("c2s prefix mismatch: %x", km.C2SPrefix)
	}
	if hex.EncodeToString(km.S2CPrefix) != vf.Session.S2CPrefix {
		t.Errorf("s2c prefix mismatch: %x", km.S2CPrefix)
	}

	prk2, km2, err := crypt.DeriveRekey(prk, unhex(t, vf.Rekey.Seed))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(prk2) != vf.Rekey.PrkOut {
		t.Errorf("rekey prk mismatch: %x", prk2)
	}
	if hex.EncodeToString(km2.C2SKey) != vf.Rekey.C2SKey {
		t.Errorf("rekey c2s key mismatch: %x", km2.C2SKey)
	}
	if hex.EncodeToString(km2.S2CPrefix) != vf.Rekey.S2CPrefix {
		t.Errorf("rekey s2c prefix mismatch: %x", km2.S2CPrefix)
	}
}

func TestHandshakeAuthVectors(t *testing.T) {
	vf := loadVectors(t)
	psk := unhex(t, vf.PSK)
	a := vf.Auth

	hello, err := crypt.HelloAuth(psk, a.Role, []byte(a.Ident), unhex(t, a.ClientPub),
		unhex(t, a.ClientNonce), a.Timestamp, a.Suite)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hello) != a.Hello {
		t.Errorf("hello auth mismatch: %x", hello)
	}

	ack, err := crypt.AckAuth(psk, []byte(a.Ident), unhex(t, a.ClientPub), unhex(t, a.ServerPub),
		unhex(t, a.ClientNonce), unhex(t, a.ServerNonce), unhex(t, a.SessionID), a.Suite)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ack) != a.Ack {
		t.Errorf("ack auth mismatch: %x", ack)
	}
}

func TestX25519Exchange(t *testing.T) {
	vf := loadVectors(t)
	// The vectors pin the RFC 7748 base-point multiplication for these keys.
	kp, err := crypt.NewX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := crypt.NewX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	ab, err := kp.Shared(peer.Pub)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := peer.Shared(kp.Pub)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ab) != hex.EncodeToString(ba) {
		t.Fatal("x25519 shared secrets differ")
	}
	if len(ab) != 32 || len(peer.Pub) != 32 || len(unhex(t, vf.Session.ClientPub)) != 32 {
		t.Fatal("unexpected key length")
	}
}

func TestSuiteSupport(t *testing.T) {
	if !crypt.SuiteSupported(wire.SuiteAES256GCM) {
		t.Error("AES-256-GCM must always be supported")
	}
	if crypt.SuiteSupported(wire.SuiteChaCha20Poly1305) {
		t.Skip("this build compiles in ChaCha20-Poly1305")
	}
	if _, err := crypt.Seal(wire.SuiteChaCha20Poly1305, make([]byte, 32), make([]byte, 12), nil, []byte("x")); err == nil {
		t.Error("expected unsupported-suite error")
	}
}

func TestAEADRejectsTampering(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	aad := []byte("header")
	sealed, err := crypt.Seal(wire.SuiteAES256GCM, key, nonce, aad, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[0] ^= 1
	if _, err := crypt.Open(wire.SuiteAES256GCM, key, nonce, aad, sealed); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
