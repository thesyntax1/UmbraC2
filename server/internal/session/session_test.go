package session_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

type frameVector struct {
	Suite        byte   `json:"suite"`
	Key          string `json:"key"`
	Prefix       string `json:"prefix"`
	Counter      uint64 `json:"counter"`
	Nonce        string `json:"nonce"`
	Type         byte   `json:"type"`
	PlaintextHex string `json:"plaintext_hex"`
	FrameHex     string `json:"frame_hex"`
}

type vectorFile struct {
	Frames  []frameVector     `json:"frames"`
	Rejects map[string]string `json:"rejects"`
	Session struct {
		C2SKey    string `json:"c2s_key"`
		S2CKey    string `json:"s2c_key"`
		C2SPrefix string `json:"c2s_prefix"`
		S2CPrefix string `json:"s2c_prefix"`
		Prk       string `json:"prk"`
	} `json:"session"`
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
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestFrameVectors rebuilds each pinned frame from its key, nonce and
// plaintext, proving the prelude layout, nonce derivation and AAD are
// byte-identical across implementations.
func TestFrameVectors(t *testing.T) {
	for i, fv := range loadVectors(t).Frames {
		key := unhex(t, fv.Key)
		prefix := unhex(t, fv.Prefix)
		plain := unhex(t, fv.PlaintextHex)
		want := unhex(t, fv.FrameHex)

		nonce, err := wire.MakeNonce(prefix, fv.Counter)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if hex.EncodeToString(nonce[:]) != fv.Nonce {
			t.Fatalf("frame %d: nonce mismatch %x", i, nonce)
		}
		prelude := wire.BuildHeader(0, fv.Type, fv.Suite, len(plain))
		sealed, err := crypt.Seal(fv.Suite, key, nonce[:], prelude[:], plain)
		if err != nil {
			if errors.Is(err, crypt.ErrUnsupportedSuite) {
				t.Logf("frame %d: suite %d unsupported in this build, skipped", i, fv.Suite)
				continue
			}
			t.Fatalf("frame %d: seal: %v", i, err)
		}
		frame := append(append(prelude[:], nonce[:]...), sealed...)
		if hex.EncodeToString(frame) != hex.EncodeToString(want) {
			t.Fatalf("frame %d mismatch\n got %x\nwant %x", i, frame, want)
		}
		// The body must also decode as upk after decryption.
		if _, err := upk.DecodeExact(plain); err != nil {
			t.Fatalf("frame %d: plaintext is not valid upk: %v", i, err)
		}
	}
}

func newPair(t *testing.T) (*session.Session, *session.Session) {
	t.Helper()
	vf := loadVectors(t)
	km := crypt.KeyMaterial{
		C2SKey:    unhex(t, vf.Session.C2SKey),
		S2CKey:    unhex(t, vf.Session.S2CKey),
		C2SPrefix: unhex(t, vf.Session.C2SPrefix),
		S2CPrefix: unhex(t, vf.Session.S2CPrefix),
	}
	prk := unhex(t, vf.Session.Prk)
	server, err := session.New(wire.SuiteAES256GCM, km, true, false, prk)
	if err != nil {
		t.Fatal(err)
	}
	client, err := session.New(wire.SuiteAES256GCM, km, false, false, prk)
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

func TestSessionRoundTrip(t *testing.T) {
	server, client := newPair(t)

	frame, err := client.Encrypt(wire.MsgCheckin, upk.Map{"ts": uint64(1), "n": uint64(0)})
	if err != nil {
		t.Fatal(err)
	}
	msgType, msg, err := server.OpenMessage(frame)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != wire.MsgCheckin {
		t.Fatalf("wrong type %s", wire.TypeName(msgType))
	}
	if _, ok := msg["ts"]; !ok {
		t.Fatal("body lost its timestamp")
	}

	// Server -> client direction uses independent keys and counters.
	reply, err := server.Encrypt(wire.MsgTaskBatch, upk.Map{"tasks": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.OpenFrame(reply); err != nil {
		t.Fatalf("client could not open server frame: %v", err)
	}
}

func TestSessionRejectsReplay(t *testing.T) {
	server, client := newPair(t)
	frame, err := client.Encrypt(wire.MsgCheckin, upk.Map{"ts": uint64(1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.OpenFrame(frame); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.OpenFrame(frame); err == nil {
		t.Fatal("replayed frame was accepted")
	}
}

func TestSessionRejectsTampering(t *testing.T) {
	server, client := newPair(t)
	frame, err := client.Encrypt(wire.MsgCheckin, upk.Map{"ts": uint64(1)})
	if err != nil {
		t.Fatal(err)
	}
	frame[wire.PreludeLen+wire.NonceLen] ^= 0x80 // flip a ciphertext bit
	if _, _, err := server.OpenFrame(frame); err == nil {
		t.Fatal("tampered frame was accepted")
	}
}

func TestSessionRejectsFlagMismatch(t *testing.T) {
	server, client := newPair(t)
	frame, err := client.Encrypt(wire.MsgCheckin, upk.Map{"ts": uint64(1)})
	if err != nil {
		t.Fatal(err)
	}
	frame[3] = wire.FlagBootstrap // pretend it is a handshake frame
	if _, _, err := server.OpenFrame(frame); err == nil {
		t.Fatal("frame with wrong flags was accepted")
	}
}

func TestSessionRekey(t *testing.T) {
	server, client := newPair(t)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	if err := server.ApplyRekey(seed); err != nil {
		t.Fatal(err)
	}
	if err := client.ApplyRekey(seed); err != nil {
		t.Fatal(err)
	}
	frame, err := client.Encrypt(wire.MsgPing, upk.Map{"ts": uint64(2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.OpenFrame(frame); err != nil {
		t.Fatalf("post-rekey frame rejected: %v", err)
	}
}

func TestBootstrapCannotRekey(t *testing.T) {
	bs, err := session.NewBootstrap([]byte("0123456789abcdef0123456789abcdef"), wire.SuiteAES256GCM, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.ApplyRekey(make([]byte, 32)); err == nil {
		t.Fatal("bootstrap session must not rekey")
	}
}
