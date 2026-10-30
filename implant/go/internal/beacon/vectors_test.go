package beacon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/thesyntax1/UmbraC2/implant/go/internal/crypt"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/session"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/upk"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/wire"
)

// The vectors are the contract between the implementations: the server,
// the Rust beacon, the Kotlin beacon and this one have to agree on every
// byte, and these tests are what proves it.
const vectorPath = "../../../../contracts/vectors.json"

// loadVectors reads the contract and keeps the numbers as they are: the
// integers and the floats are different types in Umbra Pack, so the
// decoder must not turn them into one.
func loadVectors(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read the vectors: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil {
		t.Fatalf("decode the vectors: %v", err)
	}
	return out
}

// mapAt reads a nested map of the vectors.
func mapAt(t *testing.T, v any, key string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("the vectors hold a map")
	}
	nested, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("the vectors hold no map under %q", key)
	}
	return nested
}

// sliceAt reads a nested array of the vectors.
func sliceAt(t *testing.T, v any, key string) []any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("the vectors hold a map")
	}
	nested, ok := m[key].([]any)
	if !ok {
		t.Fatalf("the vectors hold no array under %q", key)
	}
	return nested
}

// strAt reads a text field of the vectors.
func strAt(t *testing.T, v any, key string) string {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("the vectors hold a map")
	}
	text, ok := m[key].(string)
	if !ok {
		t.Fatalf("the vectors hold no text under %q", key)
	}
	return text
}

// numAt reads a number of the vectors.
func numAt(t *testing.T, v any, key string) uint64 {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("the vectors hold a map")
	}
	number, ok := m[key].(json.Number)
	if !ok {
		t.Fatalf("the vectors hold no number under %q", key)
	}
	value, err := number.Int64()
	if err != nil {
		t.Fatalf("the number under %q is not an integer: %v", key, err)
	}
	return uint64(value)
}

// unhex decodes a hex field of the vectors.
func unhex(t *testing.T, v any, key string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strAt(t, v, key))
	if err != nil {
		t.Fatalf("the field %q is not hex: %v", key, err)
	}
	return raw
}

// toValue turns a value of the vectors into the value of Umbra Pack.
func toValue(t *testing.T, v any) any {
	t.Helper()
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		return x
	case json.Number:
		if i, err := x.Int64(); err == nil {
			if i < 0 {
				return i
			}
			return uint64(i)
		}
		// The biggest unsigned integer does not fit in a signed one, and
		// it must not become a float on the way.
		if u, err := strconv.ParseUint(x.String(), 10, 64); err == nil {
			return u
		}
		f, err := x.Float64()
		if err != nil {
			t.Fatalf("the number is not a float either: %v", err)
		}
		return f
	case string:
		return x
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, toValue(t, item))
		}
		return out
	case map[string]any:
		if raw, ok := x["$bin"]; ok {
			if len(x) != 1 {
				t.Fatalf("the binary value carries other fields")
			}
			text, ok := raw.(string)
			if !ok {
				t.Fatalf("the binary value is not hex")
			}
			decoded, err := hex.DecodeString(text)
			if err != nil {
				t.Fatalf("the binary value is not hex: %v", err)
			}
			return decoded
		}
		out := make(map[string]any, len(x))
		for key, item := range x {
			out[key] = toValue(t, item)
		}
		return out
	default:
		t.Fatalf("the vectors hold a value of an unknown type %T", v)
		return nil
	}
}

func TestUpkEncodingMatchesVectors(t *testing.T) {
	vectors := loadVectors(t)
	for _, item := range sliceAt(t, vectors, "upk") {
		caseMap, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("a vector is not a map")
		}
		name := strAt(t, caseMap, "name")
		want := strAt(t, caseMap, "hex")
		value := toValue(t, caseMap["json"])

		encoded, err := upk.Encode(value)
		if err != nil {
			t.Fatalf("encode %s: %v", name, err)
		}
		if got := hex.EncodeToString(encoded); got != want {
			t.Fatalf("the encoding of %s is %s, the vector says %s", name, got, want)
		}
		decoded, err := upk.DecodeExact(encoded)
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		again, err := upk.Encode(decoded)
		if err != nil {
			t.Fatalf("encode %s again: %v", name, err)
		}
		if got := hex.EncodeToString(again); got != want {
			t.Fatalf("the round trip of %s is %s, the vector says %s", name, got, want)
		}
	}
}

func TestUpkRejectsInvalidEncodings(t *testing.T) {
	vectors := loadVectors(t)
	rejects := mapAt(t, vectors, "rejects")
	for _, name := range []string{
		"upk_trailing",
		"upk_unknown_tag",
		"upk_nonminimal",
		"upk_nonminimal_nested",
		"upk_nonminimal_key_len",
		"upk_unsorted_map",
		"upk_duplicate_key",
		"upk_invalid_utf8",
		"upk_surrogate_utf8",
		"upk_overlong_utf8",
		"upk_depth_exceeded",
	} {
		raw, err := hex.DecodeString(rejects[name].(string))
		if err != nil {
			t.Fatalf("the vector %s is not hex: %v", name, err)
		}
		if _, err := upk.DecodeExact(raw); err == nil {
			t.Fatalf("the encoding %s should have been rejected", name)
		}
	}
}

func TestBootstrapKeysMatchVectors(t *testing.T) {
	vectors := loadVectors(t)
	psk := unhex(t, vectors, "psk")
	bootstrap := mapAt(t, vectors, "bootstrap")
	suite := byte(numAt(t, bootstrap, "suite"))

	c2s := crypt.DeriveBootstrapKey(psk, "c2s", suite)
	s2c := crypt.DeriveBootstrapKey(psk, "s2c", suite)
	if got := hex.EncodeToString(c2s); got != strAt(t, bootstrap, "c2s_key") {
		t.Fatalf("the client key is %s, the vector says %s", got, strAt(t, bootstrap, "c2s_key"))
	}
	if got := hex.EncodeToString(s2c); got != strAt(t, bootstrap, "s2c_key") {
		t.Fatalf("the server key is %s, the vector says %s", got, strAt(t, bootstrap, "s2c_key"))
	}
	if got := hex.EncodeToString(crypt.BootstrapNoncePrefix(c2s)); got != strAt(t, bootstrap, "c2s_prefix") {
		t.Fatalf("the client prefix is %s, the vector says %s", got, strAt(t, bootstrap, "c2s_prefix"))
	}
	if got := hex.EncodeToString(crypt.BootstrapNoncePrefix(s2c)); got != strAt(t, bootstrap, "s2c_prefix") {
		t.Fatalf("the server prefix is %s, the vector says %s", got, strAt(t, bootstrap, "s2c_prefix"))
	}
}

func TestSessionAndRekeyKeysMatchVectors(t *testing.T) {
	vectors := loadVectors(t)
	shared := unhex(t, mapAt(t, vectors, "session"), "shared")
	cn := unhex(t, mapAt(t, vectors, "session"), "client_nonce")
	sn := unhex(t, mapAt(t, vectors, "session"), "server_nonce")
	sessionVectors := mapAt(t, vectors, "session")

	prk, km, err := crypt.DeriveSession(shared, cn, sn)
	if err != nil {
		t.Fatalf("derive the session: %v", err)
	}
	if got := hex.EncodeToString(prk); got != strAt(t, sessionVectors, "prk") {
		t.Fatalf("the prk is %s, the vector says %s", got, strAt(t, sessionVectors, "prk"))
	}
	if got := hex.EncodeToString(km.C2SKey); got != strAt(t, sessionVectors, "c2s_key") {
		t.Fatalf("the client key is %s, the vector says %s", got, strAt(t, sessionVectors, "c2s_key"))
	}
	if got := hex.EncodeToString(km.S2CKey); got != strAt(t, sessionVectors, "s2c_key") {
		t.Fatalf("the server key is %s, the vector says %s", got, strAt(t, sessionVectors, "s2c_key"))
	}
	if got := hex.EncodeToString(km.C2SPrefix); got != strAt(t, sessionVectors, "c2s_prefix") {
		t.Fatalf("the client prefix is %s, the vector says %s", got, strAt(t, sessionVectors, "c2s_prefix"))
	}
	if got := hex.EncodeToString(km.S2CPrefix); got != strAt(t, sessionVectors, "s2c_prefix") {
		t.Fatalf("the server prefix is %s, the vector says %s", got, strAt(t, sessionVectors, "s2c_prefix"))
	}

	rekeyVectors := mapAt(t, vectors, "rekey")
	prk2, km2, err := crypt.DeriveRekey(prk, unhex(t, rekeyVectors, "seed"))
	if err != nil {
		t.Fatalf("derive the rekey: %v", err)
	}
	if got := hex.EncodeToString(prk2); got != strAt(t, rekeyVectors, "prk_out") {
		t.Fatalf("the rekey prk is %s, the vector says %s", got, strAt(t, rekeyVectors, "prk_out"))
	}
	if got := hex.EncodeToString(km2.C2SKey); got != strAt(t, rekeyVectors, "c2s_key") {
		t.Fatalf("the rekey client key is %s, the vector says %s", got, strAt(t, rekeyVectors, "c2s_key"))
	}
	if got := hex.EncodeToString(km2.S2CKey); got != strAt(t, rekeyVectors, "s2c_key") {
		t.Fatalf("the rekey server key is %s, the vector says %s", got, strAt(t, rekeyVectors, "s2c_key"))
	}
	if got := hex.EncodeToString(km2.C2SPrefix); got != strAt(t, rekeyVectors, "c2s_prefix") {
		t.Fatalf("the rekey client prefix is %s, the vector says %s", got, strAt(t, rekeyVectors, "c2s_prefix"))
	}
}

func TestHandshakeTranscriptMatchesVectors(t *testing.T) {
	vectors := loadVectors(t)
	psk := unhex(t, vectors, "psk")
	auth := mapAt(t, vectors, "auth")

	hello, err := crypt.HelloAuth(
		psk,
		byte(numAt(t, auth, "role")),
		[]byte(strAt(t, auth, "ident")),
		unhex(t, auth, "client_pub"),
		unhex(t, auth, "client_nonce"),
		numAt(t, auth, "timestamp"),
		byte(numAt(t, auth, "suite")),
	)
	if err != nil {
		t.Fatalf("the hello auth: %v", err)
	}
	if got := hex.EncodeToString(hello); got != strAt(t, auth, "hello") {
		t.Fatalf("the hello auth is %s, the vector says %s", got, strAt(t, auth, "hello"))
	}

	ack, err := crypt.AckAuth(
		psk,
		[]byte(strAt(t, auth, "ident")),
		unhex(t, auth, "client_pub"),
		unhex(t, auth, "server_pub"),
		unhex(t, auth, "client_nonce"),
		unhex(t, auth, "server_nonce"),
		unhex(t, auth, "session_id"),
		byte(numAt(t, auth, "suite")),
	)
	if err != nil {
		t.Fatalf("the ack auth: %v", err)
	}
	if got := hex.EncodeToString(ack); got != strAt(t, auth, "ack") {
		t.Fatalf("the ack auth is %s, the vector says %s", got, strAt(t, auth, "ack"))
	}
}

func TestFramesMatchVectors(t *testing.T) {
	vectors := loadVectors(t)
	for _, item := range sliceAt(t, vectors, "frames") {
		caseMap, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("a vector is not a map")
		}
		suite := byte(numAt(t, caseMap, "suite"))
		if !crypt.SuiteSupported(suite) {
			// This build speaks one suite only.  The vector of the
			// other one is checked by the build that has it.
			continue
		}
		key := unhex(t, caseMap, "key")
		prefix := unhex(t, caseMap, "prefix")
		counter := numAt(t, caseMap, "counter")
		plain := unhex(t, caseMap, "plaintext_hex")
		want := strAt(t, caseMap, "frame_hex")

		nonce, err := wire.MakeNonce(prefix, counter)
		if err != nil {
			t.Fatalf("the nonce: %v", err)
		}
		if got := hex.EncodeToString(nonce[:]); got != strAt(t, caseMap, "nonce") {
			t.Fatalf("the nonce is %s, the vector says %s", got, strAt(t, caseMap, "nonce"))
		}
		header := wire.BuildHeader(0, byte(numAt(t, caseMap, "type")), suite, len(plain))
		sealed, err := crypt.Seal(suite, key, nonce[:], header[:], plain)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		frame := make([]byte, 0, len(header)+len(nonce)+len(sealed))
		frame = append(frame, header[:]...)
		frame = append(frame, nonce[:]...)
		frame = append(frame, sealed...)
		if got := hex.EncodeToString(frame); got != want {
			t.Fatalf("the frame is %s, the vector says %s", got, want)
		}
	}
}

func TestSessionAcceptsVectorFramesAndRejectsReplay(t *testing.T) {
	vectors := loadVectors(t)
	sessionVectors := mapAt(t, vectors, "session")
	km := crypt.KeyMaterial{
		C2SKey:    unhex(t, sessionVectors, "c2s_key"),
		S2CKey:    unhex(t, sessionVectors, "s2c_key"),
		C2SPrefix: unhex(t, sessionVectors, "c2s_prefix"),
		S2CPrefix: unhex(t, sessionVectors, "s2c_prefix"),
	}
	server, err := session.New(wire.SuiteAES256GCM, km, true, false, unhex(t, sessionVectors, "prk"))
	if err != nil {
		t.Fatalf("the session: %v", err)
	}
	frame := unhex(t, sliceAt(t, vectors, "frames")[0].(map[string]any), "frame_hex")
	msgType, _, err := server.OpenFrame(frame)
	if err != nil {
		t.Fatalf("the frame of the vector must authenticate: %v", err)
	}
	if msgType != wire.MsgCheckin {
		t.Fatalf("the frame of the vector is a %s", wire.TypeName(msgType))
	}
	if _, _, err := server.OpenFrame(frame); err == nil {
		t.Fatalf("the replay must be rejected")
	}
}

// TestAttestationMatchesVectors proves that the signature of a report is
// the same in every implementation.  The label and the bytes of the
// report are the contract; the code around them is not.
func TestAttestationMatchesVectors(t *testing.T) {
	vectors := loadVectors(t)
	attest := mapAt(t, vectors, "attest")
	if label, ok := attest["label"].(string); !ok || label != string(crypt.LabelAttest) {
		t.Fatalf("the label of the attestation is %v, the vector says %v",
			string(crypt.LabelAttest), attest["label"])
	}
	key := unhex(t, attest, "key")
	report := unhex(t, attest, "report_hex")
	mac := hmac.New(sha256.New, key)
	mac.Write(crypt.LabelAttest)
	mac.Write(report)
	if got := hex.EncodeToString(mac.Sum(nil)); got != attest["mac"] {
		t.Fatalf("the attestation is %s, the vector says %s", got, attest["mac"])
	}
}
