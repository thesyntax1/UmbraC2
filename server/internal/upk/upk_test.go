package upk_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/upk"
)

// vectorsPath resolves contracts/vectors.json from any package directory.
func vectorsPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "contracts", "vectors.json"))
	if err != nil {
		t.Fatalf("resolve vectors: %v", err)
	}
	return p
}

type upkVector struct {
	Name string          `json:"name"`
	JSON json.RawMessage `json:"json"`
	Hex  string          `json:"hex"`
}

type vectorFile struct {
	Upk     []upkVector       `json:"upk"`
	Rejects map[string]string `json:"rejects"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath(t))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vf.Upk) == 0 {
		t.Fatal("no upk vectors found")
	}
	return vf
}

// fromJSON converts the vector JSON form into the Go types upk encodes.
// Binary values use the {"$bin": "<hex>"} convention.
func fromJSON(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep 64-bit integers exact
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("vector json: %v", err)
	}
	return convert(t, v)
}

func convert(t *testing.T, v any) any {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		if b, ok := x["$bin"].(string); ok && len(x) == 1 {
			raw, err := hex.DecodeString(b)
			if err != nil {
				t.Fatalf("bad $bin hex: %v", err)
			}
			return raw
		}
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = convert(t, val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = convert(t, item)
		}
		return out
	case json.Number:
		if u, err := strconv.ParseUint(x.String(), 10, 64); err == nil {
			return u
		}
		if i, err := strconv.ParseInt(x.String(), 10, 64); err == nil {
			return i
		}
		f, err := strconv.ParseFloat(x.String(), 64)
		if err != nil {
			t.Fatalf("vector number %q: %v", x.String(), err)
		}
		return f
	default:
		return v
	}
}

func TestVectorEncode(t *testing.T) {
	for _, v := range loadVectors(t).Upk {
		want := v.Hex
		got, err := upk.Encode(fromJSON(t, v.JSON))
		if err != nil {
			t.Errorf("%s: encode: %v", v.Name, err)
			continue
		}
		if hex.EncodeToString(got) != want {
			t.Errorf("%s: encode mismatch\n got %x\nwant %s", v.Name, got, want)
		}
	}
}

func TestVectorDecodeRoundTrip(t *testing.T) {
	for _, v := range loadVectors(t).Upk {
		raw, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatalf("%s: bad vector hex", v.Name)
		}
		val, err := upk.DecodeExact(raw)
		if err != nil {
			t.Errorf("%s: decode: %v", v.Name, err)
			continue
		}
		again, err := upk.Encode(val)
		if err != nil {
			t.Errorf("%s: re-encode: %v", v.Name, err)
			continue
		}
		if hex.EncodeToString(again) != v.Hex {
			t.Errorf("%s: round trip mismatch", v.Name)
		}
	}
}

func TestRejects(t *testing.T) {
	rejects := loadVectors(t).Rejects
	cases := map[string]string{
		"upk_trailing":     "trailing bytes",
		"upk_unknown_tag":  "unknown tag",
		"upk_nonminimal":   "non-minimal",
		"upk_unsorted_map": "ascending",
	}
	for name, want := range cases {
		raw, err := hex.DecodeString(rejects[name])
		if err != nil {
			t.Fatalf("%s: bad hex", name)
		}
		if _, err := upk.DecodeExact(raw); err == nil {
			t.Errorf("%s: expected rejection (%s), got none", name, want)
		}
	}
}

func TestLimits(t *testing.T) {
	if _, err := upk.Encode(make([]byte, upk.MaxString+1)); !errors.Is(err, upk.ErrLimit) {
		t.Errorf("oversized binary: want ErrLimit, got %v", err)
	}
	deep := any("x")
	for i := 0; i < upk.MaxDepth+2; i++ {
		deep = []any{deep}
	}
	if _, err := upk.Encode(deep); err == nil {
		t.Error("expected nesting limit error")
	}
}

func TestMapOrderIsDeterministic(t *testing.T) {
	a, err := upk.Encode(map[string]any{"b": uint64(1), "a": uint64(2)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := upk.Encode(map[string]any{"a": uint64(2), "b": uint64(1)})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatalf("map encoding is not canonical: %x vs %x", a, b)
	}
}
