// Package upk implements Umbra Pack, the canonical binary encoding used by
// every UmbraC2 message.  It has no dependencies and no reflection on the hot
// path (except for the few dynamic types below).
//
// Wire grammar (type byte + payload):
//
//	0x00 null | 0x01 false | 0x02 true
//	0x03 uvarint | 0x04 svarint | 0x05 f64
//	0x06 str (uvarint len + utf8) | 0x07 bin (uvarint len + bytes)
//	0x08 array (uvarint count + values)
//	0x09 map (uvarint count + (str key, value) pairs, keys sorted ascending)
//
// The encoder always emits the canonical form and the decoder rejects
// anything non-canonical, so a given value has exactly one valid encoding.
// See operator/umbra_cli/upk.py for the reference implementation and
// contracts/vectors.json for the pinned test vectors.
//
// This is the beacon's own copy of the encoding, as the Rust and the
// Kotlin implants carry theirs.
package upk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

// Encoding limits. Keeping these tight is a cheap DoS mitigation: nothing can
// allocate more than a few MiB before it has been fully authenticated.
const (
	MaxDepth  = 16
	MaxItems  = 1 << 20
	MaxString = 1 << 20
	MaxTotal  = 4 << 20
)

const (
	tNull  byte = 0x00
	tFalse byte = 0x01
	tTrue  byte = 0x02
	tUint  byte = 0x03
	tInt   byte = 0x04
	tF64   byte = 0x05
	tStr   byte = 0x06
	tBin   byte = 0x07
	tArr   byte = 0x08
	tMap   byte = 0x09
)

// Map is a convenience alias so protocol code can build bodies concisely.
type Map = map[string]any

var (
	ErrTruncated    = errors.New("upk: truncated input")
	ErrNonCanonical = errors.New("upk: non-canonical encoding")
	ErrLimit        = errors.New("upk: value exceeds limit")
	ErrType         = errors.New("upk: unsupported type")
)

// ---------------------------------------------------------------------------
// encoder
// ---------------------------------------------------------------------------

type writer struct {
	buf   []byte
	depth int
}

// Encode returns the canonical encoding of v.
func Encode(v any) ([]byte, error) {
	w := &writer{buf: make([]byte, 0, 64)}
	if err := w.value(v); err != nil {
		return nil, err
	}
	if len(w.buf) > MaxTotal {
		return nil, ErrLimit
	}
	return w.buf, nil
}

func (w *writer) uvarint(n uint64) {
	w.buf = binary.AppendUvarint(w.buf, n)
}

func (w *writer) value(v any) error {
	if len(w.buf) > MaxTotal {
		return ErrLimit
	}
	switch x := v.(type) {
	case nil:
		w.buf = append(w.buf, tNull)
	case bool:
		if x {
			w.buf = append(w.buf, tTrue)
		} else {
			w.buf = append(w.buf, tFalse)
		}
	case int:
		return w.int64(int64(x))
	case int8:
		return w.int64(int64(x))
	case int16:
		return w.int64(int64(x))
	case int32:
		return w.int64(int64(x))
	case int64:
		return w.int64(x)
	case uint:
		return w.uint64(uint64(x))
	case uint8:
		return w.uint64(uint64(x))
	case uint16:
		return w.uint64(uint64(x))
	case uint32:
		return w.uint64(uint64(x))
	case uint64:
		return w.uint64(x)
	case float64:
		w.buf = append(w.buf, tF64)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(x))
		w.buf = append(w.buf, b[:]...)
	case string:
		if len(x) > MaxString {
			return ErrLimit
		}
		// Go strings are arbitrary bytes; upk strings must be valid UTF-8 so
		// that every implementation agrees on one canonical encoding.
		if !utf8.ValidString(x) {
			return fmt.Errorf("%w: string is not valid utf-8", ErrType)
		}
		w.buf = append(w.buf, tStr)
		w.uvarint(uint64(len(x)))
		w.buf = append(w.buf, x...)
	case []byte:
		if len(x) > MaxString {
			return ErrLimit
		}
		w.buf = append(w.buf, tBin)
		w.uvarint(uint64(len(x)))
		w.buf = append(w.buf, x...)
	case []any:
		if len(x) > MaxItems {
			return ErrLimit
		}
		if err := w.enter(); err != nil {
			return err
		}
		w.buf = append(w.buf, tArr)
		w.uvarint(uint64(len(x)))
		for _, item := range x {
			if err := w.value(item); err != nil {
				return err
			}
		}
		w.depth--
	case map[string]any:
		return w.mapping(x)
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = val
		}
		return w.mapping(m)
	default:
		return fmt.Errorf("%w: %T", ErrType, v)
	}
	return nil
}

func (w *writer) mapping(m map[string]any) error {
	if len(m) > MaxItems {
		return ErrLimit
	}
	if err := w.enter(); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if len(k) > MaxString {
			return ErrLimit
		}
		if !utf8.ValidString(k) {
			return fmt.Errorf("%w: map key is not valid utf-8", ErrType)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys) // byte-wise ascending for UTF-8 strings
	w.buf = append(w.buf, tMap)
	w.uvarint(uint64(len(keys)))
	for _, k := range keys {
		w.buf = append(w.buf, tStr)
		w.uvarint(uint64(len(k)))
		w.buf = append(w.buf, k...)
		if err := w.value(m[k]); err != nil {
			return err
		}
	}
	w.depth--
	return nil
}

func (w *writer) int64(n int64) error {
	if n >= 0 {
		return w.uint64(uint64(n))
	}
	w.buf = append(w.buf, tInt)
	w.uvarint(zigzag(n))
	return nil
}

func (w *writer) uint64(n uint64) error {
	w.buf = append(w.buf, tUint)
	w.uvarint(n)
	return nil
}

func (w *writer) enter() error {
	w.depth++
	if w.depth > MaxDepth {
		return fmt.Errorf("%w: nesting too deep", ErrLimit)
	}
	return nil
}

func zigzag(n int64) uint64 { return uint64(n<<1) ^ uint64(n>>63) }

// ---------------------------------------------------------------------------
// decoder
// ---------------------------------------------------------------------------

type reader struct {
	buf   []byte
	pos   int
	depth int
}

// Decode parses one value and returns it together with the number of bytes
// consumed, allowing callers to decode packed sequences.
func Decode(b []byte) (any, int, error) {
	r := &reader{buf: b}
	v, err := r.value()
	if err != nil {
		return nil, 0, err
	}
	return v, r.pos, nil
}

// DecodeExact parses exactly one value and rejects trailing bytes.
func DecodeExact(b []byte) (any, error) {
	v, n, err := Decode(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrNonCanonical, len(b)-n)
	}
	return v, nil
}

func (r *reader) need(n int) error {
	if n < 0 || r.pos+n > len(r.buf) {
		return ErrTruncated
	}
	return nil
}

func (r *reader) uvarint() (uint64, error) {
	var (
		result uint64
		shift  uint
	)
	for i := 0; i < 10; i++ {
		if err := r.need(1); err != nil {
			return 0, err
		}
		b := r.buf[r.pos]
		r.pos++
		if shift == 63 && b > 1 {
			return 0, fmt.Errorf("%w: uvarint overflow", ErrNonCanonical)
		}
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			if i > 0 && b == 0 {
				return 0, fmt.Errorf("%w: non-minimal uvarint", ErrNonCanonical)
			}
			return result, nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("%w: uvarint too long", ErrNonCanonical)
}

func (r *reader) value() (any, error) {
	if err := r.need(1); err != nil {
		return nil, err
	}
	t := r.buf[r.pos]
	r.pos++
	switch t {
	case tNull:
		return nil, nil
	case tFalse:
		return false, nil
	case tTrue:
		return true, nil
	case tUint:
		return r.uvarint()
	case tInt:
		z, err := r.uvarint()
		if err != nil {
			return nil, err
		}
		return int64(z>>1) ^ -int64(z&1), nil
	case tF64:
		if err := r.need(8); err != nil {
			return nil, err
		}
		v := math.Float64frombits(binary.BigEndian.Uint64(r.buf[r.pos:]))
		r.pos += 8
		return v, nil
	case tStr:
		n, err := r.uvarint()
		if err != nil {
			return nil, err
		}
		if n > MaxString {
			return nil, ErrLimit
		}
		if err := r.need(int(n)); err != nil {
			return nil, err
		}
		raw := r.buf[r.pos : r.pos+int(n)]
		r.pos += int(n)
		if !utf8.Valid(raw) {
			return nil, fmt.Errorf("%w: invalid utf-8 string", ErrType)
		}
		return string(raw), nil
	case tBin:
		n, err := r.uvarint()
		if err != nil {
			return nil, err
		}
		if n > MaxString {
			return nil, ErrLimit
		}
		if err := r.need(int(n)); err != nil {
			return nil, err
		}
		out := make([]byte, n)
		copy(out, r.buf[r.pos:r.pos+int(n)])
		r.pos += int(n)
		return out, nil
	case tArr:
		n, err := r.uvarint()
		if err != nil {
			return nil, err
		}
		if n > MaxItems {
			return nil, ErrLimit
		}
		if err := r.enter(); err != nil {
			return nil, err
		}
		out := make([]any, 0, min64(n, 64))
		for i := uint64(0); i < n; i++ {
			v, err := r.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		r.depth--
		return out, nil
	case tMap:
		n, err := r.uvarint()
		if err != nil {
			return nil, err
		}
		if n > MaxItems {
			return nil, ErrLimit
		}
		if err := r.enter(); err != nil {
			return nil, err
		}
		out := make(map[string]any, min64(n, 64))
		var prev string
		for i := uint64(0); i < n; i++ {
			if err := r.need(1); err != nil {
				return nil, err
			}
			if r.buf[r.pos] != tStr {
				return nil, fmt.Errorf("%w: map key must be a string", ErrType)
			}
			r.pos++
			klen, err := r.uvarint()
			if err != nil {
				return nil, err
			}
			if klen > MaxString {
				return nil, ErrLimit
			}
			if err := r.need(int(klen)); err != nil {
				return nil, err
			}
			kraw := r.buf[r.pos : r.pos+int(klen)]
			r.pos += int(klen)
			if !utf8.Valid(kraw) {
				return nil, fmt.Errorf("%w: invalid utf-8 map key", ErrType)
			}
			key := string(kraw)
			if i > 0 && key <= prev {
				return nil, fmt.Errorf("%w: map keys not ascending", ErrNonCanonical)
			}
			prev = key
			v, err := r.value()
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		r.depth--
		return out, nil
	default:
		return nil, fmt.Errorf("%w: tag 0x%02x", ErrType, t)
	}
}

func (r *reader) enter() error {
	r.depth++
	if r.depth > MaxDepth {
		return fmt.Errorf("%w: nesting too deep", ErrLimit)
	}
	return nil
}

func min64(a uint64, b int) int {
	if a < uint64(b) {
		return int(a)
	}
	return b
}
