// Package wire defines the UmbraC2 v1 frame format and message registry.
//
//	prelude (12 bytes, cleartext but authenticated as AEAD AAD)
//	  0..1  magic "UC"
//	  2     version
//	  3     flags (bit0 = bootstrap/PSK phase)
//	  4     message type
//	  5     AEAD suite
//	  6..7  reserved (must be zero)
//	  8..11 plaintext length (u32 BE)
//	  12..23 nonce (4-byte direction prefix + 8-byte counter, BE)
//	  24..   ciphertext || 16-byte tag
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Version    byte = 1
	PreludeLen      = 12
	NonceLen        = 12
	TagLen          = 16
	HeaderLen       = PreludeLen + NonceLen
	MaxBody         = 1 << 20
	MaxFrame        = HeaderLen + MaxBody + TagLen
)

// Magic identifies an UmbraC2 frame on a shared socket.
var Magic = [2]byte{0x55, 0x43}

// AEAD suites. The server always supports suite 1; suite 2 is negotiated when
// every participant supports it (see crypt.SuiteSupported).
const (
	SuiteAES256GCM       byte = 1
	SuiteChaCha20Poly1305 byte = 2
)

// Frame flags.
const (
	FlagBootstrap byte = 0x01
)

// Message types -- stable wire constants, never renumber.
const (
	MsgHello    byte = 0x01
	MsgHelloAck byte = 0x02

	MsgCheckin    byte = 0x10
	MsgTaskBatch  byte = 0x11
	MsgResult     byte = 0x12
	MsgConfig     byte = 0x13
	MsgPing       byte = 0x14
	MsgPong       byte = 0x15
	MsgRekey      byte = 0x16
	MsgKill       byte = 0x17
	MsgTaskCancel byte = 0x18
	MsgBye        byte = 0x19

	MsgError byte = 0x1F

	MsgOpRequest  byte = 0x20
	MsgOpResponse byte = 0x21
	MsgOpEvent    byte = 0x22

	// payload markers inside handshake bodies
	MarkerHello    byte = 0x01
	MarkerHelloAck byte = 0x02
)

// SuiteName returns the human readable name of an AEAD suite.
func SuiteName(id byte) string {
	switch id {
	case SuiteAES256GCM:
		return "aes-256-gcm"
	case SuiteChaCha20Poly1305:
		return "chacha20-poly1305"
	default:
		return fmt.Sprintf("unknown(%d)", id)
	}
}

// TypeName returns the human readable name of a message type.
func TypeName(t byte) string {
	switch t {
	case MsgHello:
		return "HELLO"
	case MsgHelloAck:
		return "HELLO_ACK"
	case MsgCheckin:
		return "CHECKIN"
	case MsgTaskBatch:
		return "TASK_BATCH"
	case MsgResult:
		return "RESULT"
	case MsgConfig:
		return "CONFIG"
	case MsgPing:
		return "PING"
	case MsgPong:
		return "PONG"
	case MsgRekey:
		return "REKEY"
	case MsgKill:
		return "KILL"
	case MsgTaskCancel:
		return "TASK_CANCEL"
	case MsgBye:
		return "BYE"
	case MsgError:
		return "ERROR"
	case MsgOpRequest:
		return "OP_REQUEST"
	case MsgOpResponse:
		return "OP_RESPONSE"
	case MsgOpEvent:
		return "OP_EVENT"
	default:
		return fmt.Sprintf("type(0x%02x)", t)
	}
}

var (
	ErrBadMagic   = errors.New("wire: bad magic")
	ErrBadVersion = errors.New("wire: unsupported version")
	ErrTooLarge   = errors.New("wire: frame too large")
	ErrReserved   = errors.New("wire: reserved prelude bytes set")
)

// Header is the parsed (still cleartext) part of a frame.
type Header struct {
	Version byte
	Flags   byte
	Type    byte
	Suite   byte
	Length  uint32
	Nonce   [NonceLen]byte
	Prelude [PreludeLen]byte
}

// BuildHeader assembles the authenticated prelude for a body of plaintextLen.
func BuildHeader(flags, msgType, suite byte, plaintextLen int) [PreludeLen]byte {
	var p [PreludeLen]byte
	p[0], p[1] = Magic[0], Magic[1]
	p[2] = Version
	p[3] = flags
	p[4] = msgType
	p[5] = suite
	p[6], p[7] = 0, 0
	binary.BigEndian.PutUint32(p[8:12], uint32(plaintextLen))
	return p
}

// ParsePrelude validates and decodes a prelude.
func ParsePrelude(p []byte) (Header, error) {
	var h Header
	if len(p) < PreludeLen {
		return h, io.ErrUnexpectedEOF
	}
	if p[0] != Magic[0] || p[1] != Magic[1] {
		return h, ErrBadMagic
	}
	if p[2] != Version {
		return h, fmt.Errorf("%w: %d", ErrBadVersion, p[2])
	}
	if p[6] != 0 || p[7] != 0 {
		return h, ErrReserved
	}
	if p[5] != SuiteAES256GCM && p[5] != SuiteChaCha20Poly1305 {
		return h, fmt.Errorf("wire: unknown suite %d", p[5])
	}
	h.Version = p[2]
	h.Flags = p[3]
	h.Type = p[4]
	h.Suite = p[5]
	h.Length = binary.BigEndian.Uint32(p[8:12])
	if h.Length > MaxBody {
		return h, ErrTooLarge
	}
	copy(h.Prelude[:], p[:PreludeLen])
	return h, nil
}

// FrameLen returns the total on-wire size of a frame with the given plaintext
// length, including header and tag.
func FrameLen(plaintextLen int) int { return HeaderLen + plaintextLen + TagLen }

// ReadFrame reads one complete frame (header + ciphertext + tag) from r.
func ReadFrame(r io.Reader) ([]byte, error) {
	prelude := make([]byte, PreludeLen)
	if _, err := io.ReadFull(r, prelude); err != nil {
		return nil, err
	}
	h, err := ParsePrelude(prelude)
	if err != nil {
		return nil, err
	}
	rest := make([]byte, NonceLen+int(h.Length)+TagLen)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	return append(prelude, rest...), nil
}

// MakeNonce builds a deterministic per-frame nonce.
func MakeNonce(prefix []byte, counter uint64) ([NonceLen]byte, error) {
	var n [NonceLen]byte
	if len(prefix) != 4 {
		return n, fmt.Errorf("wire: nonce prefix must be 4 bytes, got %d", len(prefix))
	}
	copy(n[:4], prefix)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n, nil
}
