// Package session implements the encrypted link state machine: one object per
// connection, owning both directions, nonce counters and key rotation.
package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// RekeyAfter is the maximum number of frames encrypted with one key set.
const RekeyAfter = 1 << 20

var (
	ErrReplay    = errors.New("session: nonce mismatch (replay, reorder or desync)")
	ErrFlags     = errors.New("session: unexpected frame flags")
	ErrSuite     = errors.New("session: unexpected aead suite")
	ErrSize      = errors.New("session: frame size mismatch")
	ErrNoPRK     = errors.New("session: no PRK, session cannot rekey")
	ErrBadLength = errors.New("session: length mismatch after decryption")
)

// Direction is one half of a session: key, nonce prefix and frame counter.
type Direction struct {
	key     []byte
	prefix  []byte
	counter uint64
	frames  uint64
}

func (d *Direction) nonce() ([wire.NonceLen]byte, error) {
	return wire.MakeNonce(d.prefix, d.counter)
}

func (d *Direction) advance() {
	d.counter++
	d.frames++
}

func (d *Direction) rotate(key, prefix []byte) {
	d.key = key
	d.prefix = prefix
	d.counter = 0
	d.frames = 0
}

// Session is safe for one concurrent writer and one concurrent reader; use the
// link's own lock if a transport is fully duplex.
type Session struct {
	Suite     byte
	IsServer  bool
	Bootstrap bool
	Flags     byte

	prk  []byte
	send Direction
	recv Direction

	sendMu sync.Mutex
	recvMu sync.Mutex
}

// New builds a session from key material.
func New(suite byte, km crypt.KeyMaterial, isServer, bootstrap bool, prk []byte) (*Session, error) {
	s := &Session{
		Suite:     suite,
		IsServer:  isServer,
		Bootstrap: bootstrap,
		prk:       prk,
	}
	if bootstrap {
		s.Flags = wire.FlagBootstrap
		if len(km.C2SPrefix) == 0 || len(km.S2CPrefix) == 0 {
			km.C2SPrefix = crypt.BootstrapNoncePrefix(km.C2SKey)
			km.S2CPrefix = crypt.BootstrapNoncePrefix(km.S2CKey)
		}
	}
	if isServer {
		s.send = Direction{key: km.S2CKey, prefix: km.S2CPrefix}
		s.recv = Direction{key: km.C2SKey, prefix: km.C2SPrefix}
	} else {
		s.send = Direction{key: km.C2SKey, prefix: km.C2SPrefix}
		s.recv = Direction{key: km.S2CKey, prefix: km.S2CPrefix}
	}
	return s, nil
}

// NewBootstrap builds the PSK-phase session for a suite.
func NewBootstrap(psk []byte, suite byte, isServer bool) (*Session, error) {
	km := crypt.KeyMaterial{
		C2SKey: crypt.DeriveBootstrapKey(psk, "c2s", suite),
		S2CKey: crypt.DeriveBootstrapKey(psk, "s2c", suite),
	}
	return New(suite, km, isServer, true, nil)
}

// Encrypt encodes body as upk (when it is not already []byte) and seals it.
func (s *Session) Encrypt(msgType byte, body any) ([]byte, error) {
	var plain []byte
	switch b := body.(type) {
	case []byte:
		plain = b
	case nil:
		plain = nil
	default:
		var err error
		plain, err = upk.Encode(b)
		if err != nil {
			return nil, err
		}
	}
	return s.SealFrame(msgType, plain)
}

// SealFrame seals an already encoded body.
func (s *Session) SealFrame(msgType byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) > wire.MaxBody {
		return nil, wire.ErrTooLarge
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	prelude := wire.BuildHeader(s.Flags, msgType, s.Suite, len(plaintext))
	nonce, err := s.send.nonce()
	if err != nil {
		return nil, err
	}
	sealed, err := crypt.Seal(s.Suite, s.send.key, nonce[:], prelude[:], plaintext)
	if err != nil {
		return nil, err
	}
	s.send.advance()

	out := make([]byte, 0, len(prelude)+len(nonce)+len(sealed))
	out = append(out, prelude[:]...)
	out = append(out, nonce[:]...)
	out = append(out, sealed...)
	return out, nil
}

// OpenFrame authenticates and decrypts a complete frame.
func (s *Session) OpenFrame(frame []byte) (byte, []byte, error) {
	if len(frame) < wire.HeaderLen {
		return 0, nil, ErrSize
	}
	h, err := wire.ParsePrelude(frame[:wire.PreludeLen])
	if err != nil {
		return 0, nil, err
	}
	if want := wire.HeaderLen + int(h.Length) + wire.TagLen; len(frame) != want {
		return 0, nil, fmt.Errorf("%w: got %d want %d", ErrSize, len(frame), want)
	}
	if h.Flags != s.Flags {
		return 0, nil, ErrFlags
	}
	if h.Suite != s.Suite {
		return 0, nil, ErrSuite
	}

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	want, err := s.recv.nonce()
	if err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(frame[wire.PreludeLen:wire.HeaderLen], want[:]) {
		return 0, nil, ErrReplay
	}
	plain, err := crypt.Open(s.Suite, s.recv.key, want[:], frame[:wire.PreludeLen], frame[wire.HeaderLen:])
	if err != nil {
		return 0, nil, err
	}
	if len(plain) != int(h.Length) {
		return 0, nil, ErrBadLength
	}
	s.recv.advance()
	return h.Type, plain, nil
}

// OpenMessage decrypts a frame and decodes its upk map body.
func (s *Session) OpenMessage(frame []byte) (byte, map[string]any, error) {
	msgType, plain, err := s.OpenFrame(frame)
	if err != nil {
		return 0, nil, err
	}
	v, err := upk.DecodeExact(plain)
	if err != nil {
		return 0, nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return 0, nil, errors.New("session: body must be a map")
	}
	return msgType, m, nil
}

// NeedsRekey reports whether either counter reached the rekey threshold.
func (s *Session) NeedsRekey() bool {
	return s.send.frames >= RekeyAfter || s.recv.frames >= RekeyAfter
}

// ApplyRekey installs the next key set derived from seed and the running PRK.
func (s *Session) ApplyRekey(seed []byte) error {
	if len(s.prk) == 0 {
		return ErrNoPRK
	}
	newPrk, km, err := crypt.DeriveRekey(s.prk, seed)
	if err != nil {
		return err
	}
	s.sendMu.Lock()
	s.recvMu.Lock()
	defer s.sendMu.Unlock()
	defer s.recvMu.Unlock()

	s.prk = newPrk
	if s.IsServer {
		s.send.rotate(km.S2CKey, km.S2CPrefix)
		s.recv.rotate(km.C2SKey, km.C2SPrefix)
	} else {
		s.send.rotate(km.C2SKey, km.C2SPrefix)
		s.recv.rotate(km.S2CKey, km.S2CPrefix)
	}
	return nil
}

// Counters exposes (send, recv) frame counters for diagnostics.
func (s *Session) Counters() (uint64, uint64) { return s.send.frames, s.recv.frames }

// nonceCounter is exported for tests that need to reason about framing.
func nonceCounter(nonce []byte) uint64 { return binary.BigEndian.Uint64(nonce[4:]) }
