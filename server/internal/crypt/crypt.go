// Package crypt is the server side of the UmbraC2 key schedule and AEAD layer.
//
//	PSK --HKDF--> bootstrap keys (one per direction, per suite)
//	X25519(ephemeral, ephemeral) --HKDF--> session PRK
//	session PRK --HKDF-Expand--> c2s key, s2c key, c2s nonce prefix, s2c nonce prefix
//	running PRK + random seed --HKDF--> rekeyed key set (forward secrecy)
//
// Only AES-256-GCM is compiled into the reference server because Go's standard
// library ships it; ChaCha20-Poly1305 has a reserved suite id, is implemented
// in the Rust implant and the Python operator, and can be enabled here by
// providing a crypt.NewAEAD implementation for SuiteChaCha20Poly1305.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// Roles as carried in the HELLO message.
const (
	RoleAgent    byte = 1
	RoleOperator byte = 2
)

// Versioned domain separation labels. Changing any of these is a protocol break.
var (
	LabelBootstrap = []byte("umbra/v1/bootstrap")
	LabelSession   = []byte("umbra/v1/session")
	LabelRekey     = []byte("umbra/v1/rekey")
)

var (
	ErrUnsupportedSuite = errors.New("crypt: aead suite not supported by this build")
	ErrAuth             = errors.New("crypt: frame authentication failed")
	ErrBadKeyLen        = errors.New("crypt: invalid key length")
)

// KeyMaterial holds the two directional keys and their nonce prefixes.
type KeyMaterial struct {
	C2SKey    []byte // agent/operator -> server
	S2CKey    []byte // server -> agent/operator
	C2SPrefix []byte
	S2CPrefix []byte
}

const okmLen = 72 // 32 + 32 + 4 + 4

// SuiteSupported reports whether this build can use the given AEAD suite.
func SuiteSupported(suite byte) bool { return suite == wire.SuiteAES256GCM }

// ServerSuites is the preference-ordered suite list advertised by the server.
func ServerSuites() []byte { return []byte{wire.SuiteAES256GCM} }

// ---------------------------------------------------------------------------
// hashes, MACs, KDFs
// ---------------------------------------------------------------------------

// SHA256 is a convenience wrapper.
func SHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// HMACSHA256 computes HMAC-SHA256(key, data).
func HMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// HkdfExtract is HKDF-SHA256 extract (RFC 5869).
func HkdfExtract(salt, ikm []byte) []byte { return HMACSHA256(salt, ikm) }

// HkdfExpand is HKDF-SHA256 expand.
func HkdfExpand(prk, info []byte, length int) []byte {
	if length <= 0 || length > 255*32 {
		panic("crypt: invalid hkdf length")
	}
	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{counter})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// HkdfSHA256 runs extract+expand in one call.
func HkdfSHA256(ikm, salt, info []byte, length int) []byte {
	return HkdfExpand(HkdfExtract(salt, ikm), info, length)
}

// ConstantTimeEq compares two byte slices without leaking timing.
func ConstantTimeEq(a, b []byte) bool { return hmac.Equal(a, b) }

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

// X25519Keypair is an ephemeral key pair.
type X25519Keypair struct {
	priv *ecdh.PrivateKey
	Pub  []byte
}

// NewX25519Keypair generates a fresh ephemeral key pair.
func NewX25519Keypair() (*X25519Keypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &X25519Keypair{priv: priv, Pub: priv.PublicKey().Bytes()}, nil
}

// Shared computes the raw X25519 shared secret with the peer's public key.
// crypto/ecdh rejects low-order points, which is what we want here.
func (k *X25519Keypair) Shared(peerPub []byte) ([]byte, error) {
	if len(peerPub) != 32 {
		return nil, fmt.Errorf("crypt: x25519 public key must be 32 bytes, got %d", len(peerPub))
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("crypt: invalid x25519 public key: %w", err)
	}
	shared, err := k.priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("crypt: x25519 exchange failed: %w", err)
	}
	return shared, nil
}

// ---------------------------------------------------------------------------
// key schedule
// ---------------------------------------------------------------------------

// normalisePSK binds the pre-shared key to the negotiated AEAD suite. The PSK
// itself may be any byte string (token, password, key file content).
func normalisePSK(psk []byte, suite byte) []byte {
	salt := append(append([]byte{}, LabelBootstrap...), "/psk"...)
	return HkdfSHA256(psk, salt, []byte{'s', 'u', 'i', 't', 'e', ':', suite}, 32)
}

// DeriveBootstrapKey derives the one-way PSK key used during the handshake.
// The two directions never share a key, and the derived key never doubles as
// an HMAC key: it is only ever used with the AEAD.
func DeriveBootstrapKey(psk []byte, direction string, suite byte) []byte {
	if direction != "c2s" && direction != "s2c" {
		panic("crypt: direction must be c2s or s2c")
	}
	info := string(LabelBootstrap) + "/" + direction
	return HkdfSHA256(normalisePSK(psk, suite), LabelBootstrap, []byte(info), 32)
}

// BootstrapNoncePrefix derives the 4-byte nonce prefix for the PSK phase.
func BootstrapNoncePrefix(key []byte) []byte {
	return HkdfSHA256(key, LabelBootstrap, []byte("nonce-prefix"), 4)
}

// DeriveSession returns the running PRK and the first key set of a session.
func DeriveSession(shared, clientNonce, serverNonce []byte) ([]byte, KeyMaterial, error) {
	if len(clientNonce) != 16 || len(serverNonce) != 16 {
		return nil, KeyMaterial{}, errors.New("crypt: handshake nonces must be 16 bytes")
	}
	saltInput := append(append(append([]byte{}, LabelSession...), clientNonce...), serverNonce...)
	salt := SHA256(saltInput)
	prk := HkdfExtract(salt, shared)
	okm := HkdfExpand(prk, append(LabelSession, "/keys"...), okmLen)
	return prk, materialFromOKM(okm), nil
}

// DeriveRekey mixes a fresh seed into the PRK and returns the next key set.
func DeriveRekey(prk, seed []byte) ([]byte, KeyMaterial, error) {
	if len(seed) != 32 {
		return nil, KeyMaterial{}, errors.New("crypt: rekey seed must be 32 bytes")
	}
	newPrk := HkdfExtract(seed, prk)
	okm := HkdfExpand(newPrk, append(LabelRekey, "/keys"...), okmLen)
	return newPrk, materialFromOKM(okm), nil
}

func materialFromOKM(okm []byte) KeyMaterial {
	return KeyMaterial{
		C2SKey:    okm[0:32],
		S2CKey:    okm[32:64],
		C2SPrefix: okm[64:68],
		S2CPrefix: okm[68:72],
	}
}

// ---------------------------------------------------------------------------
// handshake authentication
// ---------------------------------------------------------------------------

// HelloAuth builds the HMAC that binds the client's HELLO to the PSK.
func HelloAuth(psk []byte, role byte, ident, clientPub, clientNonce []byte, timestamp uint64, suite byte) ([]byte, error) {
	if len(ident) > 255 {
		return nil, errors.New("crypt: identity too long")
	}
	msg := make([]byte, 0, 128)
	msg = append(msg, LabelBootstrap...)
	msg = append(msg, "/auth/hello"...)
	msg = append(msg, role, byte(len(ident)))
	msg = append(msg, ident...)
	msg = append(msg, clientPub...)
	msg = append(msg, clientNonce...)
	msg = binary.BigEndian.AppendUint64(msg, timestamp)
	msg = append(msg, suite)
	return HMACSHA256(psk, msg), nil
}

// AckAuth builds the HMAC that proves the server's HELLO_ACK to the client.
func AckAuth(psk, ident, clientPub, serverPub, clientNonce, serverNonce, sessionID []byte, suite byte) ([]byte, error) {
	if len(ident) > 255 {
		return nil, errors.New("crypt: identity too long")
	}
	msg := make([]byte, 0, 160)
	msg = append(msg, LabelBootstrap...)
	msg = append(msg, "/auth/ack"...)
	msg = append(msg, byte(len(ident)))
	msg = append(msg, ident...)
	msg = append(msg, clientPub...)
	msg = append(msg, serverPub...)
	msg = append(msg, clientNonce...)
	msg = append(msg, serverNonce...)
	msg = append(msg, sessionID...)
	msg = append(msg, suite)
	return HMACSHA256(psk, msg), nil
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

func newAEAD(suite byte, key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrBadKeyLen
	}
	switch suite {
	case wire.SuiteAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedSuite, wire.SuiteName(suite))
	}
}

// Seal encrypts plaintext and returns ciphertext||tag. aad must be the prelude.
func Seal(suite byte, key, nonce, aad, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("crypt: nonce must be %d bytes", aead.NonceSize())
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open authenticates and decrypts ciphertext||tag.
func Open(suite byte, key, nonce, aad, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("crypt: nonce must be %d bytes", aead.NonceSize())
	}
	if len(ciphertext) < aead.Overhead() {
		return nil, ErrAuth
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}
