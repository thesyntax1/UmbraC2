// Package otp holds the second factor of the operator.
//
// The token of an operator is a secret that lives in the configuration
// of the server and in the memory of the console.  A second factor is a
// secret that lives in the phone of the operator and never travels: the
// console sends the six digits of the moment, the server checks them
// against the secret it keeps, and the code is useless a minute later.
//
// The rules are three:
//
//   - the secret is shown once.  The server hands it out when it is
//     rotated and never again, and the file it keeps is not readable
//     by anybody but the server;
//   - the check is constant time.  A server that compares the codes
//     byte by byte is a server that leaks the code one byte at a time;
//   - a window of one step on each side.  A code that was made half a
//     minute ago is still good, because the clock of a phone is not the
//     clock of the server, and a code from an hour ago is not good at
//     all.
//
// The codes follow RFC 6238 with HMAC-SHA1 and six digits, which is
// what the authenticator applications of every phone understand.  The
// secret is base32 without padding, the way those applications write
// it.
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- HMAC-SHA1 is what RFC 6238 asks for.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The shape of the codes.
const (
	// Digits is how many digits a code has.
	Digits = 6
	// Period is the length of one step, in seconds.
	Period = 30
	// Window is how many steps on each side of the moment are
	// accepted.  One step is thirty seconds.
	Window = 1
	// SecretLen is the length of the secret in bytes, before base32.
	SecretLen = 20
	// MaxOperators bounds the registry: a registry of a thousand
	// operators is a registry of a server that serves a thousand
	// people, and this server serves a team.
	MaxOperators = 64
	// MaxIssuerLen bounds the name of the team that issues the codes.
	MaxIssuerLen = 64
)

// The errors of the package.
var (
	// ErrNoSuchOperator says that the operator has no second factor.
	ErrNoSuchOperator = errors.New("otp: the operator has no second factor")
	// ErrNoOperator says that the operator was not named.
	ErrNoOperator = errors.New("otp: the operator was not named")
	// ErrTooMany says that the registry is full.
	ErrTooMany = errors.New("otp: too many operators")
)

// Secret is the second factor of one operator.
type Secret struct {
	// Operator is the identity the secret belongs to.
	Operator string `json:"operator"`
	// Secret is the base32 secret itself.  It never leaves the server
	// except when it is rotated.
	Secret string `json:"secret"`
	// Issuer is the name of the team, the way the phone shows it.
	Issuer string `json:"issuer,omitempty"`
	// Created is when the secret was made.
	Created time.Time `json:"created"`
	// Rotated is when the secret was changed the last time.
	Rotated time.Time `json:"rotated"`
	// Enabled says whether the server asks for the code of this
	// operator.  A secret that is kept but not asked for is a secret
	// that is ready for the day the team turns it on.
	Enabled bool `json:"enabled"`
}

// Clone returns a copy of the secret.
func (s Secret) Clone() Secret { return s }

// Status is what the operator is told about the second factors.
//
// The secret is not in it.  A list of second factors that carries the
// secrets is a list of second factors that leaks them.
type Status struct {
	// Operator is the identity.
	Operator string `json:"operator"`
	// Issuer is the name of the team.
	Issuer string `json:"issuer,omitempty"`
	// Enabled says whether the code is asked for.
	Enabled bool `json:"enabled"`
	// Created is when the secret was made.
	Created time.Time `json:"created"`
	// Rotated is when the secret was changed the last time.
	Rotated time.Time `json:"rotated"`
	// Age is how long the secret has been in place, in words.
	Age string `json:"age"`
}

// Registry holds the second factors of the team.
type Registry struct {
	mu      sync.RWMutex
	byOp    map[string]Secret
	path    string
	loaded  bool
	nowFunc func() time.Time
	// used is the last step a code was spent on, per operator: the
	// second factor proves itself once, not once per window.
	used map[string]int64
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{byOp: make(map[string]Secret), nowFunc: func() time.Time { return time.Now().UTC() }}
}

// SetPath tells the registry where to keep itself.
//
// The path is a file: the secrets are written as a JSON object with
// the counter of nothing and the secrets themselves.  The file is
// written for the server only.
func (r *Registry) SetPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path = path
}

// Path is where the registry is kept, empty when it is not kept.
func (r *Registry) Path() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.path
}

// Load reads the registry back.
//
// A file that cannot be read is not fatal: the server starts with an
// empty registry and says so.  A registry that is silently wrong is a
// trap: an operator who believes the second factor is on would be
// wrong about the one thing that protects the console.
func (r *Registry) Load() error {
	r.mu.RLock()
	path := r.path
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("otp: read %s: %w", path, err)
	}
	var file registryFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("otp: parse %s: %w", path, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byOp = make(map[string]Secret, len(file.Secrets))
	for _, sec := range file.Secrets {
		if sec.Operator == "" || sec.Secret == "" {
			continue
		}
		r.byOp[sec.Operator] = sec
	}
	r.loaded = true
	return nil
}

// registryFile is what the registry looks like on the disk.
//
// The version guards against a downgrade: a file written by a newer
// build may hold fields this one would silently drop.
type registryFile struct {
	Version int      `json:"version"`
	SavedAt time.Time `json:"saved_at"`
	Secrets []Secret `json:"secrets"`
}

// Save writes the registry to the disk.
//
// The write is atomic and the file belongs to the server alone: the
// secrets of the second factors are the keys of the console.
func (r *Registry) Save() error {
	r.mu.RLock()
	path := r.path
	secrets := make([]Secret, 0, len(r.byOp))
	for _, sec := range r.byOp {
		secrets = append(secrets, sec)
	}
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].Operator < secrets[j].Operator })
	raw, err := json.MarshalIndent(registryFile{
		Version: 1,
		SavedAt: time.Now().UTC(),
		Secrets: secrets,
	})
	if err != nil {
		return fmt.Errorf("otp: the registry could not be written: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("otp: %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("otp: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("otp: save the registry: %w", err)
	}
	return nil
}

// Rotate makes a new secret for an operator.
//
// The old secret stops working at once: a secret that keeps working
// after it was rotated is a secret that was leaked.
func (r *Registry) Rotate(operator, issuer string) (Secret, error) {
	operator = strings.TrimSpace(operator)
	issuer = strings.TrimSpace(issuer)
	if operator == "" {
		return Secret{}, ErrNoOperator
	}
	if len(issuer) > MaxIssuerLen {
		return Secret{}, fmt.Errorf("otp: the issuer is longer than %d characters", MaxIssuerLen)
	}
	secret, err := GenerateSecret()
	if err != nil {
		return Secret{}, err
	}
	r.mu.Lock()
	if _, ok := r.byOp[operator]; !ok && len(r.byOp) >= MaxOperators {
		r.mu.Unlock()
		return Secret{}, ErrTooMany
	}
	now := r.nowFunc()
	old := r.byOp[operator]
	entry := Secret{
		Operator: operator,
		Secret:   secret,
		Issuer:   issuer,
		Created:  now,
		Rotated:  now,
		Enabled:  true,
	}
	if !old.Created.IsZero() {
		entry.Created = old.Created
	}
	r.byOp[operator] = entry
	// A new secret has new steps: the memory of the old ones would
	// refuse the first code of the new phone.
	delete(r.used, operator)
	r.mu.Unlock()
	return entry, nil
}

// Remove takes the second factor of an operator away.
//
// The console of that operator works again with the token alone, which
// is what the team wants when a phone is lost.
func (r *Registry) Remove(operator string) error {
	operator = strings.TrimSpace(operator)
	if operator == "" {
		return ErrNoOperator
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byOp[operator]; !ok {
		return ErrNoSuchOperator
	}
	delete(r.byOp, operator)
	delete(r.used, operator)
	return nil
}

// Enable turns the second factor of an operator on or off.
//
// A secret that is kept but not asked for is ready for the day the
// team turns it on.
func (r *Registry) Enable(operator string, on bool) error {
	operator = strings.TrimSpace(operator)
	if operator == "" {
		return ErrNoOperator
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	sec, ok := r.byOp[operator]
	if !ok {
		return ErrNoSuchOperator
	}
	sec.Enabled = on
	r.byOp[operator] = sec
	return nil
}

// SecretFor returns the secret of an operator.
//
// The caller is the server itself: the secret does not travel to the
// console except when it is rotated.
func (r *Registry) SecretFor(operator string) (Secret, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sec, ok := r.byOp[strings.TrimSpace(operator)]
	return sec, ok
}

// Enabled says whether the server asks this operator for a code.
func (r *Registry) Enabled(operator string) bool {
	sec, ok := r.SecretFor(operator)
	return ok && sec.Enabled
}

// Verify says whether the code is the code of the moment.
//
// The comparison is constant time and the window is one step on each
// side, so a phone whose clock is a little off still works.
func (r *Registry) Verify(operator, code string, now time.Time) bool {
	sec, ok := r.SecretFor(operator)
	if !ok || !sec.Enabled {
		return true
	}
	return Verify(sec.Secret, code, now)
}

// VerifyOnce is Verify with the memory of the step it accepted.
//
// A code of the moment is a one-time code: without this memory the code a
// console used to open one session would open another for the rest of the
// window, which makes the second factor a password that changes every
// thirty seconds instead of a proof that is spent by use.  The step, not
// the code, is remembered, because two codes of the same step differ only
// by the arithmetic that produced them.
func (r *Registry) VerifyOnce(operator, code string, now time.Time) bool {
	sec, ok := r.SecretFor(operator)
	if !ok || !sec.Enabled {
		return true
	}
	step, matched := matchStep(sec.Secret, code, now)
	if !matched {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used == nil {
		r.used = make(map[string]int64, 8)
	}
	if step <= r.used[sec.Operator] {
		// The code is right and already spent: a console that lost
		// its session asks again with the next code, not this one.
		return false
	}
	r.used[sec.Operator] = step
	return true
}

// Status returns what the operator is told about the second factors.
//
// The secrets are not in it.
func (r *Registry) Status() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Status, 0, len(r.byOp))
	for _, sec := range r.byOp {
		out = append(out, Status{
			Operator: sec.Operator,
			Issuer:   sec.Issuer,
			Enabled:  sec.Enabled,
			Created:  sec.Created,
			Rotated:  sec.Rotated,
			Age:      age(sec.Rotated),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operator < out[j].Operator })
	return out
}

// age says how long ago something happened, in words.
func age(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// GenerateSecret makes a new secret.
//
// The secret is twenty bytes of the system generator, written in
// base32 without padding: the way the authenticator applications
// expect it.
func GenerateSecret() (string, error) {
	raw := make([]byte, SecretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("otp: the secret could not be made: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// DecodeSecret reads the bytes of a secret.
func DecodeSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	if cleaned == "" {
		return nil, errors.New("otp: the secret is empty")
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("otp: the secret is not base32: %w", err)
	}
	if len(raw) < 10 {
		return nil, errors.New("otp: the secret is too short")
	}
	return raw, nil
}

// Code returns the code of the moment for a secret.
//
// The console does not need it -- the phone of the operator has it --
// but a lab does: an operator who is testing the second factor needs
// a way to see what the server expects.
func Code(secret string, now time.Time) (string, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(now.UTC().Unix()) / Period
	return codeAt(key, counter)
}

// Verify says whether the code is the code of the moment.
func Verify(secret, code string, now time.Time) bool {
	_, ok := matchStep(secret, code, now)
	return ok
}

// matchStep is the step a code answers to, or false when it answers to none.
//
// The comparison is constant time on every step of the window, so the time
// the check takes says nothing about how close a wrong code was.
func matchStep(secret, code string, now time.Time) (int64, bool) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return 0, false
	}
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	counter := int64(now.UTC().Unix()) / Period
	for delta := -int64(Window); delta <= int64(Window); delta++ {
		step := counter + delta
		if step < 0 {
			continue
		}
		want, err := codeAt(key, uint64(step))
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// codeAt is the code of one step.
//
// This is the arithmetic of RFC 6238: the counter of the step, the
// HMAC of it under the secret, the byte that says where the number
// starts and the number itself.
func codeAt(key []byte, counter uint64) (string, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(buf[:]); err != nil {
		return "", fmt.Errorf("otp: the code could not be made: %w", err)
	}
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, value%mod), nil
}

// URI is the address the authenticator application reads.
//
// The phone scans the picture or types the secret; either way the
// application ends up with the same secret.
func URI(issuer, account, secret string) string {
	label := url.PathEscape(strings.TrimSpace(issuer) + ":" + strings.TrimSpace(account))
	q := url.Values{}
	q.Set("secret", strings.TrimSpace(secret))
	q.Set("issuer", strings.TrimSpace(issuer))
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(Digits))
	q.Set("period", strconv.Itoa(Period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
