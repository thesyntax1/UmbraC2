// Package keyring holds the credentials the server accepts, and rotates them
// while it runs.
//
// A C2 that can only change its credentials by restarting is a C2 with a
// maintenance window: the operator who suspects a token is compromised has
// to choose between a burned console and a server that is down.  This
// package is the other answer.  The keyring holds the current credential and
// the one before it, and the old one keeps working for a while so the
// beacons and the consoles that have not heard the news yet are not locked
// out in the middle of an engagement.
//
// The three things it manages:
//
//   - the agent PSK, the key every beacon authenticates with;
//   - the operator tokens, one per identity, each with a role, a set of
//     scopes, an expiry and the moment it was last used;
//   - the moments of the rotation themselves, so the audit trail can say
//     who rotated what and when.
//
// Everything is guarded by one lock, and nothing in here ever writes a
// secret to a log, an event or an error message.
package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
)

// DefaultOverlap is how long the previous credential keeps working after a
// rotation.
//
// The overlap has to cover the slowest check-in of the fleet: a beacon
// that sleeps for five minutes and a console that was closed for the night
// both have to find the door open.
const DefaultOverlap = 30 * time.Minute

// TokenBytes is how many random bytes a generated token carries.
const TokenBytes = 32

// TokenTextLen is how long the text of a generated token is.
//
// A token is a *text*: the operator types it, copies it into a console
// and writes it into a file.  The bytes of the token are the bytes of
// that text, so what the operator sees is what the server checks.
const TokenTextLen = 2 * TokenBytes

// Operator is one operator's credentials.
type Operator struct {
	// Name is the identity the token authenticates.
	Name string
	// Token is the current token.
	Token []byte
	// Previous is the token from before the last rotation.  It keeps
	// working until the overlap is over.
	Previous []byte
	// PreviousUntil is when the previous token stops working.
	PreviousUntil time.Time
	// Role is admin, operator or viewer.
	Role string
	// Scopes are the commands this operator may call.  An empty list
	// means the role decides, which is the way a deployment that knows
	// nothing about scopes keeps working.
	Scopes []string
	// Expires is when the token stops working for good.
	Expires time.Time
	// LastUsed is when the operator last authenticated.
	LastUsed time.Time
	// RotatedAt is when the token was last rotated.
	RotatedAt time.Time
}

// Expired reports whether the token has expired.
func (o *Operator) Expired(now time.Time) bool {
	return !o.Expires.IsZero() && now.After(o.Expires)
}

// Keyring is the set of credentials the server accepts.
type Keyring struct {
	mu sync.RWMutex

	agentPSK []byte
	// previousAgentPSK is the PSK from before the last rotation.
	previousAgentPSK []byte
	// previousAgentUntil is when the previous PSK stops working.
	previousAgentUntil time.Time

	operators map[string]*Operator
	// overlap is how long the previous credential keeps working.
	overlap time.Duration
}

// FromConfig builds the runtime keyring out of the configured one.
func FromConfig(k config.Keyring) *Keyring {
	ring := &Keyring{
		operators: map[string]*Operator{},
		overlap:   DefaultOverlap,
	}
	if len(k.AgentPSK) > 0 {
		ring.agentPSK = append([]byte(nil), k.AgentPSK...)
	}
	for name, token := range k.Operators {
		op := &Operator{
			Name:  name,
			Token: append([]byte(nil), token...),
			Role:  k.Role(name),
		}
		if scopes, ok := k.Scopes[name]; ok {
			op.Scopes = append([]string(nil), scopes...)
		}
		if expiry, ok := k.Expires[name]; ok && !expiry.IsZero() {
			op.Expires = expiry
		}
		ring.operators[name] = op
	}
	return ring
}

// New builds a keyring with one agent PSK and one operator token.
func New(agentPSK []byte, operator string, token []byte, role string) *Keyring {
	ring := &Keyring{
		agentPSK:  append([]byte(nil), agentPSK...),
		operators: map[string]*Operator{},
		overlap:   DefaultOverlap,
	}
	if operator != "" && len(token) > 0 {
		ring.operators[operator] = &Operator{
			Name:  operator,
			Token: append([]byte(nil), token...),
			Role:  role,
		}
	}
	return ring
}

// Overlap returns how long a previous credential keeps working.
func (k *Keyring) Overlap() time.Duration {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.overlap
}

// SetOverlap changes the overlap window.
func (k *Keyring) SetOverlap(d time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.overlap = d
}

// AgentCandidates returns the agent PSKs the server accepts, newest first.
//
// The handshake tries them in order, so a beacon that still has the old
// key is served while it learns the new one.
func (k *Keyring) AgentCandidates() [][]byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([][]byte, 0, 2)
	if len(k.agentPSK) > 0 {
		out = append(out, append([]byte(nil), k.agentPSK...))
	}
	if len(k.previousAgentPSK) > 0 && k.previousValid(time.Now()) {
		out = append(out, append([]byte(nil), k.previousAgentPSK...))
	}
	return out
}

// OperatorCandidates returns every operator token the server accepts, with
// the identity and the role it belongs to.
//
// The order is stable: the current token of an operator comes before the
// previous one, and the operators come in the order of their names.
func (k *Keyring) OperatorCandidates() []Candidate {
	k.mu.RLock()
	defer k.mu.RUnlock()
	names := make([]string, 0, len(k.operators))
	for name := range k.operators {
		names = append(names, name)
	}
	sortStrings(names)
	out := make([]Candidate, 0, len(names)*2)
	now := time.Now()
	for _, name := range names {
		op := k.operators[name]
		if op.Expired(now) {
			continue
		}
		out = append(out, Candidate{
			Name:  name,
			Token: append([]byte(nil), op.Token...),
			Role:  op.Role,
		})
		if len(op.Previous) > 0 && op.PreviousUntil.After(now) {
			out = append(out, Candidate{
				Name:  name,
				Token: append([]byte(nil), op.Previous...),
				Role:  op.Role,
			})
		}
	}
	return out
}

// Candidate is one token the server accepts.
type Candidate struct {
	Name  string
	Token []byte
	Role  string
}

// Authenticate checks a token and returns the operator it belongs to.
//
// The comparison is constant time: a token is a secret, and the time the
// server takes to reject it says something about it.
func (k *Keyring) Authenticate(name string, token []byte) (*Operator, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	op, ok := k.operators[name]
	if !ok {
		return nil, false
	}
	now := time.Now()
	if op.Expired(now) {
		return nil, false
	}
	if !equalSecret(op.Token, token) &&
		!(len(op.Previous) > 0 && op.PreviousUntil.After(now) && equalSecret(op.Previous, token)) {
		return nil, false
	}
	op.LastUsed = now
	return op, true
}

// Touch records that an operator was seen, without checking a token.
func (k *Keyring) Touch(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if op, ok := k.operators[name]; ok {
		op.LastUsed = time.Now()
	}
}

// Operator returns a copy of one operator's credentials.
func (k *Keyring) Operator(name string) (Operator, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	op, ok := k.operators[name]
	if !ok {
		return Operator{}, false
	}
	return *op, true
}

// Operators returns a copy of every operator's credentials.
func (k *Keyring) Operators() []Operator {
	k.mu.RLock()
	defer k.mu.RUnlock()
	names := make([]string, 0, len(k.operators))
	for name := range k.operators {
		names = append(names, name)
	}
	sortStrings(names)
	out := make([]Operator, 0, len(names))
	for _, name := range names {
		out = append(out, *k.operators[name])
	}
	return out
}

// RotateAgentPSK replaces the agent PSK and returns the new one.
//
// The old PSK keeps working for the overlap, so the beacons that are
// asleep are not locked out.  The caller is responsible for telling the
// fleet: the new PSK travels with the route the server pushes.
//
// The new key is a *text*: the random bytes are hex encoded, so the
// operator can write it into the configuration of a beacon, into a file
// or into an environment variable without anything being lost on the
// way.  A key that only exists as bytes cannot be copied by hand, and a
// key that cannot be copied is a key that cannot be rolled out.
//
// The bytes of the returned key are therefore the bytes of the text: a
// beacon configured with that text authenticates with exactly these
// bytes.
func (k *Keyring) RotateAgentPSK() ([]byte, error) {
	fresh, err := randomToken()
	if err != nil {
		return nil, err
	}
	psk := []byte(hex.EncodeToString(fresh))
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.agentPSK) > 0 {
		k.previousAgentPSK = k.agentPSK
		k.previousAgentUntil = time.Now().Add(k.overlap)
	}
	k.agentPSK = psk
	return append([]byte(nil), psk...), nil
}

// SetAgentPSK replaces the agent PSK with one the operator brought.
//
// The operator may want to choose the key itself (a key management system
// that hands it out), and the server must not argue.
func (k *Keyring) SetAgentPSK(psk []byte) error {
	if len(psk) < 16 {
		return errors.New("keyring: the agent PSK must be at least 16 bytes")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.agentPSK) > 0 {
		k.previousAgentPSK = k.agentPSK
		k.previousAgentUntil = time.Now().Add(k.overlap)
	}
	k.agentPSK = append([]byte(nil), psk...)
	return nil
}

// RotateOperator replaces the token of one operator and returns the new one.
//
// The old token keeps working for the overlap, so a console that was
// closed does not have to be reopened by hand.
//
// The new token is a *text*, hex encoded: the operator types it into the
// console and the server compares exactly those bytes.
func (k *Keyring) RotateOperator(name string) ([]byte, error) {
	fresh, err := NewTokenBytes()
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	op, ok := k.operators[name]
	if !ok {
		return nil, fmt.Errorf("keyring: there is no operator called %q", name)
	}
	op.Previous = op.Token
	op.PreviousUntil = time.Now().Add(k.overlap)
	op.Token = fresh
	op.RotatedAt = time.Now()
	return append([]byte(nil), fresh...), nil
}

// SetOperator replaces the credentials of one operator.
//
// The scopes and the expiry are part of the credentials: an operator
// whose scope was narrowed must not keep the old one.
//
// An operator that does not exist yet is created when a token comes with
// it, so a new analyst can be given a token without restarting the
// server.
func (k *Keyring) SetOperator(name, role string, scopes []string, expires time.Time, token []byte) error {
	if !rbac.Valid(role) {
		return fmt.Errorf("keyring: unknown role %q", role)
	}
	for _, scope := range scopes {
		if scope == "*" {
			// The wildcard means "whatever the role allows"; it names
			// no command of its own.
			continue
		}
		if !rbac.Known(scope) {
			return fmt.Errorf("keyring: unknown command %q in the scopes", scope)
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	op, ok := k.operators[name]
	if !ok {
		if len(token) == 0 {
			return fmt.Errorf("keyring: there is no operator called %q", name)
		}
		op = &Operator{Name: name}
		k.operators[name] = op
	}
	if len(token) > 0 {
		op.Previous = op.Token
		op.PreviousUntil = time.Now().Add(k.overlap)
		op.Token = append([]byte(nil), token...)
		op.RotatedAt = time.Now()
	}
	op.Role = role
	op.Scopes = append([]string(nil), scopes...)
	op.Expires = expires
	return nil
}

// RemoveOperator forgets an operator entirely.
//
// A token that is not in the keyring does not exist: it is not a token
// that is temporarily refused.
func (k *Keyring) RemoveOperator(name string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.operators[name]; !ok {
		return false
	}
	delete(k.operators, name)
	return true
}

// Allowed says whether an operator may call a command.
//
// The scopes narrow the role; they never widen it.  An operator with
// scopes may call what is in them and what its role allows, and nothing
// else.  The scope `*` means "no narrowing", so the role alone decides.
//
// An operator without scopes is judged by the role alone, which is how a
// deployment that never heard of scopes keeps working.
//
// The answer comes from the live keyring, so a scope that was narrowed a
// minute ago is already in force.
func (k *Keyring) Allowed(name string, cmd string) bool {
	op, ok := k.Operator(name)
	if !ok {
		return false
	}
	return Permits(op.Role, op.Scopes, cmd)
}

// Permits is the rule itself: what a role with a scope list may call.
//
// It lives here so that there is exactly one implementation of it: the
// server, the tests and the documentation all say the same thing.
func Permits(role string, scopes []string, cmd string) bool {
	if !rbac.Allowed(role, cmd) {
		return false
	}
	if len(scopes) == 0 {
		return true
	}
	return ScopeNames(scopes, cmd)
}

// ScopeNames says whether a scope list names a command.
//
// The wildcard names every command: it is the way to say "the role
// decides" without removing the scopes from the token.
func ScopeNames(scopes []string, cmd string) bool {
	for _, scope := range scopes {
		if scope == "*" || scope == cmd {
			return true
		}
	}
	return false
}

// previousValid reports whether the previous agent PSK still works.
func (k *Keyring) previousValid(now time.Time) bool {
	return len(k.previousAgentPSK) > 0 && k.previousAgentUntil.After(now)
}

// randomToken returns a fresh random token.
func randomToken() ([]byte, error) {
	buf := make([]byte, TokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("keyring: no randomness: %w", err)
	}
	return buf, nil
}

// NewToken returns a fresh token, hex encoded, for the operator to hand
// out.  It is the only place a token is printed.
func NewToken() (string, error) {
	buf, err := randomToken()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// NewTokenBytes returns a fresh token as the bytes the server stores.
//
// The token is the hex text of the random bytes, so the operator can
// type it and the server compares exactly what was typed.
func NewTokenBytes() ([]byte, error) {
	text, err := NewToken()
	if err != nil {
		return nil, err
	}
	return []byte(text), nil
}

// equalSecret compares two secrets in constant time.
func equalSecret(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// sortStrings sorts a slice of strings in place.
func sortStrings(out []string) {
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
}
