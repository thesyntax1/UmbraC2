package link

import (
	"sync"
	"time"
)

// tokenBucket is a minimal per-identity rate limiter.
//
// Operators are trusted, but "trusted" is not "incapable of a bug": a looping
// script calling agents.list on a 5000-agent engagement can pin the server and
// starve beacons. The bucket costs one mutex and two numbers, and the failure
// mode is a clear error rather than a wedged server.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// operatorRPCBurst is how many calls an operator may make back-to-back.
const operatorRPCBurst = 120

// operatorRPCPerSec is the sustained RPC rate per operator.
const operatorRPCPerSec = 40.0

// Allow consumes one token and reports whether the call may proceed.
func (b *tokenBucket) Allow(now time.Time, rate, burst float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens = burst
		b.last = now
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// allowOperatorRPC applies the per-operator budget. The key is the operator
// identity, not the connection, so reconnecting does not reset the budget.
func (s *Server) allowOperatorRPC(name string) bool {
	bucket := s.bucketFor(name)
	return bucket.Allow(time.Now(), operatorRPCPerSec, operatorRPCBurst)
}

func (s *Server) bucketFor(name string) *tokenBucket {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	b, ok := s.opRate[name]
	if !ok {
		b = &tokenBucket{}
		s.opRate[name] = b
	}
	return b
}

// forgetOperatorRate drops an idle operator's bucket. Called when the operator
// disconnects so the map cannot grow without bound; a reconnect starts fresh,
// which is acceptable because a human reconnecting is not a flood.
func (s *Server) forgetOperatorRate(name string) {
	s.opMu.Lock()
	delete(s.opRate, name)
	s.opMu.Unlock()
}
