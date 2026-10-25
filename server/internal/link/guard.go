package link

import (
	"sync"
	"time"
)

// guard is a tiny per-source-address brute-force damper. It keeps memory
// bounded by capping the number of tracked addresses and evicting the oldest.
type guard struct {
	mu       sync.Mutex
	entries  map[string]*guardEntry
	max      int
	failures int
	banFor   time.Duration
}

type guardEntry struct {
	failures int
	bannedAt time.Time
	lastSeen time.Time
	banned   bool
}

func newGuard(max int, banFor time.Duration) *guard {
	return &guard{entries: make(map[string]*guardEntry), max: max, banFor: banFor}
}

// Allow reports whether a connection from addr may proceed.
func (g *guard) Allow(addr string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[addr]
	if !ok {
		return true
	}
	if e.banned {
		if time.Since(e.bannedAt) < g.banFor {
			return false
		}
		e.banned = false
		e.failures = 0
	}
	return true
}

// Fail records a failed handshake and bans the source after 5 failures.
func (g *guard) Fail(addr string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.entries[addr]
	if !ok {
		if len(g.entries) >= g.max {
			g.evictLocked()
		}
		e = &guardEntry{}
		g.entries[addr] = e
	}
	e.failures++
	e.lastSeen = time.Now()
	if e.failures >= 5 {
		e.banned = true
		e.bannedAt = time.Now()
	}
}

// Succeed clears the failure counter for addr.
func (g *guard) Succeed(addr string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entries, addr)
}

func (g *guard) evictLocked() {
	var oldest string
	var oldestAt time.Time
	for k, e := range g.entries {
		if oldest == "" || e.lastSeen.Before(oldestAt) {
			oldest, oldestAt = k, e.lastSeen
		}
	}
	if oldest != "" {
		delete(g.entries, oldest)
	}
}
