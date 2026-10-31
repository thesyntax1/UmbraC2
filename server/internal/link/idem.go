package link

import (
	"strings"
	"time"
)

// idemEntry is one remembered submission.
//
// An entry is born as a reservation: the key is claimed before the task is
// queued, so a second console that arrives in the same millisecond waits
// for the answer of the first instead of queueing a second task.  The
// reservation becomes an answer the moment the queue accepts the task.
type idemEntry struct {
	TaskID  string
	At      time.Time
	Pending bool
}

const (
	// idemWindow is how long a key is honoured.
	//
	// Five minutes is the length of a retried click: a console that lost
	// the answer, a wire that timed out, an operator who pressed twice.
	// Longer would turn a key into a cache of the queue, and the queue
	// is already the record.
	idemWindow = 5 * time.Minute
	// idemMax bounds the memory of the keys.
	//
	// A key is a promise, not an archive: past four thousand live keys
	// the oldest is forgotten, so a console that generates keys in a
	// loop cannot grow the server.
	idemMax = 4096
	// idemKeyMax is the longest key the server accepts.
	//
	// The key is never cut.  Two long keys that share a prefix are two
	// different questions, and cutting them would answer one with the
	// other: the handler refuses a key past this length instead.
	idemKeyMax = 120
	// idemWait is how long a duplicate waits for the first submission to
	// finish before it is told that the answer is still coming.
	idemWait = 750 * time.Millisecond
	// idemPoll is how often the waiter looks.
	idemPoll = 10 * time.Millisecond
)

// idemStatus is what a claim of a key found.
type idemStatus int

const (
	// idemOwner: the key was free and this caller now holds it.
	idemOwner idemStatus = iota
	// idemDone: the key already answered; TaskID is the task.
	idemDone
	// idemBusy: the key is held by a submission that has not finished.
	idemBusy
)

// idemNormalize is the one reading of a key the whole server uses.
//
// Trim only: the handler is the gate on length, and a key that was never
// cut is a key that can be looked up with exactly the bytes it arrived
// with.
func idemNormalize(key string) string { return strings.TrimSpace(key) }

// idemClaim takes the key for this submission, or reports what it found.
//
// The claim and the look are one critical section, so two consoles racing
// on the same key cannot both become the owner.  A duplicate that finds a
// live reservation waits a short while for the answer: the common case is
// a retried click on a slow link, and the answer it wants is the task the
// first click made.
func (s *Server) idemClaim(key string) (string, idemStatus) {
	key = idemNormalize(key)
	if key == "" {
		return "", idemOwner
	}
	deadline := time.Now().Add(idemWait)
	for {
		s.idemMu.Lock()
		if s.idem == nil {
			s.idem = make(map[string]idemEntry, 64)
		}
		entry, ok := s.idem[key]
		if !ok {
			s.idem[key] = idemEntry{At: time.Now(), Pending: true}
			s.idemPruneLocked()
			s.idemMu.Unlock()
			return "", idemOwner
		}
		if time.Since(entry.At) > idemWindow {
			// A key past the window is a new question: it is claimed
			// again rather than waited on.
			s.idem[key] = idemEntry{At: time.Now(), Pending: true}
			s.idemMu.Unlock()
			return "", idemOwner
		}
		if !entry.Pending {
			s.idemMu.Unlock()
			return entry.TaskID, idemDone
		}
		s.idemMu.Unlock()
		if time.Now().After(deadline) {
			return "", idemBusy
		}
		time.Sleep(idemPoll)
	}
}

// idemFinish binds a claimed key to the task it produced.
func (s *Server) idemFinish(key, taskID string) {
	key = idemNormalize(key)
	if key == "" {
		return
	}
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	if s.idem == nil {
		s.idem = make(map[string]idemEntry, 64)
	}
	s.idem[key] = idemEntry{TaskID: taskID, At: time.Now()}
	s.idemPruneLocked()
}

// idemAbort gives a claimed key back.
//
// A submission that failed queued nothing, so its key must not answer a
// retry with a task that does not exist.
func (s *Server) idemAbort(key string) {
	key = idemNormalize(key)
	if key == "" {
		return
	}
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	if entry, ok := s.idem[key]; ok && entry.Pending {
		delete(s.idem, key)
	}
}

// idemPruneLocked keeps the memory of the keys bounded.
//
// A pending reservation is never the oldest thing worth keeping: it is
// minutes old at most and it is released by the caller.
func (s *Server) idemPruneLocked() {
	if len(s.idem) <= idemMax {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, entry := range s.idem {
		if oldestKey == "" || entry.At.Before(oldest) {
			oldestKey, oldest = k, entry.At
		}
	}
	if oldestKey != "" {
		delete(s.idem, oldestKey)
	}
}

// idemKeys is how many live keys the server holds, for the queue reading.
func (s *Server) idemKeys() int {
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	return len(s.idem)
}
