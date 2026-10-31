package link

import (
	"strings"
	"sync"
	"time"
)

// idemEntry is one remembered submission.
type idemEntry struct {
	TaskID string
	At     time.Time
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
	idemKeyMax = 120
)

// idemLookup returns the task a key already produced, if the promise holds.
//
// The caller passes the key exactly as it arrived; an empty key is never a
// key, because a submission without a key is a submission that asked for a
// new task.
func (s *Server) idemLookup(key string) (string, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", false
	}
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	if s.idem == nil {
		return "", false
	}
	entry, ok := s.idem[key]
	if !ok {
		return "", false
	}
	if time.Since(entry.At) > idemWindow {
		delete(s.idem, key)
		return "", false
	}
	return entry.TaskID, true
}

// idemRemember binds a key to the task it produced.
//
// A second submission with the same key inside the window gets the first
// task back instead of a second task: the operator asked once, and the
// answer is the answer to the one question.
func (s *Server) idemRemember(key, taskID string) {
	key = strings.TrimSpace(key)
	if key == "" || taskID == "" {
		return
	}
	if len(key) > idemKeyMax {
		key = key[:idemKeyMax]
	}
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	if s.idem == nil {
		s.idem = make(map[string]idemEntry, 64)
	}
	s.idem[key] = idemEntry{TaskID: taskID, At: time.Now()}
	if len(s.idem) <= idemMax {
		return
	}
	// Forget the oldest keys first: a flood of keys must not be a way to
	// grow the server, and a key older than the window is already dead.
	var oldestKey string
	var oldest time.Time
	for k, entry := range s.idem {
		if oldestKey == "" || entry.At.Before(oldest) {
			oldestKey, oldest = k, entry.At
		}
	}
	delete(s.idem, oldestKey)
}

// idemKeys is how many live keys the server holds, for the queue reading.
func (s *Server) idemKeys() int {
	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	return len(s.idem)
}
