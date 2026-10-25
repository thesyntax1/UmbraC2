package link

import (
	"sync"

	"github.com/thesyntax1/UmbraC2/server/internal/session"
)

// Sender serialises *sealing and writing* for one connection.
//
// session.Session reserves nonces atomically, which guarantees a frame never
// reuses a (key, nonce) pair. Uniqueness on its own is not enough: when two
// goroutines seal (counters 5 and 6) and then race to the socket, the peer can
// observe counter 6 before 5. The protocol requires strictly increasing
// counters, so the peer would (correctly) drop the link as a reorder.
//
// Ordering is therefore guaranteed by holding one mutex across seal+write.
// Any connection with more than one potential writer -- a request handler plus
// an event or heartbeat pusher -- must send through a single Sender, and callers
// must not seal frames themselves. Connections with exactly one writer (the
// agent reader loop, the HTTP transport) are safe by construction.
type Sender struct {
	mu     sync.Mutex
	sess   *session.Session
	stream FrameStream
}

// NewSender pairs a session with the stream it writes to.
func NewSender(sess *session.Session, stream FrameStream) *Sender {
	return &Sender{sess: sess, stream: stream}
}

// Send encodes body, seals it and writes the frame in one critical section.
func (s *Sender) Send(msgType byte, body any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	frame, err := s.sess.Encrypt(msgType, body)
	if err != nil {
		return err
	}
	return s.stream.WriteFrame(frame)
}

// SendFrame writes an already sealed frame under the same lock. Use only when
// the frame was sealed by this Sender's caller inside the same logical step.
func (s *Sender) SendFrame(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.stream.WriteFrame(frame)
}
