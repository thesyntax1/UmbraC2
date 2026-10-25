package link

import (
	"bytes"
	"net"
	"sync"

	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// FrameStream abstracts a transport that can carry whole frames. Both the TCP
// and the HTTP transports implement it, which is why their message handling is
// byte-for-byte identical.
type FrameStream interface {
	ReadFrame() ([]byte, error)
	WriteFrame(frame []byte) error
}

// connStream wraps a net.Conn. Writes are serialised so a heartbeat or an
// operator event can never interleave with a response frame.
type connStream struct {
	conn net.Conn
	mu   sync.Mutex
}

// NewConnStream wraps a connection.
func NewConnStream(c net.Conn) FrameStream { return &connStream{conn: c} }

func (s *connStream) ReadFrame() ([]byte, error) { return wire.ReadFrame(s.conn) }

func (s *connStream) WriteFrame(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.Write(frame)
	return err
}

// httpStream carries frames inside one HTTP request/response pair: the request
// body is the inbound frame, the response body is the outbound frame(s).
type httpStream struct {
	in  *bytes.Reader
	out bytes.Buffer
}

// NewHTTPStream wraps a request body that holds exactly one frame.
func NewHTTPStream(body []byte) (*httpStream, *bytes.Buffer) {
	in := bytes.NewReader(body)
	s := &httpStream{in: in}
	return s, &s.out
}

func (s *httpStream) ReadFrame() ([]byte, error) { return wire.ReadFrame(s.in) }

func (s *httpStream) WriteFrame(frame []byte) error {
	_, err := s.out.Write(frame)
	return err
}
