package link

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// The WebSocket transport.
//
// The umbra protocol is a stream of binary frames, and a WebSocket carries
// exactly that: one umbra frame per binary WebSocket frame, in order.  The
// session state machine above the transport does not change at all -- the
// same AgentLink, the same handshake, the same task queue.
//
// The transport exists because a CDN or a reverse proxy in front of the
// server speaks WebSocket, and because a long-lived connection lets the
// server push a task the moment it is queued instead of waiting for the next
// poll.
//
// Only the part of RFC 6455 that the transport needs is implemented: the
// opening handshake, binary frames, ping/pong and a clean close.  There is
// no extension negotiation, and a fragmented frame is refused instead of
// reassembled -- the umbra frames are small enough to fit into one frame.

// The WebSocket opcodes the transport uses.
const (
	wsOpBinary    = 0x2
	wsOpClose     = 0x8
	wsOpPing      = 0x9
	wsOpPong      = 0xA
	wsVersion     = "13"
	wsGUID        = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsMaxFrame    = wire.MaxFrame + 4096
	wsHandshakeTO = 10 * time.Second
)

// wsAccept computes the Sec-WebSocket-Accept value of a client key.
//
// RFC 6455 defines it as the base64 of the SHA-1 of the key concatenated
// with the protocol GUID.
func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // the protocol demands SHA-1 here
	return base64.StdEncoding.EncodeToString(sum[:])
}

// isWebSocketUpgrade reports whether a request asks for a WebSocket.
func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// wsStream carries umbra frames inside binary WebSocket frames.
type wsStream struct {
	conn net.Conn
	br   *bufio.Reader

	// One writer at a time: the frames have to leave in order.
	wmu sync.Mutex
}

// ReadFrame reads the next umbra frame.
func (s *wsStream) ReadFrame() ([]byte, error) {
	for {
		head := make([]byte, 2)
		if _, err := io.ReadFull(s.br, head); err != nil {
			return nil, err
		}
		fin := head[0]&0x80 != 0
		opcode := head[0] & 0x0F
		masked := head[1]&0x80 != 0
		length := int(head[1] & 0x7F)
		switch length {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(s.br, ext); err != nil {
				return nil, err
			}
			length = int(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(s.br, ext); err != nil {
				return nil, err
			}
			value := binary.BigEndian.Uint64(ext)
			if value > uint64(wsMaxFrame) {
				return nil, errors.New("websocket frame is too large")
			}
			length = int(value)
		}
		if length > wsMaxFrame {
			return nil, errors.New("websocket frame is too large")
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(s.br, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(s.br, payload); err != nil {
				return nil, err
			}
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i&3]
			}
		}
		switch opcode {
		case wsOpClose:
			return nil, errors.New("the peer closed the websocket")
		case wsOpPing:
			if err := s.writeFrame(wsOpPong, payload); err != nil {
				return nil, err
			}
			continue
		case wsOpPong:
			continue
		}
		if !fin {
			return nil, errors.New("fragmented websocket frames are not supported")
		}
		return payload, nil
	}
}

// WriteFrame sends one umbra frame.
func (s *wsStream) WriteFrame(frame []byte) error {
	return s.writeFrame(wsOpBinary, frame)
}

// writeFrame sends one WebSocket frame.
//
// A server frame is never masked, so the mask bit stays clear.
func (s *wsStream) writeFrame(opcode int, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	header := make([]byte, 0, 10)
	header = append(header, 0x80|byte(opcode))
	size := len(payload)
	switch {
	case size < 126:
		header = append(header, byte(size))
	case size < 1<<16:
		header = append(header, 126)
		header = binary.BigEndian.AppendUint16(header, uint16(size))
	default:
		header = append(header, 127)
		header = binary.BigEndian.AppendUint64(header, uint64(size))
	}
	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := s.conn.Write(payload)
	return err
}

// Close ends the connection with a WebSocket close frame.
func (s *wsStream) Close() error {
	_ = s.writeFrame(wsOpClose, []byte{0x03, 0xE8}) // 1000, normal closure
	return s.conn.Close()
}

// handleBeaconWebSocket upgrades a beacon request and serves the session.
//
// The upgrade is done by hand: the standard library has no WebSocket
// support, and the transport only needs four frames of code on top of the
// HTTP hijacker.
func (s *Server) handleBeaconWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	addr := clientIP(r)
	log := s.Log.With("peer", addr, "transport", "ws")
	if !s.guard.Allow(addr) {
		http.Error(w, "too many failures", http.StatusTooManyRequests)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "the connection cannot be upgraded", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hijacker.Hijack()
	if err != nil {
		log.Warn("websocket hijack failed", "err", err)
		return
	}
	// The session owns the connection from here on.
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(wsHandshakeTO)); err != nil {
		_ = conn.Close()
		return
	}
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n" +
		"Sec-WebSocket-Version: " + wsVersion + "\r\n\r\n"
	if _, err := brw.WriteString(response); err != nil {
		_ = conn.Close()
		return
	}
	if err := brw.Flush(); err != nil {
		_ = conn.Close()
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return
	}

	stream := &wsStream{conn: conn, br: brw.Reader}
	sess, info, err := Handshake(stream, s.Cfg, s.Keys, log, addr)
	if err != nil {
		s.guard.Fail(addr)
		log.Warn("handshake failed", "err", err)
		_ = conn.Close()
		return
	}
	if info.Role != crypt.RoleAgent {
		log.Warn("operator key used on the websocket listener", "id", info.ID)
		_ = conn.Close()
		return
	}
	s.guard.Succeed(addr)

	sleep, jitter := s.Cfg.Server.Beacon.Sleep, s.Cfg.Server.Beacon.Jitter
	meta := AgentMeta(info, "ws", addr, sleep, jitter)
	rec, _, err := s.Hub.RegisterAgent(meta, "ws", addr, info.Suite, info.SessionID)
	if err != nil {
		log.Warn("agent registration refused", "err", err)
		_ = conn.Close()
		return
	}
	log.Info("websocket agent registered", "agent", rec.ID, "peer", addr)
	s.runAgent(stream, conn, sess, info, addr, "ws", log)
}
