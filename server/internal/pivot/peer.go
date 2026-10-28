package pivot

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// The peer link.
//
// Two beacons speak it with each other, and the team server speaks it when
// a pivot is chained: the server asks the first agent for a stream to the
// next one and then plays the peer on that stream.
//
//	peer hello   a length prefixed upk map
//	peer ack     a length prefixed upk map
//	then the umbra session frames, exactly like the server link
//
// The hello proves that the sender owns the pre-shared key and the key it
// claims; the answer proves the same for the other side and covers both
// hellos, so the transcript cannot be rearranged.

// PeerMaxFrame bounds one handshake message.
const PeerMaxFrame = 4096

// PeerID is the identity the server uses on a peer link.
const PeerID = "umbra-server"

// PeerHello is one half of the peer handshake.
type PeerHello struct {
	ID    string
	Pub   []byte
	Nonce []byte
	MAC   []byte
}

// PeerHelloMAC is the tag of a peer hello.
//
// It binds the identity to the key and the nonce of the sender, so a hello
// cannot be replayed into another link.
func PeerHelloMAC(psk []byte, id string, pub, nonce []byte) []byte {
	msg := make([]byte, 0, 32+len(id)+len(pub)+len(nonce))
	msg = append(msg, []byte("umbra/v1/p2p/hello")...)
	msg = append(msg, id...)
	msg = append(msg, pub...)
	msg = append(msg, nonce...)
	return crypt.HMACSHA256(psk, msg)
}

// PeerAckMAC is the tag of the answer.
//
// It covers both hellos: the transcript cannot be rearranged, and the
// answer cannot be replayed into another link.
func PeerAckMAC(psk []byte, hello, ack PeerHello) []byte {
	msg := make([]byte, 0, 64+len(hello.ID)+len(ack.ID))
	msg = append(msg, []byte("umbra/v1/p2p/ack")...)
	msg = append(msg, hello.ID...)
	msg = append(msg, hello.Pub...)
	msg = append(msg, hello.Nonce...)
	msg = append(msg, ack.ID...)
	msg = append(msg, ack.Pub...)
	msg = append(msg, ack.Nonce...)
	return crypt.HMACSHA256(psk, msg)
}

// peerMap turns a hello into the map that travels on the wire.
func peerMap(h PeerHello) upk.Map {
	return upk.Map{
		"id":    h.ID,
		"pub":   h.Pub,
		"nonce": h.Nonce,
		"mac":   h.MAC,
	}
}

// peerHello reads a hello out of a map.
func peerHello(m upk.Map) (PeerHello, error) {
	h := PeerHello{}
	h.ID, _ = m["id"].(string)
	h.Pub, _ = m["pub"].([]byte)
	h.Nonce, _ = m["nonce"].([]byte)
	h.MAC, _ = m["mac"].([]byte)
	if h.ID == "" || len(h.Pub) != 32 || len(h.Nonce) != 16 || len(h.MAC) != 32 {
		return h, errors.New("pivot: malformed peer hello")
	}
	return h, nil
}

// peerWrite sends one handshake message.
func peerWrite(w io.Writer, m upk.Map) error {
	payload, err := upk.Encode(m)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > PeerMaxFrame {
		return errors.New("pivot: the peer hello has a bad size")
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// peerRead receives one handshake message.
func peerRead(r io.Reader) (upk.Map, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(head[:])
	if size == 0 || size > PeerMaxFrame {
		return nil, errors.New("pivot: the peer hello has a bad size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	value, err := upk.DecodeExact(payload)
	if err != nil {
		return nil, err
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("pivot: the peer hello is not a map")
	}
	return upk.Map(m), nil
}

// peerDial plays the initiator of a peer link over an open byte stream.
//
// The initiator is the one that speaks first.  Both sides derive the same
// session keys: the shared secret of the key exchange is mixed with the
// pre-shared key, so the link is only as good as the key both beacons
// already hold.
func peerDial(rw io.ReadWriter, psk []byte, id string) (*session.Session, error) {
	kp, err := crypt.NewX25519Keypair()
	if err != nil {
		return nil, err
	}
	nonce, err := crypt.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	hello := PeerHello{ID: id, Pub: kp.Pub, Nonce: nonce}
	hello.MAC = PeerHelloMAC(psk, hello.ID, hello.Pub, hello.Nonce)
	if err := peerWrite(rw, peerMap(hello)); err != nil {
		return nil, err
	}
	raw, err := peerRead(rw)
	if err != nil {
		return nil, err
	}
	ack, err := peerHello(raw)
	if err != nil {
		return nil, err
	}
	if !crypt.ConstantTimeEq(PeerAckMAC(psk, hello, ack), ack.MAC) {
		return nil, errors.New("pivot: the peer did not authenticate the transcript")
	}
	shared, err := kp.Shared(ack.Pub)
	if err != nil {
		return nil, err
	}
	mixed := crypt.HMACSHA256(psk, shared)
	prk, km, err := crypt.DeriveSession(mixed, hello.Nonce, ack.Nonce)
	if err != nil {
		return nil, err
	}
	return session.New(wire.SuiteAES256GCM, km, false, false, prk)
}

// peerAccept plays the responder of a peer link over an open byte stream.
//
// A beacon uses it when another beacon (or the server) dials in.
func peerAccept(rw io.ReadWriter, psk []byte, id string) (*session.Session, error) {
	raw, err := peerRead(rw)
	if err != nil {
		return nil, err
	}
	hello, err := peerHello(raw)
	if err != nil {
		return nil, err
	}
	if !crypt.ConstantTimeEq(PeerHelloMAC(psk, hello.ID, hello.Pub, hello.Nonce), hello.MAC) {
		return nil, errors.New("pivot: the peer did not authenticate")
	}
	kp, err := crypt.NewX25519Keypair()
	if err != nil {
		return nil, err
	}
	nonce, err := crypt.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	ack := PeerHello{ID: id, Pub: kp.Pub, Nonce: nonce}
	ack.MAC = PeerAckMAC(psk, hello, ack)
	if err := peerWrite(rw, peerMap(ack)); err != nil {
		return nil, err
	}
	shared, err := kp.Shared(hello.Pub)
	if err != nil {
		return nil, err
	}
	mixed := crypt.HMACSHA256(psk, shared)
	prk, km, err := crypt.DeriveSession(mixed, hello.Nonce, ack.Nonce)
	if err != nil {
		return nil, err
	}
	return session.New(wire.SuiteAES256GCM, km, true, false, prk)
}

// wireStream carries umbra frames over a byte stream.
//
// The pivot package cannot use the link package (that one imports this
// package), so the frame format is read and written here.  It is the same
// format: a twelve byte prelude, the nonce, the body and the tag.
type wireStream struct {
	rw io.ReadWriter
	rd *bufio.Reader

	mu sync.Mutex
}

// newWireStream wraps a byte stream.
func newWireStream(rw io.ReadWriter) *wireStream {
	return &wireStream{rw: rw, rd: bufio.NewReader(rw)}
}

// ReadFrame reads one whole umbra frame.
func (w *wireStream) ReadFrame() ([]byte, error) {
	prelude := make([]byte, wire.PreludeLen)
	if _, err := io.ReadFull(w.rd, prelude); err != nil {
		return nil, err
	}
	if prelude[0] != wire.Magic[0] || prelude[1] != wire.Magic[1] {
		return nil, wire.ErrBadMagic
	}
	length := binary.BigEndian.Uint32(prelude[8:12])
	if length > wire.MaxBody {
		return nil, errors.New("pivot: the frame is too large")
	}
	rest := make([]byte, wire.NonceLen+int(length)+wire.TagLen)
	if _, err := io.ReadFull(w.rd, rest); err != nil {
		return nil, err
	}
	return append(prelude, rest...), nil
}

// WriteFrame writes one whole umbra frame.
func (w *wireStream) WriteFrame(frame []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.rw.Write(frame)
	return err
}

// peerSession is the team server on the far side of a peer link.
//
// The frames are the ones the callback session uses; only the roles are
// swapped: the server asks, the peer opens.
type peerSession struct {
	sess   *session.Session
	stream FrameStream

	writeMu sync.Mutex

	mu        sync.Mutex
	streams   map[string]*peerStream
	done      chan struct{}
	closeOnce sync.Once
}

// newPeerSession starts a peer session over an established link.
func newPeerSession(sess *session.Session, stream FrameStream) *peerSession {
	ps := &peerSession{
		sess:    sess,
		stream:  stream,
		streams: make(map[string]*peerStream),
		done:    make(chan struct{}),
	}
	go ps.readLoop()
	return ps
}

// readLoop owns the peer link.
func (ps *peerSession) readLoop() {
	defer ps.shutdown()
	for {
		raw, err := ps.stream.ReadFrame()
		if err != nil {
			return
		}
		msgType, msg, err := ps.sess.OpenMessage(raw)
		if err != nil {
			return
		}
		switch msgType {
		case wire.MsgTunnelOpen:
			ps.onOpen(msg)
		case wire.MsgTunnelData:
			ps.onData(msg)
		case wire.MsgTunnelClose:
			ps.onClose(msg)
		case wire.MsgRekey:
			ps.onRekey(msg)
		}
	}
}

// onRekey rotates the keys of the peer link.
//
// The seed travels inside the frame, so both ends derive the same keys
// from it and the link keeps running without the server.
func (ps *peerSession) onRekey(msg map[string]any) {
	seed, _ := msg["seed"].([]byte)
	if len(seed) != 32 {
		ps.shutdown()
		return
	}
	if err := ps.sess.ApplyRekey(seed); err != nil {
		ps.shutdown()
	}
}

// send seals and writes one frame in a single critical section.
func (ps *peerSession) send(msgType byte, body any) error {
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()
	frame, err := ps.sess.Encrypt(msgType, body)
	if err != nil {
		return err
	}
	if err := ps.stream.WriteFrame(frame); err != nil {
		return err
	}
	return ps.maybeRekey()
}

// maybeRekey rotates the keys when the link carried enough frames.
//
// The REKEY frame itself is sealed with the old keys, and both ends
// derive the same keys from the seed it carries.
func (ps *peerSession) maybeRekey() error {
	if !ps.sess.NeedsRekey() {
		return nil
	}
	seed := make([]byte, 32)
	if _, err := crypt.RandomBytes(len(seed)); err != nil {
		return err
	}
	frame, err := ps.sess.Encrypt(wire.MsgRekey, upk.Map{"seed": seed})
	if err != nil {
		return err
	}
	if err := ps.stream.WriteFrame(frame); err != nil {
		return err
	}
	return ps.sess.ApplyRekey(seed)
}

func (ps *peerSession) onOpen(msg map[string]any) {
	op, _ := msg["op"].(string)
	id, _ := msg["stream"].(string)
	if op != "result" {
		return
	}
	ok, _ := msg["ok"].(bool)
	text, _ := msg["err"].(string)
	ps.mu.Lock()
	st := ps.streams[id]
	ps.mu.Unlock()
	if st == nil {
		return
	}
	if ok {
		st.result <- nil
		return
	}
	if text == "" {
		text = "the peer refused the stream"
	}
	st.result <- errors.New(text)
}

func (ps *peerSession) onData(msg map[string]any) {
	id, _ := msg["stream"].(string)
	data, _ := msg["data"].([]byte)
	ps.mu.Lock()
	st := ps.streams[id]
	ps.mu.Unlock()
	if st == nil {
		return
	}
	select {
	case st.data <- data:
	case <-st.closed:
	default:
		st.closeWith("pivot: the peer stream buffer overflowed")
	}
}

func (ps *peerSession) onClose(msg map[string]any) {
	id, _ := msg["stream"].(string)
	reason, _ := msg["reason"].(string)
	ps.mu.Lock()
	st := ps.streams[id]
	ps.mu.Unlock()
	if st == nil {
		return
	}
	if reason == "" {
		reason = "the peer closed the stream"
	}
	st.closeWith(reason)
}

// openStream asks the peer to open a connection to host:port.
func (ps *peerSession) openStream(host string, port int) (relayStream, error) {
	id := newID("s")
	st := &peerStream{
		id:     id,
		sess:   ps,
		result: make(chan error, 1),
		data:   make(chan []byte, StreamBuffer),
		closed: make(chan struct{}),
	}
	ps.mu.Lock()
	if len(ps.streams) >= MaxStreamsPerSession {
		ps.mu.Unlock()
		return nil, errors.New("pivot: too many streams on the peer link")
	}
	ps.streams[id] = st
	ps.mu.Unlock()

	body := upk.Map{"stream": id, "op": "open", "host": host, "port": int64(port)}
	if err := ps.send(wire.MsgTunnelOpen, body); err != nil {
		ps.dropStream(id)
		return nil, err
	}
	select {
	case err := <-st.result:
		if err != nil {
			ps.dropStream(id)
			return nil, err
		}
	case <-time.After(StreamTimeout):
		ps.dropStream(id)
		return nil, errors.New("pivot: the peer did not answer the stream request")
	case <-ps.done:
		ps.dropStream(id)
		return nil, errors.New("pivot: the peer link closed")
	}
	return st, nil
}

func (ps *peerSession) dropStream(id string) {
	ps.mu.Lock()
	delete(ps.streams, id)
	ps.mu.Unlock()
}

func (ps *peerSession) shutdown() {
	ps.closeOnce.Do(func() {
		ps.mu.Lock()
		streams := ps.streams
		ps.streams = make(map[string]*peerStream)
		ps.mu.Unlock()
		for _, st := range streams {
			st.closeWith("pivot: the peer link closed")
		}
		close(ps.done)
	})
}

// peerStream is one logical stream inside a peer link.
type peerStream struct {
	id     string
	sess   *peerSession
	result chan error
	data   chan []byte
	closed chan struct{}

	once sync.Once
	mu   sync.Mutex
	// The bytes that were read but did not fit into the buffer of the
	// caller.  The lock of the buffer is its own: a read that waits for
	// the peer must not keep the close of the stream from happening.
	bufMu   sync.Mutex
	pending []byte
	reason  string
}

// Write sends bytes to the peer.
func (st *peerStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	body := upk.Map{"stream": st.id, "data": p}
	if err := st.sess.send(wire.MsgTunnelData, body); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite tells the peer that this side is done sending.
func (st *peerStream) CloseWrite() {
	body := upk.Map{"stream": st.id, "reason": "local side closed"}
	_ = st.sess.send(wire.MsgTunnelClose, body)
}

// Read returns the next bytes from the peer.
//
// The bytes that did not fit into the buffer of the caller are kept for
// the next read: a chunk is never lost.
func (st *peerStream) Read(buf []byte) (int, error) {
	st.bufMu.Lock()
	defer st.bufMu.Unlock()
	for len(st.pending) == 0 {
		select {
		case chunk := <-st.data:
			if len(chunk) == 0 {
				return 0, io.EOF
			}
			st.pending = append(st.pending, chunk...)
		case <-st.closed:
			select {
			case chunk := <-st.data:
				if len(chunk) == 0 {
					return 0, io.EOF
				}
				st.pending = append(st.pending, chunk...)
			default:
				return 0, io.EOF
			}
		}
	}
	n := copy(buf, st.pending)
	st.pending = st.pending[n:]
	return n, nil
}

// Close tears the stream down.
func (st *peerStream) Close() error {
	st.closeWith("closed")
	return nil
}

func (st *peerStream) closeWith(reason string) {
	st.once.Do(func() {
		st.mu.Lock()
		st.reason = reason
		st.mu.Unlock()
		close(st.closed)
		st.sess.dropStream(st.id)
	})
}

// describePeer renders a peer address for the log.
func describePeer(addr string) string {
	if addr == "" {
		return "no address"
	}
	return fmt.Sprintf("peer %s", addr)
}
