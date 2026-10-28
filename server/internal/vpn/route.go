package vpn

// The routing table and the ping of the tunnel.
//
// The tunnel is a layer-3 network, so a peer may be the gateway of a
// whole network behind it: the server routes the packets of that network
// to the peer, and the peer forwards them.  The operator sets the routes
// by hand, because only the operator knows what lies behind an agent.
//
// The ping travels through the tunnel like a data packet: the question
// and the answer are sealed with the keys of the session, so only the
// peer can read the question, and only the server can tell that the
// answer is the answer.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// ErrNoAnswer is returned when a peer did not answer the ping.
var ErrNoAnswer = errors.New("vpn: the peer did not answer the ping")

// The kinds of the payload of a control packet.
const (
	pingKind byte = 1
	pongKind byte = 2
	// ControlLen is the length of the payload of a control packet: the
	// kind, the nonce and the timestamp of the question.
	ControlLen = 1 + 8 + 8
)

// Route is a network that lies behind one peer.
type Route struct {
	Peer    string `json:"peer"`
	Network string `json:"network"`
	Bytes   int64  `json:"bytes"`
	Packets int64  `json:"packets"`

	// base and mask are the network in the form the routing uses.
	base uint32
	mask uint32
}

// SetRoute sends the traffic of a network to a peer.
//
// The network is a CIDR in the IPv4 form.  A route replaces the one of
// the same network, so the operator can move a network from one peer to
// another without cleaning up first.
func (s *Server) SetRoute(peerID, cidr string) (Route, error) {
	base, mask, err := parseNetwork(cidr)
	if err != nil {
		return Route{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.peers[peerID]; !ok {
		return Route{}, ErrNoSuchPeer
	}
	for i := range s.routes {
		if s.routes[i].base == base && s.routes[i].mask == mask {
			s.routes[i].Peer = peerID
			s.routes[i].Bytes = 0
			s.routes[i].Packets = 0
			return *s.routes[i], nil
		}
	}
	route := Route{Peer: peerID, Network: cidr, base: base, mask: mask}
	s.routes = append(s.routes, &route)
	s.log.Info("vpn route added", "peer", peerID, "network", cidr)
	return route, nil
}

// RemoveRoute forgets a network.
func (s *Server) RemoveRoute(cidr string) bool {
	base, mask, err := parseNetwork(cidr)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.routes {
		if s.routes[i].base == base && s.routes[i].mask == mask {
			s.routes = append(s.routes[:i], s.routes[i+1:]...)
			return true
		}
	}
	return false
}

// Routes returns the routing table.
func (s *Server) Routes() []Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Route, 0, len(s.routes))
	for _, r := range s.routes {
		out = append(out, *r)
	}
	return out
}

// routePeer finds the peer that owns the destination.
//
// The longest prefix wins, so a small network inside a large one is
// reached the way the operator meant it.  The caller holds the lock.
func (s *Server) routePeer(dst uint32) (*Peer, *Route) {
	var best *Route
	for _, r := range s.routes {
		if dst&r.mask != r.base {
			continue
		}
		if best == nil || r.mask > best.mask {
			best = r
		}
	}
	if best == nil {
		return nil, nil
	}
	return s.peers[best.Peer], best
}

// Ping asks a peer whether it is there and how far away it is.
//
// The question travels through the tunnel and comes back through it, so
// the answer says more than the bookkeeping of the server: the packet
// really made the round trip.
func (s *Server) Ping(peerID string, timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	s.mu.Lock()
	peer := s.peers[peerID]
	s.mu.Unlock()
	if peer == nil {
		return 0, ErrNoSuchPeer
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	payload := make([]byte, 0, ControlLen)
	payload = append(payload, pingKind)
	payload = append(payload, nonce...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(now.UnixNano()))
	payload = append(payload, ts[:]...)
	if err := s.sendControl(peer, TypePing, payload); err != nil {
		return 0, err
	}
	deadline := now.Add(timeout)
	for {
		select {
		case rtt := <-peer.pongs:
			return rtt, nil
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return 0, ErrNoAnswer
		}
	}
}

// sendControl sends a control packet to a peer.
//
// The packet is sealed like a data packet, so the peer can be sure that
// the question comes from the server and the server can be sure that the
// answer comes from the peer.
func (s *Server) sendControl(peer *Peer, kind byte, payload []byte) error {
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
	header[0] = kind
	binary.BigEndian.PutUint64(header[1:9], counter)
	nonce := make([]byte, NonceLen)
	copy(nonce[:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], counter)
	sealed, err := crypt.Seal(wire.SuiteAES256GCM, key, nonce, header, payload)
	if err != nil {
		return err
	}
	out := append(header, sealed...)
	if peer.Endpoint == nil || s.conn == nil {
		return ErrNotEstablished
	}
	_, err = s.conn.WriteToUDP(out, peer.Endpoint)
	return err
}

// handlePong takes the answer of a peer.
func (s *Server) handlePong(pkt []byte, addr *net.UDPAddr) {
	if len(pkt) < HeaderLen+TagLen {
		return
	}
	peer := s.peerByEndpoint(addr)
	if peer == nil {
		return
	}
	peer.mu.Lock()
	if !peer.established {
		peer.mu.Unlock()
		return
	}
	header := pkt[:HeaderLen]
	counter := binary.BigEndian.Uint64(header[1:9])
	key := peer.recvKey
	prefix := peer.recvPrefix
	peer.mu.Unlock()

	nonce := make([]byte, NonceLen)
	copy(nonce[:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], counter)
	plain, err := crypt.Open(wire.SuiteAES256GCM, key, nonce, header, pkt[HeaderLen:])
	if err != nil {
		return
	}
	if len(plain) < ControlLen || plain[0] != pongKind {
		return
	}
	sent := int64(binary.BigEndian.Uint64(plain[9:17]))
	rtt := time.Since(time.Unix(0, sent))
	select {
	case peer.pongs <- rtt:
	default:
	}
}

// peerByEndpoint finds the peer that sits behind an address.
func (s *Server) peerByEndpoint(addr *net.UDPAddr) *Peer {
	if addr == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.peers {
		if p.Endpoint != nil && p.Endpoint.String() == addr.String() {
			return p
		}
	}
	return nil
}
