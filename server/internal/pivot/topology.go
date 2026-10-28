package pivot

import (
	"errors"
	"net"
	"strings"
	"time"
)

// The accounting of the proxy.
//
// A pivot is a door into a network, so the server keeps three things about
// it: who used it, where they went and when they were there.  The operator
// reads that before they read anything else, because it is the difference
// between "the proxy is open" and "the proxy is open and it is in use".

// MaxConnections is how many connections the log keeps.  The log is a
// ring: the oldest entry falls off when a new one arrives.
const MaxConnections = 256

// clientAccount is what one client of the SOCKS5 proxy has done.
type clientAccount struct {
	Address     string    `json:"address"`
	Connections int64     `json:"connections"`
	BytesUp     int64     `json:"bytes_up"`
	BytesDown   int64     `json:"bytes_down"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
}

// connectionRecord is one connection of the proxy.
type connectionRecord struct {
	Client    string    `json:"client"`
	Target    string    `json:"target"`
	Port      int       `json:"port"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	At        time.Time `json:"at"`
	State     string    `json:"state"`
}

// denyRule is one entry of the list the proxy refuses.
type denyRule struct {
	host string
	port int
}

// DenyRule is the operator-visible form of a denied target.
type DenyRule struct {
	// Host is the name or the address of the target.
	Host string `json:"host"`
	// Port is the port of the target; zero matches every port.
	Port int `json:"port"`
}

// denied reports whether a target is on the list.
//
// A rule with a port of zero matches every port of the host.  A rule with
// a port matches that port only.  The host is compared in lower case, and
// a rule that names an address is also compared against the address the
// name resolves to, so a rule for "10.0.0.5" also covers the name that
// points at it.
func (m *Manager) denied(host string, port int) bool {
	if host == "" {
		return false
	}
	m.mu.Lock()
	rules := make([]denyRule, len(m.deny))
	copy(rules, m.deny)
	m.mu.Unlock()
	name := strings.ToLower(host)
	addr := ""
	if ip := net.ParseIP(host); ip == nil {
		if resolved, err := net.LookupIP(host); err == nil && len(resolved) > 0 {
			addr = resolved[0].String()
		}
	} else {
		addr = host
	}
	for _, rule := range rules {
		if rule.port != 0 && rule.port != port {
			continue
		}
		want := strings.ToLower(rule.host)
		if want == name || (addr != "" && want == addr) {
			return true
		}
		// A rule that names a network refuses every address in it.
		if _, network, err := net.ParseCIDR(want); err == nil {
			if ip := net.ParseIP(addr); ip != nil && network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// account books a client of the proxy.
func (m *Manager) account(client string, up, down int64) {
	if client == "" {
		return
	}
	now := time.Now().UTC()
	m.mu.Lock()
	entry, ok := m.clients[client]
	if !ok {
		entry = &clientAccount{Address: client, First: now}
		m.clients[client] = entry
	}
	entry.Connections++
	entry.BytesUp += up
	entry.BytesDown += down
	entry.Last = now
	m.mu.Unlock()
}

// noteConnection writes one line in the connection log.
func (m *Manager) noteConnection(client, target string, port int, up, down int64, state string) {
	record := connectionRecord{
		Client:    client,
		Target:    target,
		Port:      port,
		BytesUp:   up,
		BytesDown: down,
		At:        time.Now().UTC(),
		State:     state,
	}
	m.mu.Lock()
	m.connections = append(m.connections, record)
	if len(m.connections) > MaxConnections {
		m.connections = m.connections[len(m.connections)-MaxConnections:]
	}
	m.mu.Unlock()
	m.account(client, up, down)
}

// dropClaimLocked removes a tunnel from its claim.
//
// The caller holds the lock.
func (m *Manager) dropClaimLocked(tun *tunnel) {
	if tun == nil || tun.claim == "" {
		return
	}
	ids := m.claims[tun.claim]
	out := ids[:0]
	for _, id := range ids {
		if id != tun.id {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		delete(m.claims, tun.claim)
		return
	}
	m.claims[tun.claim] = out
}

// Claims returns the claims of the engagement and the tunnels they hold.
func (m *Manager) Claims() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]string, len(m.claims))
	for name, ids := range m.claims {
		list := make([]string, len(ids))
		copy(list, ids)
		out[name] = list
	}
	return out
}

// Release tears every tunnel of a claim down.
//
// This is the "release the claim" an operator wants at the end of an
// operation: the forwards are gone, the listener is closed and the
// accounting of the claim stays in the log.
func (m *Manager) Release(claim string) ([]string, error) {
	claim = strings.TrimSpace(claim)
	if claim == "" {
		return nil, errEmptyClaim
	}
	m.mu.Lock()
	ids := m.claims[claim]
	tunnels := make([]*tunnel, 0, len(ids))
	for _, id := range ids {
		if tun, ok := m.tunnels[id]; ok {
			tunnels = append(tunnels, tun)
		}
	}
	delete(m.claims, claim)
	m.mu.Unlock()
	closed := make([]string, 0, len(tunnels))
	for _, tun := range tunnels {
		if err := m.Close(tun.id); err != nil {
			continue
		}
		closed = append(closed, tun.id)
	}
	return closed, nil
}

// errEmptyClaim is returned when a release carries no name.
var errEmptyClaim = errors.New("pivot: the release needs the name of a claim")

// TopologyNode is one agent in the graph of the pivots.
type TopologyNode struct {
	// AgentID is the agent the node stands for.
	AgentID string `json:"agent_id"`
	// Role is "pivot" when the agent holds a tunnel and "host" otherwise.
	Role string `json:"role"`
	// Transport is the transport the agent speaks.
	Transport string `json:"transport,omitempty"`
	// Online tells whether the agent answered recently.
	Online bool `json:"online"`
	// Tunnels is how many pivots the agent holds.
	Tunnels int `json:"tunnels"`
}

// TopologyEdge is one pivot in the graph.
type TopologyEdge struct {
	Tunnel      string `json:"tunnel"`
	AgentID     string `json:"agent_id"`
	Through     string `json:"through,omitempty"`
	Mode        string `json:"mode"`
	Listen      string `json:"listen"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Streams     int    `json:"streams"`
	BytesUp     int64  `json:"bytes_up"`
	BytesDown   int64  `json:"bytes_down"`
	LastActive  int64  `json:"last_active"`
	State       string `json:"state"`
	Claim       string `json:"claim,omitempty"`
	DNS         string `json:"dns,omitempty"`
}

// Topology is the whole picture: the agents, the pivots between them, the
// clients of the proxy and the log of the connections.
type Topology struct {
	Nodes       []TopologyNode     `json:"nodes"`
	Edges       []TopologyEdge     `json:"edges"`
	Clients     []clientAccount    `json:"clients"`
	Connections []connectionRecord `json:"connections"`
	Claims      map[string][]string `json:"claims"`
	Sessions    int                `json:"sessions"`
	Tunnels     int                `json:"tunnels"`
}

// Topology returns the graph of the pivots.
//
// The operator asked for the picture of the engagement: which agent is
// tunnelled through which, what moves through it and when it moved the
// last time.  The dashboard draws this, and the console prints it.
func (m *Manager) Topology() Topology {
	m.mu.Lock()
	tunnels := make([]*tunnel, 0, len(m.tunnels))
	for _, tun := range m.tunnels {
		tunnels = append(tunnels, tun)
	}
	clients := make([]clientAccount, 0, len(m.clients))
	for _, entry := range m.clients {
		clients = append(clients, *entry)
	}
	connections := make([]connectionRecord, 0, len(m.connections))
	connections = append(connections, m.connections...)
	claims := make(map[string][]string, len(m.claims))
	for name, ids := range m.claims {
		list := make([]string, len(ids))
		copy(list, ids)
		claims[name] = list
	}
	sessions := len(m.sessions)
	m.mu.Unlock()

	edges := make([]TopologyEdge, 0, len(tunnels))
	perAgent := make(map[string]int)
	for _, tun := range tunnels {
		info := m.info(tun)
		perAgent[info.AgentID]++
		edges = append(edges, TopologyEdge{
			Tunnel:     info.Stream,
			AgentID:    info.AgentID,
			Through:    info.Through,
			Mode:       info.Mode,
			Listen:     info.Listen,
			Host:       info.Host,
			Port:       info.Port,
			Streams:    info.Streams,
			BytesUp:    info.BytesUp,
			BytesDown:  info.BytesDown,
			LastActive: info.LastActivity.Unix(),
			State:      info.State,
			Claim:      info.Claim,
			DNS:        info.DNS,
		})
	}

	nodes := make([]TopologyNode, 0, len(perAgent))
	if m.hub != nil {
		for _, agent := range m.hub.Store().Agents() {
			count := perAgent[agent.ID]
			role := "host"
			if count > 0 {
				role = "pivot"
			}
			nodes = append(nodes, TopologyNode{
				AgentID:   agent.ID,
				Role:      role,
				Transport: agent.Transport,
				Online:    agent.State == "online",
				Tunnels:   count,
			})
		}
	}
	return Topology{
		Nodes:       nodes,
		Edges:       edges,
		Clients:     clients,
		Connections: connections,
		Claims:      claims,
		Sessions:    sessions,
		Tunnels:     len(edges),
	}
}
