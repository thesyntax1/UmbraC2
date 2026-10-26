package link

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// probeStream records the nonce counter of every frame it is handed and flags
// any two writers that are inside WriteFrame at the same time.
type probeStream struct {
	mu      sync.Mutex
	inside  int
	overlap bool
	order   []uint64
	hold    time.Duration
}

func (p *probeStream) ReadFrame() ([]byte, error) { return nil, io.EOF }

func (p *probeStream) WriteFrame(frame []byte) error {
	p.mu.Lock()
	p.inside++
	if p.inside > 1 {
		p.overlap = true
	}
	p.mu.Unlock()

	time.Sleep(p.hold)

	p.mu.Lock()
	p.order = append(p.order, nonceOf(frame))
	p.inside--
	p.mu.Unlock()
	return nil
}

func nonceOf(frame []byte) uint64 {
	var n uint64
	for _, b := range frame[wire.PreludeLen : wire.PreludeLen+wire.NonceLen][4:] {
		n = n<<8 | uint64(b)
	}
	return n
}

// TestSenderSerialisesSealAndWrite pins the ordering invariant: a sender with
// two concurrent writers must never let two WriteFrame calls overlap and must
// emit strictly increasing counters, because the peer drops the link on the
// first out-of-order nonce.
func TestSenderSerialisesSealAndWrite(t *testing.T) {
	sess, err := session.NewBootstrap(key32(0x21), wire.SuiteAES256GCM, false)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	stream := &probeStream{hold: 2 * time.Millisecond}
	send := NewSender(sess, stream)

	const perWriter = 20
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				if err := send.Send(wire.MsgOpEvent, map[string]any{"n": j}); err != nil {
					t.Errorf("send: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if stream.overlap {
		t.Fatal("two writers were inside WriteFrame at once")
	}
	if len(stream.order) != 2*perWriter {
		t.Fatalf("wrote %d frames, want %d", len(stream.order), 2*perWriter)
	}
	for i, got := range stream.order {
		if got != uint64(i) {
			t.Fatalf("frame %d carried counter %d: frames left out of nonce order", i, got)
		}
	}
}

func TestSenderPropagatesSealErrors(t *testing.T) {
	sess, err := session.NewBootstrap(key32(0x22), wire.SuiteAES256GCM, false)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	stream := &probeStream{}
	send := NewSender(sess, stream)

	// An unencodable body must fail before anything reaches the wire.
	if err := send.Send(wire.MsgOpResponse, map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("expected an encode error")
	}
	if len(stream.order) != 0 {
		t.Fatalf("wrote %d frames after a failed seal, want 0", len(stream.order))
	}
}

func key32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
