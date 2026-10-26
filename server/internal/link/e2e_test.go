package link_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/link"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

var (
	agentPSK = []byte("agent-psk-0123456789abcdef0123")
	opToken  = []byte("operator-token-0123456789ab")
)

func newTestServer(t *testing.T) (*link.Server, *hub.Hub, string, string) {
	t.Helper()
	cfg := config.Default()
	cfg.Server.AgentListen = "127.0.0.1:0"
	cfg.Server.OperatorListen = "127.0.0.1:0"
	cfg.Server.HTTPListen = ""
	cfg.Server.DataFile = ""
	cfg.Server.Limits.HandshakeTimeoutSec = 5
	cfg.Server.Limits.IdleTimeoutSec = 10
	cfg.Keyring = config.Keyring{
		AgentPSK:  agentPSK,
		Operators: map[string][]byte{"op1": opToken},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	h := hub.New(cfg, st, logger)
	srv := link.New(cfg, h, logger)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	})
	addrs := srv.Addresses()
	if len(addrs) != 2 {
		t.Fatalf("expected two listeners, got %v", addrs)
	}
	return srv, h, addrs[0], addrs[1]
}

// client is a minimal protocol client used to exercise the server.
type client struct {
	conn   net.Conn
	stream link.FrameStream
	sess   *session.Session
	sid    []byte
}

func dial(t *testing.T, addr string, psk []byte, role byte, id string) *client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	stream := link.NewConnStream(conn)

	suite := wire.SuiteAES256GCM
	kp, err := crypt.NewX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	cn, err := crypt.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	ts := uint64(time.Now().Unix())
	auth, err := crypt.HelloAuth(psk, role, []byte(id), kp.Pub, cn, ts, suite)
	if err != nil {
		t.Fatal(err)
	}
	hello := upk.Map{
		"v": uint64(1), "role": role, "id": id, "pub": kp.Pub, "cn": cn,
		"ts": ts, "suite": suite, "auth": auth,
		"meta": upk.Map{"host": "testhost", "os": "linux", "arch": "x86_64", "user": "tester", "pid": int64(4242), "ver": "0.1.0"},
	}
	body, err := upk.Encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := session.NewBootstrap(psk, suite, false)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := boot.Encrypt(wire.MsgHello, append([]byte{wire.MarkerHello}, body...))
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.WriteFrame(frame); err != nil {
		t.Fatal(err)
	}
	raw, err := stream.ReadFrame()
	if err != nil {
		t.Fatalf("read HELLO_ACK: %v", err)
	}
	msgType, plain, err := boot.OpenFrame(raw)
	if err != nil {
		t.Fatalf("open HELLO_ACK: %v", err)
	}
	if msgType != wire.MsgHelloAck {
		t.Fatalf("expected HELLO_ACK, got %s", wire.TypeName(msgType))
	}
	v, err := upk.DecodeExact(plain[1:])
	if err != nil {
		t.Fatalf("decode HELLO_ACK: %v", err)
	}
	ack, ok := v.(map[string]any)
	if !ok {
		t.Fatal("HELLO_ACK body is not a map")
	}
	serverPub, _ := ack["pub"].([]byte)
	sn, _ := ack["sn"].([]byte)
	sid, _ := ack["sid"].([]byte)
	gotAuth, _ := ack["auth"].([]byte)
	wantAuth, err := crypt.AckAuth(psk, []byte(id), kp.Pub, serverPub, cn, sn, sid, suite)
	if err != nil {
		t.Fatal(err)
	}
	if !crypt.ConstantTimeEq(wantAuth, gotAuth) {
		t.Fatal("server ack failed authentication")
	}
	shared, err := kp.Shared(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	prk, km, err := crypt.DeriveSession(shared, cn, sn)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.New(suite, km, false, false, prk)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &client{conn: conn, stream: stream, sess: sess, sid: sid}
}

func (c *client) send(t *testing.T, msgType byte, body upk.Map) {
	t.Helper()
	frame, err := c.sess.Encrypt(msgType, body)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := c.stream.WriteFrame(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func (c *client) recv(t *testing.T) (byte, map[string]any) {
	t.Helper()
	raw, err := c.stream.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	msgType, msg, err := c.sess.OpenMessage(raw)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return msgType, msg
}

// An agent can report a frame-level failure with ERROR (0x1F) without ending
// the session; operators must see it as a hub event.
func TestAgentErrorIsSurfacedToOperators(t *testing.T) {
	_, h, agentAddr, _ := newTestServer(t)

	op := h.Subscribe("watcher", "127.0.0.1:0", "tcp/operator")
	defer h.Unsubscribe(op.ID)

	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-err-1")

	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'x'
	}
	ag.send(t, wire.MsgError, upk.Map{"code": int64(7), "msg": string(long)})

	// The session must survive: the very next check-in is still answered.
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	msgType, _ := ag.recv(t)
	if msgType != wire.MsgTaskBatch {
		t.Fatalf("expected TASK_BATCH after ERROR, got %s", wire.TypeName(msgType))
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev, ok := <-op.Events:
			if !ok {
				t.Fatal("event stream closed")
			}
			if ev.Kind != "beacon.error" {
				continue
			}
			if ev.AgentID != "agent-err-1" {
				t.Fatalf("wrong agent on event: %q", ev.AgentID)
			}
			if got, _ := ev.Data["code"].(int64); got != 7 {
				t.Fatalf("code not preserved: %v", ev.Data["code"])
			}
			text, _ := ev.Data["msg"].(string)
			if len(text) != 512 {
				t.Fatalf("expected the message to be clipped to 512 bytes, got %d", len(text))
			}
			return
		case <-deadline:
			t.Fatal("no beacon.error event reached the operator")
		}
	}
}

func TestAgentBeaconAndTaskFlow(t *testing.T) {
	_, h, agentAddr, _ := newTestServer(t)

	ag := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-e2e-1")

	// 1. First check-in: no work queued yet.
	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	msgType, batch := ag.recv(t)
	if msgType != wire.MsgTaskBatch {
		t.Fatalf("expected TASK_BATCH, got %s", wire.TypeName(msgType))
	}
	tasks, _ := batch["tasks"].([]any)
	if len(tasks) != 0 {
		t.Fatalf("expected empty task batch, got %d", len(tasks))
	}

	// 2. Queue work as if an operator had submitted it.
	task, err := h.SubmitTask("agent-e2e-1", "shell", map[string]any{"cmd": "id"})
	if err != nil {
		t.Fatalf("submit task: %v", err)
	}

	ag.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	_, batch = ag.recv(t)
	tasks, _ = batch["tasks"].([]any)
	if len(tasks) != 1 {
		t.Fatalf("expected one task, got %d", len(tasks))
	}
	first, _ := tasks[0].(map[string]any)
	if first["id"] != task.ID {
		t.Fatalf("task id mismatch: %v", first["id"])
	}
	if first["kind"] != "shell" {
		t.Fatalf("task kind mismatch: %v", first["kind"])
	}

	// 3. Report the result.
	ag.send(t, wire.MsgResult, upk.Map{"id": task.ID, "code": int64(0), "out": []byte("uid=0(root)\n")})
	ag.send(t, wire.MsgBye, upk.Map{})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, ok := h.Store().Task(task.ID)
		if ok && got.State == store.TaskDone {
			if string(got.Output) != "uid=0(root)\n" {
				t.Fatalf("unexpected output %q", got.Output)
			}
			rec, _ := h.Store().Agent("agent-e2e-1")
			if rec == nil || rec.OS != "linux" || rec.PID != 4242 {
				t.Fatalf("agent metadata not stored: %+v", rec)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("task was never completed")
}

func TestOperatorRPC(t *testing.T) {
	_, _, _, opAddr := newTestServer(t)

	op := dial(t, opAddr, opToken, crypt.RoleOperator, "op1")

	// An operator cannot use the agent key and vice versa; role check happens
	// in the handshake, so this dial succeeds for the right identity.
	op.send(t, wire.MsgOpRequest, upk.Map{
		"rid": uint64(1), "cmd": "server.stats", "args": upk.Map{},
	})
	msgType, resp := op.recv(t)
	if msgType != wire.MsgOpResponse {
		t.Fatalf("expected OP_RESPONSE, got %s", wire.TypeName(msgType))
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("server.stats failed: %v", resp["err"])
	}
	data, _ := resp["data"].(map[string]any)
	if data["protocol"] != "umbra/v1" {
		t.Fatalf("unexpected stats: %v", data)
	}

	op.send(t, wire.MsgOpRequest, upk.Map{
		"rid": uint64(2), "cmd": "agents.list", "args": upk.Map{},
	})
	_, resp = op.recv(t)
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("agents.list failed: %v", resp["err"])
	}

	// Unknown command must be reported, not fatal.
	op.send(t, wire.MsgOpRequest, upk.Map{
		"rid": uint64(3), "cmd": "does.not.exist", "args": upk.Map{},
	})
	_, resp = op.recv(t)
	if ok, _ := resp["ok"].(bool); ok {
		t.Fatal("unknown command reported success")
	}
	if _, ok := resp["err"].(string); !ok {
		t.Fatal("unknown command did not report an error string")
	}
}

func TestHandshakeRejectsWrongKey(t *testing.T) {
	_, _, agentAddr, _ := newTestServer(t)
	conn, err := net.DialTimeout("tcp", agentAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send garbage that looks like a frame with a bad tag.
	bad := make([]byte, wire.HeaderLen+32)
	bad[0], bad[1] = wire.Magic[0], wire.Magic[1]
	bad[2] = wire.Version
	bad[3] = wire.FlagBootstrap
	bad[4] = wire.MsgHello
	bad[5] = wire.SuiteAES256GCM
	bad[11] = 32
	if _, err := conn.Write(bad); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("server answered a forged handshake")
	}

	// The guard should not ban a single failure yet, so a valid client works.
	good := dial(t, agentAddr, agentPSK, crypt.RoleAgent, "agent-after-failure")
	good.send(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	if _, batch := good.recv(t); batch == nil {
		t.Fatal("valid client rejected after one bad handshake")
	}
}
