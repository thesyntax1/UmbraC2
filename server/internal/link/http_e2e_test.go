package link_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/link"
	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
	"github.com/thesyntax1/UmbraC2/server/internal/session"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// httpAgent is a beacon that speaks the HTTP transport: no socket of its own,
// just POST bodies carrying frames.
type httpAgent struct {
	base string
	sid  string
	sess *session.Session
}

func newHTTPServer(t *testing.T) (*link.Server, *hub.Hub, string) {
	t.Helper()
	cfg := config.Default()
	cfg.Server.AgentListen = ""
	cfg.Server.OperatorListen = ""
	cfg.Server.HTTPListen = "127.0.0.1:0"
	cfg.Server.DataFile = ""
	cfg.Server.Limits.HandshakeTimeoutSec = 5
	cfg.Server.Limits.IdleTimeoutSec = 60
	cfg.Keyring = config.Keyring{
		AgentPSK:  agentPSK,
		Operators: map[string][]byte{"op1": opToken, "viewer1": viewerToken},
		Roles:     map[string]string{"op1": rbac.Admin, "viewer1": rbac.Viewer},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	h := hub.New(cfg, st, logger)
	srv := link.New(cfg, h, logger)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	})
	addrs := srv.Addresses()
	if len(addrs) != 1 {
		t.Fatalf("expected only the HTTP listener, got %v", addrs)
	}
	return srv, h, addrs[0]
}

// post sends one HTTP request whose body is the concatenation of frames and
// returns the response frames.
func (a *httpAgent) post(t *testing.T, url string, frames ...[]byte) ([][]byte, int) {
	t.Helper()
	var body bytes.Buffer
	for _, f := range frames {
		body.Write(f)
	}
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	out, err := wire.SplitFrames(raw)
	if err != nil {
		t.Fatalf("split response frames: %v", err)
	}
	return out, resp.StatusCode
}

// dialHTTP performs the bootstrap POST and returns an authenticated agent.
func dialHTTP(t *testing.T, addr, id string) *httpAgent {
	t.Helper()
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
	auth, err := crypt.HelloAuth(agentPSK, crypt.RoleAgent, []byte(id), kp.Pub, cn, ts, suite)
	if err != nil {
		t.Fatal(err)
	}
	hello := upk.Map{
		"v": uint64(1), "role": crypt.RoleAgent, "id": id, "pub": kp.Pub, "cn": cn,
		"ts": ts, "suite": suite, "auth": auth,
		"meta": upk.Map{"host": "http-host", "os": "linux", "arch": "arm64", "user": "tester", "pid": int64(99), "ver": "0.1.0"},
	}
	body, err := upk.Encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := session.NewBootstrap(agentPSK, suite, false)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := boot.Encrypt(wire.MsgHello, append([]byte{wire.MarkerHello}, body...))
	if err != nil {
		t.Fatal(err)
	}

	agent := &httpAgent{base: "http://" + addr + "/api/v1/beacon"}
	resp, err := http.Post(agent.base, "application/octet-stream", bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("bootstrap post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap rejected: %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	ackFrames, err := wire.SplitFrames(raw)
	if err != nil {
		t.Fatalf("split HELLO_ACK: %v", err)
	}
	if len(ackFrames) != 1 {
		t.Fatalf("expected one HELLO_ACK frame, got %d", len(ackFrames))
	}
	msgType, plain, err := boot.OpenFrame(ackFrames[0])
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
	wantAuth, err := crypt.AckAuth(agentPSK, []byte(id), kp.Pub, serverPub, cn, sn, sid, suite)
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
	agent.sess = sess
	agent.sid = hex.EncodeToString(sid)
	return agent
}

func (a *httpAgent) seal(t *testing.T, msgType byte, body upk.Map) []byte {
	t.Helper()
	frame, err := a.sess.Encrypt(msgType, body)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return frame
}

// A single POST may carry several frames. The beacon reports the results of a
// whole batch in one request and the server must process every frame in order:
// before this was fixed the body was handed to OpenFrame as if it were one
// frame, so the request failed with "bad frame" and the session was dropped.
func TestHTTPBeaconCarriesMultipleFramesPerRequest(t *testing.T) {
	_, h, addr := newHTTPServer(t)
	agent := dialHTTP(t, addr, "agent-http-1")
	if _, ok := h.Live("agent-http-1"); !ok {
		t.Fatal("agent not registered after the HTTP handshake")
	}

	first, err := h.SubmitTask("agent-http-1", "shell", map[string]any{"cmd": "id"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	second, err := h.SubmitTask("agent-http-1", "sysinfo", nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Check-in: the batch arrives in the response body.
	frames, status := agent.post(t, agent.base+"/"+agent.sid,
		agent.seal(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())}))
	if status != http.StatusOK {
		t.Fatalf("check-in status %d", status)
	}
	if len(frames) != 1 {
		t.Fatalf("expected one TASK_BATCH frame, got %d", len(frames))
	}
	msgType, msg, err := agent.sess.OpenMessage(frames[0])
	if err != nil {
		t.Fatalf("open batch: %v", err)
	}
	if msgType != wire.MsgTaskBatch {
		t.Fatalf("expected TASK_BATCH, got %s", wire.TypeName(msgType))
	}
	tasks, _ := msg["tasks"].([]any)
	if len(tasks) != 2 {
		t.Fatalf("expected two tasks in the batch, got %d", len(tasks))
	}

	// Results for both tasks plus the next check-in in ONE body.
	frames, status = agent.post(t, agent.base+"/"+agent.sid,
		agent.seal(t, wire.MsgResult, upk.Map{"id": first.ID, "code": int64(0), "out": []byte("uid=0\n")}),
		agent.seal(t, wire.MsgResult, upk.Map{"id": second.ID, "code": int64(0), "out": []byte("host\n")}),
		agent.seal(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())}),
	)
	if status != http.StatusOK {
		t.Fatalf("result post status %d", status)
	}
	if len(frames) != 1 {
		t.Fatalf("expected one TASK_BATCH reply, got %d frames", len(frames))
	}
	for _, id := range []string{first.ID, second.ID} {
		rec, ok := h.Store().Task(id)
		if !ok {
			t.Fatalf("task %s missing", id)
		}
		if rec.State != store.TaskDone {
			t.Fatalf("task %s state %q, want done (only the first frame was processed?)", id, rec.State)
		}
	}

	// BYE ends the session and the server forgets it.
	if _, status := agent.post(t, agent.base+"/"+agent.sid,
		agent.seal(t, wire.MsgBye, upk.Map{})); status != http.StatusOK {
		t.Fatalf("bye status %d", status)
	}
	if _, ok := h.Live("agent-http-1"); ok {
		t.Error("agent still live after BYE")
	}
	if _, status := agent.post(t, agent.base+"/"+agent.sid,
		agent.seal(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})); status != http.StatusGone {
		t.Errorf("expected 410 after BYE, got %d", status)
	}
}

// A frame that fails to authenticate must drop the session AND mark the agent
// offline; otherwise a dead beacon stays in the live list forever.
func TestHTTPBadFrameUnregistersAgent(t *testing.T) {
	_, h, addr := newHTTPServer(t)
	agent := dialHTTP(t, addr, "agent-http-2")

	good := agent.seal(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
	bad := append([]byte{}, good...)
	bad[len(bad)-1] ^= 0x01 // flip a tag byte

	if _, status := agent.post(t, agent.base+"/"+agent.sid, bad); status != http.StatusBadRequest {
		t.Fatalf("expected 400 for a bad frame, got %d", status)
	}
	if _, ok := h.Live("agent-http-2"); ok {
		t.Error("agent still live after a rejected frame")
	}
}

// An empty body is a client bug, not a reason to hang or to allocate.
// (The size cap is covered by TestReadBeaconBodyEnforcesTheLimit, which can
// check the boundary exactly without pushing 16 MiB through a socket.)
func TestHTTPRejectsEmptyBody(t *testing.T) {
	_, h, addr := newHTTPServer(t)
	agent := dialHTTP(t, addr, "agent-http-3")
	url := agent.base + "/" + agent.sid

	if _, status := agent.post(t, url); status != http.StatusBadRequest {
		t.Errorf("empty body: got %d, want 400", status)
	}
	// A rejected body must not cost the beacon its session: the very next
	// request is still answered.
	frames, status := agent.post(t, url,
		agent.seal(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())}))
	if status != http.StatusOK {
		t.Fatalf("check-in after an empty POST: %d", status)
	}
	if len(frames) != 1 {
		t.Fatalf("expected a TASK_BATCH reply, got %d frames", len(frames))
	}
	if _, ok := h.Live("agent-http-3"); !ok {
		t.Error("session dropped by an empty body")
	}
}

// Keep-alive only works if every reply is length-delimited: a chunked body can
// only be ended by closing the connection, so the beacon would pay for a new
// TCP (and TLS, behind a proxy) handshake on every POST of a cycle. This pins
// both halves: an explicit Content-Length on the wire and a second request that
// reuses the same connection.
func TestHTTPRepliesAreLengthDelimitedAndReusable(t *testing.T) {
	_, _, addr := newHTTPServer(t)
	agent := dialHTTP(t, addr, "agent-keepalive")
	url := agent.base + "/" + agent.sid

	var reused int
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Reused {
				reused++
			}
		},
	}
	client := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}

	for i := 0; i < 2; i++ {
		frame := agent.seal(t, wire.MsgCheckin, upk.Map{"ts": uint64(time.Now().Unix())})
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(frame))
		if err != nil {
			t.Fatal(err)
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		raw, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("post %d: status %d", i, resp.StatusCode)
		}
		if resp.ContentLength < 0 {
			t.Fatalf("post %d: reply had no Content-Length (chunked or close-delimited)", i)
		}
		if len(resp.TransferEncoding) != 0 {
			t.Fatalf("post %d: reply used %v", i, resp.TransferEncoding)
		}
		if resp.ContentLength != int64(len(raw)) {
			t.Fatalf("post %d: Content-Length %d != body %d", i, resp.ContentLength, len(raw))
		}
	}
	if reused == 0 {
		t.Fatal("the second POST opened a new connection instead of reusing the first")
	}
}
