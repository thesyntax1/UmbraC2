package beacon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/implant/go/internal/wire"
)

// The key of the tests: it has to be long enough for the server to
// accept it.
var testKey = []byte("umbra-go-implant-test-key")

// newTestBeacon builds a beacon for the tests.
func newTestBeacon(t *testing.T) *Beacon {
	t.Helper()
	impl, err := New(Config{Server: "127.0.0.1:1", PSK: testKey, ID: "test-agent"})
	if err != nil {
		t.Fatalf("the beacon: %v", err)
	}
	return impl
}

func TestTheCapabilityListMatchesTheTaskTable(t *testing.T) {
	impl := newTestBeacon(t)
	advertised := map[string]bool{}
	for _, item := range Capabilities() {
		kind, ok := item.(string)
		if !ok {
			t.Fatalf("a capability is not a string")
		}
		advertised[kind] = true
	}
	if len(advertised) == 0 {
		t.Fatalf("the implant advertises nothing")
	}
	for kind := range advertised {
		outcome := impl.runTask(kind, map[string]any{})
		if strings.Contains(outcome.Err, errUnknownKind.Error()) {
			t.Fatalf("the kind %q is advertised but the implant does not know it", kind)
		}
	}
	// A kind that is not advertised is refused with the error that says
	// so, and not with a panic.
	outcome := impl.runTask("not-a-kind", map[string]any{})
	if !strings.Contains(outcome.Err, errUnknownKind.Error()) {
		t.Fatalf("an unknown kind answered %q", outcome.Err)
	}
}

func TestTheFileTasksWork(t *testing.T) {
	impl := newTestBeacon(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "note.txt")

	outcome := impl.runTask("upload", map[string]any{"path": path, "data": []byte("hello umbra")})
	if outcome.Code != 0 {
		t.Fatalf("the upload failed: %s", outcome.Err)
	}
	outcome = impl.runTask("cat", map[string]any{"path": path})
	if string(outcome.Out) != "hello umbra" {
		t.Fatalf("the cat read %q", string(outcome.Out))
	}
	digest := sha256.Sum256([]byte("hello umbra"))
	outcome = impl.runTask("hash", map[string]any{"path": path})
	if !strings.Contains(string(outcome.Out), hex.EncodeToString(digest[:])) {
		t.Fatalf("the hash is %q", string(outcome.Out))
	}
	outcome = impl.runTask("ls", map[string]any{"path": dir})
	if !strings.Contains(string(outcome.Out), "note.txt") {
		t.Fatalf("the listing is %q", string(outcome.Out))
	}
	outcome = impl.runTask("tail", map[string]any{"path": path, "lines": uint64(5)})
	if !strings.Contains(string(outcome.Out), "hello umbra") {
		t.Fatalf("the tail is %q", string(outcome.Out))
	}
	outcome = impl.runTask("find", map[string]any{"path": dir, "pattern": "*.txt"})
	if !strings.Contains(string(outcome.Out), "note.txt") {
		t.Fatalf("the find is %q", string(outcome.Out))
	}
}

func TestTheHostTasksWork(t *testing.T) {
	impl := newTestBeacon(t)
	outcome := impl.runTask("sysinfo", map[string]any{})
	if outcome.Code != 0 {
		t.Fatalf("the sysinfo failed: %s", outcome.Err)
	}
	for _, key := range []string{"\"os\"", "\"arch\"", "\"pid\""} {
		if !strings.Contains(string(outcome.Out), key) {
			t.Fatalf("the inventory has no %s: %s", key, string(outcome.Out))
		}
	}
	outcome = impl.runTask("pwd", map[string]any{})
	if outcome.Code != 0 || len(outcome.Out) == 0 {
		t.Fatalf("the pwd failed: %s", outcome.Err)
	}
	outcome = impl.runTask("env", map[string]any{})
	if outcome.Code != 0 {
		t.Fatalf("the env failed: %s", outcome.Err)
	}
	outcome = impl.runTask("netinfo", map[string]any{})
	if outcome.Code != 0 {
		t.Fatalf("the netinfo failed: %s", outcome.Err)
	}
	outcome = impl.runTask("ps", map[string]any{})
	if outcome.Code != 0 {
		t.Fatalf("the ps failed: %s", outcome.Err)
	}
}

func TestTheSleepTaskChangesTheCadence(t *testing.T) {
	impl := newTestBeacon(t)
	outcome := impl.runTask("sleep", map[string]any{"seconds": uint64(120)})
	if outcome.Code != 0 {
		t.Fatalf("the sleep failed: %s", outcome.Err)
	}
	if impl.cfg.Sleep != 120*time.Second {
		t.Fatalf("the interval is %s", impl.cfg.Sleep)
	}
}

func TestTheExitTaskStopsTheImplant(t *testing.T) {
	impl := newTestBeacon(t)
	outcome := impl.runTask("exit", map[string]any{"reason": "the operator said so"})
	if outcome.Code != 0 {
		t.Fatalf("the exit failed: %s", outcome.Err)
	}
	if !impl.stop {
		t.Fatalf("the implant did not stop")
	}
}

func TestTheCycleRunsTheTaskAndReportsIt(t *testing.T) {
	view, err := selfTestCycle(testKey, wire.SuiteAES256GCM)
	if err != nil {
		t.Fatalf("the cycle: %v", err)
	}
	if view.result == nil {
		t.Fatalf("the built-in server received no result")
	}
	if code := i64Or(view.result, "code", -1); code != 0 {
		t.Fatalf("the task failed with the code %d", code)
	}
	if id := strField(view.result, "id"); id != "t-1" {
		t.Fatalf("the result carries the id %q", id)
	}
	if !strings.Contains(string(binField(view.result, "out")), "pong") {
		t.Fatalf("the result carries %q", string(binField(view.result, "out")))
	}
	if view.heartbeat == nil {
		t.Fatalf("the built-in server received no heartbeat")
	}
	if iver := strField(view.heartbeat, "iver"); iver != Version {
		t.Fatalf("the heartbeat carries the version %q", iver)
	}
}

func TestTheHelloCarriesTheCapabilities(t *testing.T) {
	view, err := selfTestCycle(testKey, wire.SuiteAES256GCM)
	if err != nil {
		t.Fatalf("the cycle: %v", err)
	}
	caps := arrField(view.hello, "caps")
	if len(caps) == 0 {
		t.Fatalf("the hello carries no capability")
	}
	advertised := map[string]bool{}
	for _, item := range caps {
		kind, ok := item.(string)
		if !ok {
			t.Fatalf("a capability is not a string")
		}
		advertised[kind] = true
	}
	for _, kind := range Capabilities() {
		if !advertised[kind.(string)] {
			t.Fatalf("the hello does not carry the capability %q", kind)
		}
	}
	if strField(view.hello, "iver") != Version {
		t.Fatalf("the hello carries the wrong implant version")
	}
}

func TestTheHandshakeRefusesTheWrongKey(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		_, _ = serveOnce(listener, testKey, wire.SuiteAES256GCM)
	}()
	impl, err := New(Config{
		Server:  listener.Addr().String(),
		PSK:     []byte("a-completely-different-key"),
		ID:      "test-agent",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("the beacon: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := impl.cycle(ctx); err == nil {
		t.Fatalf("the cycle should have failed with the wrong key")
	}
}

func TestTheSelfTestPasses(t *testing.T) {
	if err := SelfTest(); err != nil {
		t.Fatalf("the self test: %v", err)
	}
}

func TestTheIntervalStaysInTheWindow(t *testing.T) {
	impl, err := New(Config{Server: "127.0.0.1:1", PSK: testKey, Sleep: 60 * time.Second, JitterPct: 20})
	if err != nil {
		t.Fatalf("the beacon: %v", err)
	}
	for i := 0; i < 200; i++ {
		got := impl.nextInterval()
		if got < 48*time.Second || got > 72*time.Second {
			t.Fatalf("the interval %s is outside the window", got)
		}
	}
}

func TestTheBackoffGrowsAndIsCapped(t *testing.T) {
	impl, err := New(Config{Server: "127.0.0.1:1", PSK: testKey, Sleep: 10 * time.Second})
	if err != nil {
		t.Fatalf("the beacon: %v", err)
	}
	impl.failures = 1
	if got := impl.backoff(); got != 20*time.Second {
		t.Fatalf("the backoff is %s", got)
	}
	impl.failures = 9
	if got := impl.backoff(); got > 5*time.Minute {
		t.Fatalf("the backoff is %s", got)
	}
}

func TestTheInventoryNamesTheHost(t *testing.T) {
	inventory := Inventory()
	if _, ok := inventory["os"]; !ok {
		t.Fatalf("the inventory has no operating system")
	}
	if _, ok := inventory["arch"]; !ok {
		t.Fatalf("the inventory has no architecture")
	}
	if _, ok := inventory["pid"]; !ok {
		t.Fatalf("the inventory has no process id")
	}
	host, err := os.Hostname()
	if err == nil && host != "" {
		if inventory["host"] != host {
			t.Fatalf("the inventory names the host %v", inventory["host"])
		}
	}
}
