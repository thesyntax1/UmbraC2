package hub_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

func newHub(t *testing.T) *hub.Hub {
	t.Helper()
	cfg := config.Default()
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return hub.New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func agent(id string) *store.Agent {
	return &store.Agent{ID: id, Host: "host-" + id, OS: "linux", Arch: "x86_64"}
}

// A beacon that reconnects keeps the same agent id. The old session's cleanup
// must not delete the new session's live entry, or the agent shows offline
// while it is still beaconing.
func TestUnregisterSessionOnlyDropsItsOwnSession(t *testing.T) {
	h := newHub(t)

	oldSession := []byte("0123456789abcdef")
	newSession := []byte("fedcba9876543210")

	if _, _, err := h.RegisterAgent(agent("a1"), "tcp", "127.0.0.1:1000", 1, oldSession); err != nil {
		t.Fatalf("register old: %v", err)
	}
	if _, _, err := h.RegisterAgent(agent("a1"), "tcp", "127.0.0.1:2000", 1, newSession); err != nil {
		t.Fatalf("register new: %v", err)
	}

	// The stale goroutine finishes and cleans up after its own session.
	h.UnregisterSession("a1", "deadbeefdeadbeefdeadbeefdeadbeef") // unrelated session
	if _, ok := h.Live("a1"); !ok {
		t.Fatal("an unrelated session id removed the live agent")
	}
	h.UnregisterSession("a1", hexOf(oldSession))
	if _, ok := h.Live("a1"); !ok {
		t.Fatal("the superseded session removed the live agent")
	}

	live, ok := h.Live("a1")
	if !ok {
		t.Fatal("agent not live")
	}
	if live.Addr != "127.0.0.1:2000" {
		t.Fatalf("live entry is the old session: %+v", live)
	}

	// The current session's cleanup does remove it, and marks it offline.
	h.UnregisterSession("a1", hexOf(newSession))
	if _, ok := h.Live("a1"); ok {
		t.Fatal("matching session did not unregister the agent")
	}
	rec, ok := h.Store().Agent("a1")
	if !ok {
		t.Fatal("agent record disappeared")
	}
	if rec.State != store.StateOffline {
		t.Fatalf("agent state is %q, want offline", rec.State)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

func TestForceUnregisterDropsAnySession(t *testing.T) {
	h := newHub(t)
	if _, _, err := h.RegisterAgent(agent("a2"), "http", "10.0.0.9", 1, []byte("aaaabbbbccccdddd")); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Expiry does not know which session to look for, so it forces.
	h.UnregisterAgent("a2")
	if _, ok := h.Live("a2"); ok {
		t.Fatal("force unregister left the agent live")
	}
}

func TestOperatorsAreListedWithTheirBacklog(t *testing.T) {
	h := newHub(t)
	bob := h.Subscribe("bob", "10.0.0.7:1", "tcp/operator")
	alice := h.Subscribe("alice", "10.0.0.5:2", "tcp/operator")
	defer h.Unsubscribe(bob.ID)
	defer h.Unsubscribe(alice.ID)

	// Queue one event; every subscriber receives it.
	h.Emit(hub.Event{Kind: "task.queued", AgentID: "a1"})

	ops := h.Operators()
	if len(ops) != 2 {
		t.Fatalf("expected two operators, got %d", len(ops))
	}
	if ops[0].Name != "alice" || ops[1].Name != "bob" {
		t.Fatalf("operators are not sorted by name: %v", ops)
	}
	if ops[0].Peer == "" || ops[0].Transport != "tcp/operator" {
		t.Fatalf("operator identity lost: %+v", ops[0])
	}
	if ops[0].Backlog != 1 {
		t.Fatalf("backlog not reported: %d", ops[0].Backlog)
	}
}

// A console that stops reading must not stall the server, and the drop must be
// visible in stats rather than silently swallowed.
func TestDroppedEventsAreCounted(t *testing.T) {
	h := newHub(t)
	op := h.Subscribe("slow", "10.0.0.8:1", "tcp/operator")
	defer h.Unsubscribe(op.ID)

	// The channel holds 256 events; push well past that without reading.
	for i := 0; i < 400; i++ {
		h.Emit(hub.Event{Kind: "task.result", AgentID: "a1"})
	}
	stats := h.Stats()
	dropped, ok := stats["events_dropped"].(uint64)
	if !ok {
		t.Fatalf("events_dropped missing from stats: %v", stats)
	}
	if dropped == 0 {
		t.Fatal("no drops counted although the subscriber never read")
	}
	if want := uint64(400 - cap(op.Events)); dropped < want {
		t.Fatalf("dropped %d events, expected at least %d", dropped, want)
	}
	if pending := len(op.Events); pending != cap(op.Events) {
		t.Fatalf("queue holds %d events, expected it to be full (%d)", pending, cap(op.Events))
	}
}
