package approval

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newQueue builds a queue with a short expiry, so the tests do not sleep.
func newQueue(t *testing.T, ttl time.Duration) *Queue {
	t.Helper()
	q := New()
	q.SetTTL(ttl)
	return q
}

// The rule the package exists for: the operator who asked cannot decide.
//
// It is checked here rather than only in the documentation because it is
// the whole of the two-person rule: a decision that the requester can make
// alone is a request that runs.
func TestTheRequesterCannotDecide(t *testing.T) {
	q := newQueue(t, time.Hour)
	req, err := q.Request(Request{Kind: "wipe.run", AgentID: "web-01", RequestedBy: "alice"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if req.State != StatePending {
		t.Fatalf("a fresh request is %q", req.State)
	}

	got, err := q.Decide(req.ID, "alice", true, "approved by myself")
	if !errors.Is(err, ErrOwnRequest) {
		t.Fatalf("the requester decided their own request: %v", err)
	}
	if got.State != StatePending {
		t.Fatalf("the refused decision changed the state to %q", got.State)
	}
	if got.DecidedBy != "" || !got.DecidedAt.IsZero() {
		t.Fatalf("the refused decision was recorded: %+v", got)
	}

	// A second operator can, and the record says who, when and why.
	done, err := q.Decide(req.ID, "bob", true, "the customer agreed")
	if err != nil {
		t.Fatalf("the second operator could not decide: %v", err)
	}
	if done.State != StateApproved || done.DecidedBy != "bob" || done.Note != "the customer agreed" {
		t.Fatalf("the decision was not recorded: %+v", done)
	}
	if done.DecidedAt.IsZero() {
		t.Fatal("the decision has no moment")
	}

	// And it stays decided: a second decision, by anybody, is refused.
	if _, err := q.Decide(req.ID, "carol", false, "too late"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("a decided request was decided again: %v", err)
	}
}

// A request nobody decides goes stale, and a stale request decides nothing.
func TestARequestThatNobodyDecidesGoesStale(t *testing.T) {
	q := newQueue(t, 20*time.Millisecond)
	req, err := q.Request(Request{Kind: "decommission", RequestedBy: "alice"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	time.Sleep(40 * time.Millisecond)

	got, err := q.Decide(req.ID, "bob", true, "late")
	if !errors.Is(err, ErrNotPending) {
		t.Fatalf("a stale request was decided: %v", err)
	}
	if got.State != StateExpired {
		t.Fatalf("a stale request is %q, want %q", got.State, StateExpired)
	}
	if got.Note == "" {
		t.Fatal("a stale request does not say why it decided nothing")
	}
	// The sweep says how many it buried, and doing it twice buries nothing.
	if n := q.Expire(); n != 0 {
		t.Fatalf("the sweep buried %d requests that were already stale", n)
	}
}

// The queue is shared by the team and survives a restart: the request one
// operator wrote is the one the other operator decides, after a reboot too.
func TestTheQueueSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approval.json")
	q := New()
	q.SetPath(path)
	q.SetTTL(time.Hour)

	req, err := q.Request(Request{
		Kind: "wipe.run", AgentID: "web-01", Reason: "the engagement is over",
		Args: map[string]any{"keep": "audit.log"}, RequestedBy: "alice",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := q.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	again := New()
	again.SetPath(path)
	again.SetTTL(time.Hour)
	if err := again.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	loaded, ok := again.Get(req.ID)
	if !ok {
		t.Fatalf("the request did not survive: %v", again.List(""))
	}
	if loaded.RequestedBy != "alice" || loaded.Kind != "wipe.run" || loaded.Args["keep"] != "audit.log" {
		t.Fatalf("the request lost something: %+v", loaded)
	}
	if !loaded.ExpiresAt.Equal(req.ExpiresAt) {
		t.Fatalf("the expiry moved: %v != %v", loaded.ExpiresAt, req.ExpiresAt)
	}

	// The decision is written down too: a restart after the decision must
	// not offer the operation again.
	if _, err := again.Decide(req.ID, "bob", true, "agreed"); err != nil {
		t.Fatalf("decide after a restart: %v", err)
	}
	if err := again.Save(); err != nil {
		t.Fatalf("save the decision: %v", err)
	}
	third := New()
	third.SetPath(path)
	if err := third.Load(); err != nil {
		t.Fatalf("load the decision: %v", err)
	}
	decided, ok := third.Get(req.ID)
	if !ok || decided.State != StateApproved || decided.DecidedBy != "bob" {
		t.Fatalf("the decision did not survive: %+v", decided)
	}
}

// A request needs the operation and the name of the person who asks for it,
// and it refuses arguments it cannot carry.
func TestARequestThatSaysNothingIsRefused(t *testing.T) {
	q := newQueue(t, time.Hour)
	cases := []struct {
		name string
		req  Request
		want error
	}{
		{"no kind", Request{RequestedBy: "alice"}, ErrNoKind},
		{"no operator", Request{Kind: "wipe.run"}, ErrNoOperator},
		{"blank kind", Request{Kind: "   ", RequestedBy: "alice"}, ErrNoKind},
		{"blank operator", Request{Kind: "wipe.run", RequestedBy: " "}, ErrNoOperator},
	}
	for _, tc := range cases {
		if _, err := q.Request(tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := q.Request(Request{
		Kind: "wipe.run", RequestedBy: "alice", Reason: string(make([]byte, MaxNoteLen+1)),
	}); err == nil {
		t.Error("an oversized reason was accepted")
	}
	if _, err := q.Decide("a-9999", "bob", true, ""); !errors.Is(err, ErrNoSuchRequest) {
		t.Errorf("an unknown request was decided: %v", err)
	}
	if _, err := q.Decide("a-9999", "", true, ""); !errors.Is(err, ErrNoOperator) {
		t.Errorf("a decision without a decider was accepted: %v", err)
	}
}

// The list the team reads is what is waiting, and the queue is bounded so a
// discouraged operator cannot fill the disk with requests.
func TestTheListAndTheBound(t *testing.T) {
	q := newQueue(t, time.Hour)
	first, err := q.Request(Request{Kind: "wipe.run", RequestedBy: "alice"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := q.Decide(first.ID, "bob", false, "no"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	pending, err := q.Request(Request{Kind: "decommission", RequestedBy: "alice"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if list := q.List(StatePending); len(list) != 1 || list[0].ID != pending.ID {
		t.Fatalf("the pending list is %+v", list)
	}
	if all := q.List(""); len(all) != 2 {
		t.Fatalf("the full list has %d entries, want 2", len(all))
	}

	// The bound counts the requests that are still waiting, not the ones
	// that were decided.
	room := MaxRequests - len(q.List(StatePending))
	for i := 0; i < room; i++ {
		if _, err := q.Request(Request{Kind: "wipe.run", RequestedBy: "alice"}); err != nil {
			t.Fatalf("request %d of %d: %v", i, room, err)
		}
	}
	if _, err := q.Request(Request{Kind: "wipe.run", RequestedBy: "alice"}); err == nil {
		t.Fatalf("the queue accepted more than %d open requests", MaxRequests)
	}
}

// The arguments of a request are copied in and out: a caller that changes
// its map after the request was written cannot change what the decision runs.
func TestTheArgumentsOfARequestAreCopied(t *testing.T) {
	q := newQueue(t, time.Hour)
	args := map[string]any{"path": "/srv/app"}
	req, err := q.Request(Request{Kind: "wipe.run", RequestedBy: "alice", Args: args})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	args["path"] = "/"
	got, ok := q.Get(req.ID)
	if !ok {
		t.Fatal("the request is gone")
	}
	if got.Args["path"] != "/srv/app" {
		t.Fatalf("the request followed the caller's map: %v", got.Args["path"])
	}
	got.Args["path"] = "tampered"
	again, _ := q.Get(req.ID)
	if again.Args["path"] != "/srv/app" {
		t.Fatal("the queue handed out its own map")
	}
}

// A queue that cannot write says so; a queue with no path is a queue that
// lives in memory and does not pretend to be durable.
func TestTheFileIsWrittenOrTheErrorIsReturned(t *testing.T) {
	q := New()
	if err := q.Save(); err != nil {
		t.Fatalf("a queue with no path must not fail: %v", err)
	}
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("blocker: %v", err)
	}
	q.SetPath(filepath.Join(blocker, "approval.json"))
	if _, err := q.Request(Request{Kind: "wipe.run", RequestedBy: "alice"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := q.Save(); err == nil {
		t.Fatal("a queue that cannot be written reported success")
	}
}
