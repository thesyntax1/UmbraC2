package hook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/hub"
)

// The wire answers are judged by what the other end received, not by
// what the server hoped to have sent.
type received struct {
	body      []byte
	event     string
	signature string
}

func listener(t *testing.T, calls chan<- received) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls <- received{
			body:      body,
			event:     r.Header.Get("X-Umbra-Event"),
			signature: r.Header.Get("X-Umbra-Signature"),
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func TestTheWireCarriesTheEvent(t *testing.T) {
	calls := make(chan received, 4)
	srv := listener(t, calls)
	defer srv.Close()

	r := New()
	h, err := r.Add(Hook{URL: srv.URL, Kinds: []string{"task.result"}, Secret: "s3cr3t", Creator: "alice"})
	if err != nil {
		t.Fatalf("the wire was refused: %v", err)
	}
	if h.ID != "h-0001" {
		t.Fatalf("the wire was not numbered: %q", h.ID)
	}
	r.Dispatch(hub.Event{Kind: "task.result", AgentID: "web-01", TaskID: "t1", Seq: 7,
		Data: map[string]any{"code": 0}})
	// An event of a kind the wire does not carry stays at home.
	r.Dispatch(hub.Event{Kind: "agent.online", AgentID: "web-01", Seq: 8})

	select {
	case got := <-calls:
		if got.event != "task.result" {
			t.Fatalf("the header named the wrong event: %q", got.event)
		}
		var ev envelope
		if err := json.Unmarshal(got.body, &ev); err != nil {
			t.Fatalf("the body was not the event: %v", err)
		}
		if ev.Seq != 7 || ev.AgentID != "web-01" || ev.TaskID != "t1" {
			t.Fatalf("the event changed on the wire: %+v", ev)
		}
		mac := hmac.New(sha256.New, []byte("s3cr3t"))
		mac.Write(got.body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got.signature != want {
			t.Fatalf("the signature does not match: %q != %q", got.signature, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing was posted down the wire")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		d, ok := r.Last(h.ID)
		if ok {
			if d.Status != http.StatusOK || d.Err != "" {
				t.Fatalf("the delivery was not the answer that came back: %+v", d)
			}
			if d.Kind != "task.result" || d.Seq != 7 {
				t.Fatalf("the book tells of another post: %+v", d)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the book of the deliveries stayed empty")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTheWireKnowsWhatItRefuses(t *testing.T) {
	r := New()
	if _, err := r.Add(Hook{}); err != ErrNoURL {
		t.Fatalf("no address was accepted: %v", err)
	}
	if _, err := r.Add(Hook{URL: "ftp://example.org/x"}); err != ErrBadURL {
		t.Fatalf("a clever scheme was accepted: %v", err)
	}
	if _, err := r.Add(Hook{URL: "http://example.org/x", Kinds: []string{"Task.Result"}}); err == nil {
		t.Fatal("a kind name with a capital was accepted")
	}
	if err := r.Remove("h-0099"); err != ErrNoSuchHook {
		t.Fatalf("an unknown wire was removed: %v", err)
	}
}

func TestTheTestPostIsSignedAndMarked(t *testing.T) {
	calls := make(chan received, 1)
	srv := listener(t, calls)
	defer srv.Close()

	r := New()
	h, err := r.Add(Hook{URL: srv.URL, Secret: "pw", Creator: "alice"})
	if err != nil {
		t.Fatalf("the wire was refused: %v", err)
	}
	d, err := r.Test(h.ID, "alice")
	if err != nil {
		t.Fatalf("the test post failed: %v", err)
	}
	if d.Status != http.StatusOK {
		t.Fatalf("the receiver did not answer: %+v", d)
	}
	select {
	case got := <-calls:
		var ev envelope
		if err := json.Unmarshal(got.body, &ev); err != nil {
			t.Fatalf("the body was not the event: %v", err)
		}
		if !ev.Test || ev.Kind != "hook.test" {
			t.Fatalf("the test post is not marked as one: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("the test post never arrived")
	}
}

func TestTheLedgerSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	r := New()
	r.SetPath(path)
	if _, err := r.Add(Hook{URL: "https://chat.example.org/hook", Secret: "pw"}); err != nil {
		t.Fatalf("the wire was refused: %v", err)
	}
	if err := r.Save(); err != nil {
		t.Fatalf("the ledger could not be saved: %v", err)
	}

	again := New()
	again.SetPath(path)
	if err := again.Load(); err != nil {
		t.Fatalf("the ledger could not be read back: %v", err)
	}
	hooks := again.List()
	if len(hooks) != 1 || hooks[0].Secret != "pw" || hooks[0].ID != "h-0001" {
		t.Fatalf("the ledger forgot the wire: %+v", hooks)
	}
}
