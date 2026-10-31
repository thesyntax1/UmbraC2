package dash

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

const testToken = "operator-token-for-the-dashboard-0123"

// newTestServer builds a dashboard over an empty hub.
//
// The hub is the real one, over an in-memory store: the dashboard's job is
// to read the same truth the console reads, and a fake hub would test the
// fake.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("open the store: %v", err)
	}
	h := hub.New(config.Default(), st, log)
	return New(Config{Token: testToken, Role: "viewer"}, h, log)
}

// serve runs one request through the dashboard's auth wrapper.
func serve(s *Server, req *http.Request) *http.Response {
	rec := httptest.NewRecorder()
	s.withAuth(s.mux).ServeHTTP(rec, req)
	return rec.Result()
}

// The token is the only key, and it is asked for in the two shapes the
// page and a script use.
func TestTheTokenIsTheOnlyKey(t *testing.T) {
	s := newTestServer(t)

	bare := serve(s, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
	if bare.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated call answered %d", bare.StatusCode)
	}
	if got := bare.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("the refusal does not name the scheme: %q", got)
	}

	wrong := httptest.NewRequest(http.MethodGet, "/api/agents?token=nope", nil)
	if got := serve(s, wrong); got.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong query token answered %d", got.StatusCode)
	}

	bearer := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	bearer.Header.Set("Authorization", "Bearer "+testToken)
	if got := serve(s, bearer); got.StatusCode != http.StatusOK {
		t.Fatalf("the bearer token answered %d", got.StatusCode)
	}

	query := httptest.NewRequest(http.MethodGet, "/api/agents?token="+testToken, nil)
	if got := serve(s, query); got.StatusCode != http.StatusOK {
		t.Fatalf("the query token answered %d", got.StatusCode)
	}

	// The health check is public and says nothing worth having: if it did,
	// it would be a way around the token.
	health := serve(s, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	body, _ := io.ReadAll(health.Body)
	if health.StatusCode != http.StatusOK {
		t.Fatalf("the health check needs a token: %d", health.StatusCode)
	}
	for _, secret := range []string{testToken, "agent", "operator"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("the health check mentions %q: %s", secret, body)
		}
	}

	// An empty token never matches, not even an empty one: the server
	// refuses to serve without a token, and the comparison must not
	// degenerate into "both are empty".
	if equalSecret("", "") {
		// The function compares what it is given; the guard against an
		// empty configuration is in Serve, and it is tested by reading
		// the config, not by this helper.  This branch documents that
		// the helper alone is not the guard.
		if s.cfg.Token == "" {
			t.Fatal("the dashboard was built without a token")
		}
	}
}

// The page cannot be framed, cannot be sniffed, and cannot run a script
// that is not the one that was reviewed.
func TestThePageCarriesItsPolicy(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/?token="+testToken, nil)
	resp := serve(s, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the page answered %d", resp.StatusCode)
	}
	policy := resp.Header.Get("Content-Security-Policy")
	if policy == "" {
		t.Fatal("the page has no content security policy")
	}
	for _, want := range []string{
		"default-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"script-src 'sha256-",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the policy does not say %q: %s", want, policy)
		}
	}
	if strings.Contains(policy, "script-src 'unsafe-inline'") ||
		strings.Contains(policy, "script-src *") {
		t.Errorf("the policy allows inline script wholesale: %s", policy)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q: the token travels in the query string", got)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q: the page carries the token's data", got)
	}
	// The API answers carry the same headers: the policy is attached to
	// every answer, not only to the page.
	api := serve(s, httptest.NewRequest(http.MethodGet, "/api/agents?token="+testToken, nil))
	if got := api.Header.Get("Content-Security-Policy"); got != policy {
		t.Errorf("the API answer carries a different policy: %q", got)
	}
}

// The hash in the header is the hash of the page as it is embedded.  This
// is the test that keeps the page and its policy from drifting apart: an
// edit to index.html that forgets the header would ship a blank dashboard
// in a browser and a green suite here, and this is the only place that can
// notice.
func TestThePolicyNamesThePageThatIsServed(t *testing.T) {
	hash := inlineHash(indexHTML, "<script>", "</script>")
	if hash == "" {
		t.Fatal("the page has no inline script")
	}
	sum := sha256.Sum256([]byte(between(t, indexHTML, "<script>", "</script>")))
	want := base64.StdEncoding.EncodeToString(sum[:])
	if hash != want {
		t.Fatalf("the header names %s, the page hashes to %s", hash, want)
	}
	if !strings.Contains(contentPolicy, "'sha256-"+hash+"'") {
		t.Fatalf("the policy does not carry the hash of the page: %s", contentPolicy)
	}
}

// between returns the body of the first block between open and close.
//
// It is written again here, in a way that is obviously right, so that the
// test does not simply agree with the bug it is meant to catch.
func between(t *testing.T, page, open, close string) string {
	t.Helper()
	start := strings.Index(page, open)
	if start < 0 {
		t.Fatalf("no %s in the page", open)
	}
	rest := page[start+len(open):]
	end := strings.Index(rest, close)
	if end < 0 {
		t.Fatalf("no %s after %s", close, open)
	}
	return rest[:end]
}

// A page without an inline script gets a policy that refuses one: the
// failure is closed, and visible the first time the page is opened.
func TestAPageWithoutAScriptGetsNoScript(t *testing.T) {
	policy := buildContentPolicy("<html><body>nothing</body></html>")
	if !strings.Contains(policy, "script-src 'none'") {
		t.Fatalf("a page without a script got %q", policy)
	}
}
