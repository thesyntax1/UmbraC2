package link

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
)

func TestHTTPPathNormalisation(t *testing.T) {
	cases := map[string]string{
		"":                   "/api/v1/beacon",
		"/":                  "/api/v1/beacon",
		"/api/v1/beacon":     "/api/v1/beacon",
		"/api/v1/beacon/":    "/api/v1/beacon",
		"api/v1/beacon":      "/api/v1/beacon",
		"/beacon/v1":         "/beacon/v1",
		"/custom/poll/path/": "/custom/poll/path",
	}
	for configured, want := range cases {
		cfg := config.Default()
		cfg.Server.HTTPPath = configured
		s := &Server{Cfg: cfg}
		if got := s.httpPath(); got != want {
			t.Errorf("httpPath(%q) = %q, want %q", configured, got, want)
		}
	}
}

// The mux and the frame handler must agree on the prefix, otherwise the session
// route (/api/v1/beacon/<sid>) can never match when http_path is customised.
func TestHTTPRoutesMatchSessionIDs(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPPath = "/custom/beacon/"
	s := &Server{Cfg: cfg}

	path := s.httpPath()
	request := httptest.NewRequest(http.MethodPost, path+"/0123456789abcdef0123456789abcdef", nil)
	sid := "0123456789abcdef0123456789abcdef"
	if got := trimSessionID(request.URL.Path, path); got != sid {
		t.Fatalf("session id extracted as %q, want %q", got, sid)
	}
}

func TestClientIPTrustsForwardedForOnlyFromLoopback(t *testing.T) {
	proxied := httptest.NewRequest(http.MethodPost, "/api/v1/beacon", nil)
	proxied.RemoteAddr = "127.0.0.1:51234"
	proxied.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := clientIP(proxied); got != "203.0.113.9" {
		t.Errorf("proxied request: got %q, want 203.0.113.9", got)
	}

	// A direct client must not be able to spoof its identity (rate limiting).
	direct := httptest.NewRequest(http.MethodPost, "/api/v1/beacon", nil)
	direct.RemoteAddr = "198.51.100.7:4444"
	direct.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := clientIP(direct); got != "198.51.100.7" {
		t.Errorf("direct request: got %q, want 198.51.100.7", got)
	}

	garbage := httptest.NewRequest(http.MethodPost, "/api/v1/beacon", nil)
	garbage.RemoteAddr = "127.0.0.1:1000"
	garbage.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := clientIP(garbage); got != "127.0.0.1" {
		t.Errorf("unparsable header: got %q, want 127.0.0.1", got)
	}
}
