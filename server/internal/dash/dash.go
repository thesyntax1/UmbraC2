// Package dash serves the operator's web dashboard.
//
// The console is the tool of the day, but a dashboard is what a team leaves
// open on a second screen: the inventory, the running tasks and the event
// stream, without a terminal in the way.  It talks to the same hub the
// console does, so there is only one truth.
//
// The dashboard is deliberately small: it shows what is there and it queues
// a task.  Everything else (the pivots, the team chat, the extension
// store) stays in the console, where the answers are reviewed before they
// are given.
//
// It never listens on a public address by accident: the address and the
// token are configuration, the token is the same one the console uses, and
// the server refuses to start the dashboard without one.
package dash

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/hub"
)

// Config is what the dashboard needs to run.
type Config struct {
	// Listen is the address the dashboard binds to.
	Listen string
	// Token is the operator token the dashboard accepts.  It is compared
	// in constant time and it is never written to a log.
	Token string
	// ReadOnly refuses the endpoints that change something.
	ReadOnly bool
	// Topology returns the picture of the reach: the agents, the pivots
	// between them and the clients of the proxy.  It is nil when the
	// server has no pivot manager, and the panel stays empty then.
	Topology func() any
}

// indexHTML is the page of the dashboard.
//
//go:embed index.html
var indexHTML string

// Server is the dashboard.
type Server struct {
	cfg Config
	hub *hub.Hub
	log *slog.Logger
	mux *http.ServeMux
}

// New creates the dashboard.
func New(cfg Config, h *hub.Hub, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, hub: h, log: log, mux: http.NewServeMux()}
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/api/agents", s.handleAgents)
	s.mux.HandleFunc("/api/tasks", s.handleTasks)
	s.mux.HandleFunc("/api/events", s.handleEvents)
	s.mux.HandleFunc("/api/stats", s.handleStats)
	s.mux.HandleFunc("/api/task", s.handleSubmit)
	s.mux.HandleFunc("/api/pivot", s.handlePivot)
	return s
}

// Serve runs the dashboard until the context is done.
func (s *Server) Serve(ctx context.Context) error {
	if s.cfg.Listen == "" {
		return nil
	}
	if s.cfg.Token == "" {
		return errors.New("dash: the dashboard needs a token")
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("dash: %w", err)
	}
	srv := &http.Server{
		Handler:           s.withAuth(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	s.log.Info("the dashboard is listening", "addr", ln.Addr().String(), "read_only", s.cfg.ReadOnly)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// withAuth checks the token on every request.
//
// The token may come as a bearer header or as the "token" query
// parameter, which is what the page uses when it is opened from a
// bookmark.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := ""
		if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
			got = strings.TrimPrefix(header, "Bearer ")
		} else if r.URL != nil {
			got = r.URL.Query().Get("token")
		}
		if got == "" || !equalSecret(got, s.cfg.Token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="umbra"`)
			http.Error(w, "the dashboard needs the operator token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// equalSecret compares two secrets in constant time.
func equalSecret(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// handleIndex serves the page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(indexHTML))
}

// handleAgents serves the inventory.
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	agents := s.hub.Agents()
	writeJSON(w, http.StatusOK, map[string]any{
		"agents": agents,
		"count":  len(agents),
	})
}

// handleTasks serves the task history.
func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	kind := q.Get("kind")
	state := q.Get("state")
	tasks := s.hub.Store().FilteredTasks(q.Get("agent"), kind, state, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"tasks": tasks,
		"count": len(tasks),
	})
}

// handleEvents serves the journal.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, _ := strconv.ParseUint(q.Get("after"), 10, 64)
	limit := 100
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	events := s.hub.Journal(after, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
	})
}

// handleStats serves the counters of the server.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.hub.Stats())
}

// handlePivot serves the picture of the reach.
//
// The dashboard draws the pivots: which agent is tunnelled through which,
// what moved through it and when it moved the last time.
func (s *Server) handlePivot(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Topology == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"nodes": []any{}, "edges": []any{}, "clients": []any{},
			"connections": []any{}, "claims": map[string]any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.Topology())
}

// handleSubmit queues a task.
//
// The dashboard may be read-only, and then this endpoint refuses: a
// dashboard on a screen somebody walks past should not be able to run
// anything.
func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ReadOnly {
		http.Error(w, "the dashboard is read-only", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is allowed here", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID   string         `json:"id"`
		Kind string         `json:"kind"`
		Args map[string]any `json:"args"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "the request body is not valid JSON", http.StatusBadRequest)
		return
	}
	if body.ID == "" || body.Kind == "" {
		http.Error(w, "the request needs an agent and a kind", http.StatusBadRequest)
		return
	}
	if body.Args == nil {
		body.Args = map[string]any{}
	}
	task, err := s.hub.SubmitTask(body.ID, body.Kind, body.Args)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id": task.ID,
		"agent_id": task.AgentID,
		"kind":     task.Kind,
	})
}

// writeJSON writes an answer as JSON.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(body)
}
