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

	"github.com/thesyntax1/UmbraC2/server/internal/config"
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
	// Role is the authorisation level of the dashboard.  The operator
	// commands the dashboard runs are checked against it, exactly like
	// the commands of a console.
	Role string
	// Dispatch runs one operator command on behalf of the dashboard.  It
	// is nil when the server does not expose the operator commands to
	// the dashboard, and the endpoint then refuses.
	Dispatch func(role, cmd string, args map[string]any) (any, error)
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
	s.mux.HandleFunc("/api/persistence", s.handlePersistence)
	s.mux.HandleFunc("/api/credentials", s.handleCredentials)
	s.mux.HandleFunc("/api/workflows", s.handleWorkflows)
	s.mux.HandleFunc("/api/workflow", s.handleWorkflowRun)
	s.mux.HandleFunc("/api/alerts", s.handleAlerts)
	s.mux.HandleFunc("/api/operators", s.handleOperators)
	s.mux.HandleFunc("/api/output", s.handleOutput)
	s.mux.HandleFunc("/api/rpc", s.handleRPC)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/api/queue", s.handleQueue)
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
		// The health check is the one endpoint that needs no token: it
		// says that the process is alive and nothing else.
		if r.URL != nil && r.URL.Path == "/healthz" {
			uptime, _ := s.hub.Stats()["uptime_s"].(int)
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":       true,
				"uptime_s": uptime,
			})
			return
		}
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

// handleQueue serves the state of the queue.
//
// The panel answers the question an operator asks when the work piles up:
// what is the policy, how deep is the queue, which hosts have an open
// breaker and what is waiting in the dead letter queue.
func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	metrics := s.hub.Metrics()
	dead := make([]any, 0, 8)
	for _, task := range s.hub.Store().DeadTasks(50) {
		dead = append(dead, map[string]any{
			"task_id":  task.ID,
			"agent_id": task.AgentID,
			"kind":     task.Kind,
			"attempts": task.Attempts,
			"err":      task.Err,
			"trace_id": task.TraceID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":      s.hub.QueuePolicy(),
		"quiet":       metrics.Quiet,
		"pending":     metrics.TasksPending,
		"done":        metrics.TasksDone,
		"failed":      metrics.TasksFailed,
		"dead":        metrics.TasksDead,
		"breakers":    metrics.BreakersOpen,
		"dead_letter": dead,
	})
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

// handlePersistence serves the persistence of every host.
//
// The panel answers the question an operator asks first: where does this
// thing live, and will it still be there after a reboot?
func (s *Server) handlePersistence(w http.ResponseWriter, r *http.Request) {
	rows := make([]any, 0)
	for _, agent := range s.hub.Store().Agents() {
		entries := make([]any, 0)
		for _, entry := range agent.Persist {
			row := map[string]any{
				"technique": entry.Technique,
				"state":     entry.State,
			}
			if entry.Location != "" {
				row["path"] = entry.Location
			}
			if entry.Detail != "" {
				row["detail"] = entry.Detail
			}
			entries = append(entries, row)
		}
		rows = append(rows, map[string]any{
			"agent_id":  agent.ID,
			"host":      agent.Host,
			"os":        agent.OS,
			"user":      agent.User,
			"persisted": len(agent.Persist) > 0,
			"entries":   entries,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": rows, "count": len(rows)})
}

// handleCredentials serves the vault.
//
// The values are not here: the panel shows the shape of the material, and
// the value is fetched on purpose, with a reason in the audit trail.
func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	records := s.hub.Store().Credentials(q.Get("agent"), q.Get("kind"), q.Get("query"), 200)
	rows := make([]any, 0, len(records))
	for _, record := range records {
		rows = append(rows, map[string]any{
			"id":         record.ID,
			"agent_id":   record.AgentID,
			"source":     record.Source,
			"account":    record.Account,
			"target":     record.Target,
			"kind":       record.Kind,
			"digest":     record.Digest,
			"confidence": record.Confidence,
			"note":       record.Note,
			"collected":  record.Collected.Unix(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": rows, "count": len(rows)})
}

// handleWorkflows serves the catalogue of the named sequences of steps.
func (s *Server) handleWorkflows(w http.ResponseWriter, r *http.Request) {
	workflows := s.hub.Store().Workflows()
	rows := make([]any, 0, len(workflows))
	for _, workflow := range workflows {
		steps := make([]any, 0, len(workflow.Steps))
		for _, step := range workflow.Steps {
			steps = append(steps, map[string]any{
				"kind":      step.Kind,
				"agent":     step.Agent,
				"task_kind": step.TaskKind,
				"title":     step.Title,
				"condition": step.Condition,
				"seconds":   step.Seconds,
			})
		}
		rows = append(rows, map[string]any{
			"name":        workflow.Name,
			"description": workflow.Description,
			"params":      workflow.Params,
			"steps":       steps,
			"runs":        workflow.Runs,
			"created_by":  workflow.CreatedBy,
		})
	}
	runs := s.hub.Store().WorkflowRuns(20)
	runRows := make([]any, 0, len(runs))
	for _, run := range runs {
		runRows = append(runRows, map[string]any{
			"id":       run.ID,
			"workflow": run.Workflow,
			"state":    run.State,
			"current":  run.Current,
			"steps":    len(run.Steps),
			"by":       run.By,
			"started":  run.Started.Unix(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"workflows": rows, "count": len(rows), "runs": runRows,
	})
}

// handleWorkflowRun starts a workflow from the dashboard.
func (s *Server) handleWorkflowRun(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ReadOnly {
		http.Error(w, "the dashboard is read-only", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is allowed here", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name   string            `json:"name"`
		Params map[string]string `json:"params"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "the request body is not valid JSON", http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		http.Error(w, "the request needs a workflow", http.StatusBadRequest)
		return
	}
	run, err := s.hub.RunWorkflow(body.Name, body.Params, "dashboard")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"run_id": run.ID})
}

// handleAlerts serves the alert rules, and lets the dashboard edit them.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := s.hub.AlertRules()
		rows := make([]any, 0, len(rules))
		for _, rule := range rules {
			rows = append(rows, map[string]any{
				"name":         rule.Name,
				"event":        rule.Event,
				"tag":          rule.Tag,
				"agent":        rule.Agent,
				"task_kind":    rule.TaskKind,
				"cooldown_sec": rule.CooldownSec,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": rows, "count": len(rows)})
	case http.MethodPost:
		if s.cfg.ReadOnly {
			http.Error(w, "the dashboard is read-only", http.StatusForbidden)
			return
		}
		var body struct {
			Rules []config.AlertRule `json:"rules"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
		if err := dec.Decode(&body); err != nil {
			http.Error(w, "the request body is not valid JSON", http.StatusBadRequest)
			return
		}
		s.hub.SetAlertRules(body.Rules, "dashboard")
		writeJSON(w, http.StatusOK, map[string]any{
			"rules": body.Rules, "count": len(body.Rules),
		})
	default:
		http.Error(w, "only GET and POST are allowed here", http.StatusMethodNotAllowed)
	}
}

// handleOperators serves the presence of the team.
//
// A console that has been quiet for too long is in the list but is stale:
// the dashboard shows that, so nobody waits for an operator who left.
func (s *Server) handleOperators(w http.ResponseWriter, r *http.Request) {
	rows := s.hub.Operators()
	writeJSON(w, http.StatusOK, map[string]any{"operators": rows, "count": len(rows)})
}

// handleOutput serves the live output of the recent tasks.
//
// The dashboard does not open a websocket per task: the panel polls this
// endpoint and shows the answers as they arrive.
func (s *Server) handleOutput(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	tasks := s.hub.Store().FilteredTasks(q.Get("agent"), "", "", limit)
	rows := make([]any, 0, len(tasks))
	for _, task := range tasks {
		row := map[string]any{
			"task_id":  task.ID,
			"agent_id": task.AgentID,
			"kind":     task.Kind,
			"state":    task.State,
			"code":     task.Code,
		}
		if len(task.Output) > 0 {
			text := string(task.Output)
			if len(text) > 2000 {
				text = text[:2000]
			}
			row["out"] = text
		}
		if task.Err != "" {
			row["err"] = task.Err
		}
		rows = append(rows, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": rows, "count": len(rows)})
}

// handleMetrics serves the counters of the server in the Prometheus text
// format.
//
// The format is the one a scraper expects: one "name value" per line, the
// histogram buckets with their "le" label, and a "# HELP" and a "# TYPE"
// line above each family.  The endpoint needs the operator token like
// every other one: the numbers of an engagement are not public.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := s.hub.Metrics()
	var b strings.Builder

	family := func(name, help, kind string) {
		b.WriteString("# HELP " + name + " " + help + "\n")
		b.WriteString("# TYPE " + name + " " + kind + "\n")
	}
	line := func(name string, value any, labels ...string) {
		b.WriteString(name)
		if len(labels) > 0 {
			b.WriteString("{")
			for i, label := range labels {
				if i > 0 {
					b.WriteString(",")
				}
				b.WriteString(label)
			}
			b.WriteString("}")
		}
		b.WriteString(" ")
		switch v := value.(type) {
		case int:
			b.WriteString(strconv.Itoa(v))
		case int64:
			b.WriteString(strconv.FormatInt(v, 10))
		case uint64:
			b.WriteString(strconv.FormatUint(v, 10))
		case float64:
			b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
		case bool:
			if v {
				b.WriteString("1")
			} else {
				b.WriteString("0")
			}
		default:
			b.WriteString("0")
		}
		b.WriteString("\n")
	}

	family("umbra_agents", "The hosts the server knows.", "gauge")
	line("umbra_agents", m.AgentsTotal)
	line("umbra_agents_online", m.AgentsOnline)

	family("umbra_tasks", "The tasks of the engagement.", "gauge")
	line("umbra_tasks_total", m.TasksTotal)
	line("umbra_tasks_pending", m.TasksPending)
	line("umbra_tasks_done", m.TasksDone)
	line("umbra_tasks_failed", m.TasksFailed)
	line("umbra_tasks_dead_letter", m.TasksDead)

	family("umbra_task_latency_seconds",
		"How long a task took between the delivery and the result.", "histogram")
	for i, bound := range hub.LatencyBuckets {
		line("umbra_task_latency_seconds_bucket", m.LatencyBuckets[i],
			"le=\""+strconv.FormatFloat(bound.Seconds(), 'f', -1, 64)+"\"")
	}
	line("umbra_task_latency_seconds_bucket", m.LatencyCount, "le=\"+inf\"")
	line("umbra_task_latency_seconds_sum", m.LatencySum)
	line("umbra_task_latency_seconds_count", m.LatencyCount)

	family("umbra_checkins_total", "The check-ins the beacons made.", "counter")
	line("umbra_checkins_total", m.Checkins)

	family("umbra_agents_by_transport",
		"The hosts per transport.", "gauge")
	for _, name := range m.TransportNames() {
		line("umbra_agents_by_transport", m.Transports[name],
			"transport=\""+name+"\"")
	}

	family("umbra_bytes_total", "The bytes that moved through the server.", "counter")
	line("umbra_bytes_in_total", m.BytesIn)
	line("umbra_bytes_out_total", m.BytesOut)

	family("umbra_operators", "The operator consoles that are connected.", "gauge")
	line("umbra_operators", m.Operators)

	family("umbra_events_dropped_total",
		"The events a console missed because its queue was full.", "counter")
	line("umbra_events_dropped_total", m.EventsDropped)

	family("umbra_breakers_open",
		"The hosts whose circuit breaker is open.", "gauge")
	line("umbra_breakers_open", m.BreakersOpen)

	family("umbra_quiet", "One when the server is in its maintenance window.", "gauge")
	line("umbra_quiet", m.Quiet)

	family("umbra_uptime_seconds", "How long the server has been running.", "gauge")
	line("umbra_uptime_seconds", m.Uptime.Seconds())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// handleRPC runs one operator command from the dashboard.
//
// The dashboard is a console that happens to be a web page: every command
// the console may run is reachable here too, with the role of the
// dashboard attached.  The role table is checked by the server, exactly
// like it is for a console, so the dashboard is not a way around it.
func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dispatch == nil {
		http.Error(w, "the dashboard does not run operator commands",
			http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is allowed here", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.ReadOnly {
		http.Error(w, "the dashboard is read-only", http.StatusForbidden)
		return
	}
	var body struct {
		Cmd  string         `json:"cmd"`
		Args map[string]any `json:"args"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "the request body is not valid JSON", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.Cmd) == "" {
		http.Error(w, "the request needs a command", http.StatusBadRequest)
		return
	}
	if body.Args == nil {
		body.Args = map[string]any{}
	}
	role := s.cfg.Role
	if role == "" {
		role = "viewer"
	}
	data, err := s.cfg.Dispatch(role, strings.TrimSpace(body.Cmd), body.Args)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
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
