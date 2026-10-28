package store

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
)

// The limits of the workflow catalogue.
const (
	// MaxWorkflows bounds how many workflows the server keeps.
	MaxWorkflows = 128
	// MaxWorkflowSteps bounds the length of one workflow.
	MaxWorkflowSteps = 64
	// MaxWorkflowRuns bounds how many runs are remembered.
	MaxWorkflowRuns = 256
	// MaxWorkflowNameLen bounds the name of a workflow.
	MaxWorkflowNameLen = 64
)

// The kinds of step a workflow is made of.
const (
	// StepTask runs one task on one agent and waits for the answer.
	StepTask = "task"
	// StepChain runs a multi-stage task on one agent.
	StepChain = "chain"
	// StepWait waits for a number of seconds.
	StepWait = "wait"
	// StepCondition looks at the answer of the step before it and decides
	// whether the rest of the workflow still runs.
	StepCondition = "condition"
	// StepReport collects what the workflow found.
	StepReport = "report"
)

// The errors of the workflow catalogue.
var (
	ErrNoSuchWorkflow = errors.New("store: no such workflow")
	ErrNoSuchRun      = errors.New("store: no such workflow run")
	ErrBadStep        = errors.New("store: unknown step kind")
)

// WorkflowStep is one step of a workflow.
//
// The steps are data, not code: the server walks them, the operator writes
// them, and the console shows them.
type WorkflowStep struct {
	// Kind is "task", "chain", "wait", "condition" or "report".
	Kind string `json:"kind"`
	// Agent is the agent the step runs on. It may hold a parameter
	// placeholder ("{{target}}").
	Agent string `json:"agent,omitempty"`
	// TaskKind is the kind of the task the step runs.
	TaskKind string `json:"task_kind,omitempty"`
	// Args are the arguments of the task. A string argument may hold a
	// parameter placeholder.
	Args map[string]any `json:"args,omitempty"`
	// Stages are the steps of a chain.
	Stages []WorkflowStep `json:"stages,omitempty"`
	// Seconds is how long a wait lasts.
	Seconds int `json:"seconds,omitempty"`
	// Condition is what a condition step looks at: "ok" (the last step
	// succeeded), "failed" (it did not) or "code==N".
	Condition string `json:"condition,omitempty"`
	// Title is the name of a report step.
	Title string `json:"title,omitempty"`
}

// Clone returns a copy with its own maps and slices.
func (st WorkflowStep) Clone() WorkflowStep {
	out := st
	if st.Args != nil {
		out.Args = make(map[string]any, len(st.Args))
		for k, v := range st.Args {
			out.Args[k] = v
		}
	}
	if st.Stages != nil {
		out.Stages = make([]WorkflowStep, 0, len(st.Stages))
		for _, stage := range st.Stages {
			out.Stages = append(out.Stages, stage.Clone())
		}
	}
	return out
}

// Workflow is a named, parameterised sequence of steps.
//
// A workflow is what an engagement phase looks like: "sweep every web
// server, collect the recon of the ones that answer, write the report".
// The parameters are the placeholders the steps carry: {{target}} and
// friends are filled in when the workflow runs.
type Workflow struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Params      []string       `json:"params,omitempty"`
	Steps       []WorkflowStep `json:"steps"`
	CreatedBy   string         `json:"created_by,omitempty"`
	Created     time.Time      `json:"created"`
	Updated     time.Time      `json:"updated"`
	Runs        uint64         `json:"runs"`
	LastRun     time.Time      `json:"last_run,omitempty"`
}

// Clone returns a copy with its own slices.
func (w *Workflow) Clone() *Workflow {
	if w == nil {
		return nil
	}
	out := *w
	out.Params = append([]string(nil), w.Params...)
	out.Steps = make([]WorkflowStep, 0, len(w.Steps))
	for _, step := range w.Steps {
		out.Steps = append(out.Steps, step.Clone())
	}
	return &out
}

// WorkflowRun is one execution of a workflow.
type WorkflowRun struct {
	ID         string            `json:"id"`
	Workflow   string            `json:"workflow"`
	State      string            `json:"state"`
	Params     map[string]string `json:"params,omitempty"`
	Started    time.Time         `json:"started"`
	Finished   time.Time         `json:"finished,omitempty"`
	By         string            `json:"by,omitempty"`
	Steps      []WorkflowRunStep `json:"steps,omitempty"`
	Report     string            `json:"report,omitempty"`
	Current    int               `json:"current"`
	Error      string            `json:"err,omitempty"`
	TaskIDs    []string          `json:"task_ids,omitempty"`
}

// The states of a run.
const (
	RunQueued  = "queued"
	RunRunning = "running"
	RunDone    = "done"
	RunFailed  = "failed"
	RunStopped = "stopped"
)

// WorkflowRunStep is what one step of a run did.
type WorkflowRunStep struct {
	Index    int    `json:"index"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail,omitempty"`
	TaskID   string `json:"task_id,omitempty"`
	Code     int64  `json:"code"`
	OK       bool   `json:"ok"`
	Output   string `json:"output,omitempty"`
	Skipped  bool   `json:"skipped,omitempty"`
	Finished bool   `json:"finished,omitempty"`
}

// Clone returns a copy with its own slices.
func (r *WorkflowRun) Clone() *WorkflowRun {
	if r == nil {
		return nil
	}
	out := *r
	out.Params = make(map[string]string, len(r.Params))
	for k, v := range r.Params {
		out.Params[k] = v
	}
	out.Steps = append([]WorkflowRunStep(nil), r.Steps...)
	out.TaskIDs = append([]string(nil), r.TaskIDs...)
	return &out
}

// AddWorkflow writes a workflow into the catalogue.
//
// A workflow with the same name replaces the old one: the team edits the
// workflow it uses instead of keeping two versions of it.
func (s *Store) AddWorkflow(w *Workflow) (*Workflow, error) {
	if w == nil || strings.TrimSpace(w.Name) == "" {
		return nil, errors.New("store: a workflow needs a name")
	}
	if len(w.Name) > MaxWorkflowNameLen {
		return nil, fmt.Errorf("store: the name of a workflow is longer than %d characters",
			MaxWorkflowNameLen)
	}
	if len(w.Steps) == 0 {
		return nil, errors.New("store: a workflow needs at least one step")
	}
	if len(w.Steps) > MaxWorkflowSteps {
		return nil, fmt.Errorf("store: a workflow holds at most %d steps", MaxWorkflowSteps)
	}
	for _, step := range w.Steps {
		if err := validateStep(step); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.workflows[w.Name]; !exists && len(s.workflows) >= MaxWorkflows {
		return nil, errors.New("store: too many workflows")
	}
	now := time.Now().UTC()
	w.Created = now
	w.Updated = now
	if s.workflows[w.Name] == nil {
		s.workflowOrder = append(s.workflowOrder, w.Name)
	}
	s.workflows[w.Name] = w.Clone()
	return w.Clone(), nil
}

// validateStep checks that a step is one the runner knows.
func validateStep(step WorkflowStep) error {
	switch step.Kind {
	case StepTask:
		if step.TaskKind == "" {
			return errors.New("store: a task step needs a task kind")
		}
	case StepChain:
		if len(step.Stages) == 0 {
			return errors.New("store: a chain step needs at least one stage")
		}
		for _, stage := range step.Stages {
			if err := validateStep(stage); err != nil {
				return err
			}
		}
	case StepWait:
		if step.Seconds <= 0 {
			return errors.New("store: a wait step needs a number of seconds")
		}
	case StepCondition:
		if step.Condition == "" {
			return errors.New("store: a condition step needs a condition")
		}
	case StepReport:
		if step.Title == "" {
			return errors.New("store: a report step needs a title")
		}
	default:
		return fmt.Errorf("%w: %q", ErrBadStep, step.Kind)
	}
	return nil
}

// Workflows returns every workflow, in creation order.
func (s *Store) Workflows() []*Workflow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Workflow, 0, len(s.workflowOrder))
	for _, name := range s.workflowOrder {
		if w := s.workflows[name]; w != nil {
			out = append(out, w.Clone())
		}
	}
	return out
}

// Workflow returns one workflow by name.
func (s *Store) Workflow(name string) (*Workflow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.workflows[name]
	if !ok {
		return nil, false
	}
	return w.Clone(), true
}

// RemoveWorkflow takes a workflow out of the catalogue.
func (s *Store) RemoveWorkflow(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.workflows[name]; !ok {
		return false
	}
	delete(s.workflows, name)
	for i, known := range s.workflowOrder {
		if known == name {
			s.workflowOrder = append(s.workflowOrder[:i], s.workflowOrder[i+1:]...)
			break
		}
	}
	return true
}

// AddWorkflowRun records a run.
func (s *Store) AddWorkflowRun(r *WorkflowRun) (*WorkflowRun, error) {
	if r == nil {
		return nil, errors.New("store: a run needs a workflow")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		r.ID = NewID("wfrun")
	}
	if r.Started.IsZero() {
		r.Started = time.Now().UTC()
	}
	s.runs[r.ID] = r.Clone()
	s.runOrder = append(s.runOrder, r.ID)
	for len(s.runOrder) > MaxWorkflowRuns {
		oldest := s.runOrder[0]
		s.runOrder = s.runOrder[1:]
		delete(s.runs, oldest)
	}
	return r.Clone(), nil
}

// UpdateWorkflowRun writes the state of a run back.
func (s *Store) UpdateWorkflowRun(r *WorkflowRun) error {
	if r == nil || r.ID == "" {
		return errors.New("store: a run needs an id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[r.ID]; !ok {
		return ErrNoSuchRun
	}
	s.runs[r.ID] = r.Clone()
	return nil
}

// WorkflowRun returns one run.
func (s *Store) WorkflowRun(id string) (*WorkflowRun, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.runs[id]
	if !ok {
		return nil, false
	}
	return r.Clone(), true
}

// WorkflowRuns returns the newest runs, newest first.
func (s *Store) WorkflowRuns(limit int) []*WorkflowRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*WorkflowRun, 0, len(s.runOrder))
	for i := len(s.runOrder) - 1; i >= 0; i-- {
		if r := s.runs[s.runOrder[i]]; r != nil {
			out = append(out, r.Clone())
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// ExpandWorkflow fills the parameters of a workflow into its steps.
//
// A parameter is written {{name}} in the text of a step; the value the
// operator gave at run time replaces it.  A parameter nobody gave stays as
// it is, so the operator sees what was missing.
func ExpandWorkflow(w *Workflow, params map[string]string) []WorkflowStep {
	if w == nil {
		return nil
	}
	out := make([]WorkflowStep, 0, len(w.Steps))
	for _, step := range w.Steps {
		out = append(out, expandStep(step, params))
	}
	return out
}

// expandStep fills the parameters of one step.
func expandStep(step WorkflowStep, params map[string]string) WorkflowStep {
	out := step.Clone()
	out.Agent = ExpandParams(out.Agent, params)
	out.TaskKind = ExpandParams(out.TaskKind, params)
	out.Title = ExpandParams(out.Title, params)
	out.Condition = ExpandParams(out.Condition, params)
	if out.Args != nil {
		for k, v := range out.Args {
			if text, ok := v.(string); ok {
				out.Args[k] = ExpandParams(text, params)
			}
		}
	}
	if len(out.Stages) > 0 {
		stages := make([]WorkflowStep, 0, len(out.Stages))
		for _, stage := range out.Stages {
			stages = append(stages, expandStep(stage, params))
		}
		out.Stages = stages
	}
	return out
}

// ExpandParams replaces the placeholders of a text.
//
// The placeholders are {{name}}: the workflow says {{target}} and the
// operator gives the target when the workflow runs.
func ExpandParams(text string, params map[string]string) string {
	if text == "" || len(params) == 0 {
		return text
	}
	out := text
	for name, value := range params {
		out = strings.ReplaceAll(out, "{{"+name+"}}", value)
	}
	return out
}

// MissingParams returns the parameters a workflow needs and the run did
// not give.
//
// A workflow that is missing a parameter is a workflow that would run the
// wrong thing, so the runner refuses it.
func MissingParams(w *Workflow, params map[string]string) []string {
	if w == nil {
		return nil
	}
	missing := []string{}
	for _, name := range w.Params {
		if strings.TrimSpace(params[name]) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

// AlertRules returns the alert rules the team wrote at runtime.
//
// The rules of the configuration file are the ones the server starts
// with; these are the ones it runs with, and they are kept in the
// snapshot so they survive a restart.
func (s *Store) AlertRules() []config.AlertRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]config.AlertRule, 0, len(s.alertRules))
	out = append(out, s.alertRules...)
	return out
}

// SetAlertRules replaces the alert rules of the server.
func (s *Store) SetAlertRules(rules []config.AlertRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertRules = make([]config.AlertRule, 0, len(rules))
	s.alertRules = append(s.alertRules, rules...)
}
