package hub

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// The limits of the workflow runner.
const (
	// WorkflowStepTimeout is how long one step waits for the answer of the
	// implant before the step is given up on.
	WorkflowStepTimeout = 180 * time.Second
	// WorkflowPollInterval is how often the runner looks at the task.
	WorkflowPollInterval = 2 * time.Second
	// WorkflowOutputLimit is how much of the answer of a step is kept in
	// the report.
	WorkflowOutputLimit = 4096
)

// The errors of the workflow runner.
var (
	// ErrNoSuchWorkflow is returned when the catalogue has no workflow of
	// that name.
	ErrNoSuchWorkflow = errors.New("hub: no such workflow")
	// ErrMissingParams is returned when the operator did not give the
	// parameters the workflow needs.
	ErrMissingParams = errors.New("hub: the workflow needs parameters")
)

// RunWorkflow starts a workflow.
//
// The run happens in the background: the implant answers when it checks in
// again, and a run that waited for it would hold the operator's console
// hostage.  The run is written to the store as it goes, so the console and
// the dashboard can watch it.
func (h *Hub) RunWorkflow(name string, params map[string]string, by string) (*store.WorkflowRun, error) {
	w, ok := h.store.Workflow(name)
	if !ok {
		return nil, ErrNoSuchWorkflow
	}
	if missing := store.MissingParams(w, params); len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrMissingParams, strings.Join(missing, ", "))
	}
	steps := store.ExpandWorkflow(w, params)
	run := &store.WorkflowRun{
		ID:       store.NewID("wfrun"),
		Workflow: w.Name,
		State:    store.RunQueued,
		Params:   params,
		Started:  time.Now().UTC(),
		By:       by,
	}
	if _, err := h.store.AddWorkflowRun(run); err != nil {
		return nil, err
	}
	h.Emit(Event{Kind: "workflow.started", From: by,
		Data: map[string]any{"workflow": w.Name, "run": run.ID}})
	go h.runWorkflow(run, steps)
	return run, nil
}

// runWorkflow walks the steps of a workflow.
//
// Every step writes its result into the run before the next one starts, so
// a run that is interrupted still says what it did.
func (h *Hub) runWorkflow(run *store.WorkflowRun, steps []store.WorkflowStep) {
	run.State = store.RunRunning
	h.store.UpdateWorkflowRun(run)

	report := &strings.Builder{}
	lastOK := true
	lastCode := int64(0)
	for i, step := range steps {
		entry := store.WorkflowRunStep{Index: i, Kind: step.Kind}
		switch step.Kind {
		case store.StepWait:
			entry.Detail = fmt.Sprintf("%d seconds", step.Seconds)
			entry.OK = true
			entry.Finished = true
			time.Sleep(time.Duration(step.Seconds) * time.Second)
		case store.StepCondition:
			entry.Detail = step.Condition
			entry.OK = lastOK
			entry.Code = lastCode
			entry.Finished = true
			switch {
			case step.Condition == "failed":
				lastOK = !lastOK
			case strings.HasPrefix(step.Condition, "code=="):
				want := strings.TrimSpace(strings.TrimPrefix(step.Condition, "code=="))
				lastOK = want == fmt.Sprintf("%d", lastCode)
			}
			if !lastOK {
				// The rest of the workflow does not run.
				entry.Skipped = true
				entry.Detail = step.Condition + " was not met"
			}
		case store.StepReport:
			// A report step names what was collected so far: the content
			// gathered by the steps before it lands under the title.
			entry.Detail = step.Title
			entry.OK = true
			entry.Finished = true
			collected := report.String()
			report.Reset()
			report.WriteString("## " + step.Title + "\n\n")
			if collected == "" {
				report.WriteString("_nothing yet_\n\n")
			} else {
				report.WriteString(collected)
				report.WriteString("\n")
			}
		case store.StepTask, store.StepChain:
			taskID, code, output, err := h.runWorkflowTask(step)
			entry.TaskID = taskID
			entry.Code = code
			entry.Output = output
			entry.Finished = true
			entry.OK = err == nil && code == 0
			lastOK = entry.OK
			lastCode = code
			if err != nil {
				entry.Detail = err.Error()
			} else if step.TaskKind != "" {
				entry.Detail = step.TaskKind
			}
			if output != "" {
				report.WriteString("### " + step.TaskKind + "\n\n")
				report.WriteString(output)
				report.WriteString("\n\n")
			}
		default:
			entry.Detail = "unknown step"
			entry.Finished = true
			entry.OK = false
		}
		run.Steps = append(run.Steps, entry)
		run.Current = i + 1
		if entry.TaskID != "" {
			run.TaskIDs = append(run.TaskIDs, entry.TaskID)
		}
		h.store.UpdateWorkflowRun(run)
		h.Emit(Event{Kind: "workflow.step", From: run.By,
			Data: map[string]any{"workflow": run.Workflow, "run": run.ID,
				"step": i, "kind": step.Kind, "ok": entry.OK}})

		if !entry.OK && entry.Skipped {
			run.State = store.RunStopped
			run.Finished = time.Now().UTC()
			run.Report = report.String()
			h.store.UpdateWorkflowRun(run)
			h.Emit(Event{Kind: "workflow.finished", From: run.By,
				Data: map[string]any{"workflow": run.Workflow, "run": run.ID,
					"state": run.State}})
			return
		}
	}
	run.State = store.RunDone
	run.Finished = time.Now().UTC()
	run.Report = report.String()
	h.store.UpdateWorkflowRun(run)
	h.Emit(Event{Kind: "workflow.finished", From: run.By,
		Data: map[string]any{"workflow": run.Workflow, "run": run.ID,
			"state": run.State}})
}

// runWorkflowTask runs one step that talks to an implant and waits for the
// answer.
//
// The wait is the whole point: a workflow is a sequence of steps that build
// on each other, so the next step starts when the previous one answered.
func (h *Hub) runWorkflowTask(step store.WorkflowStep) (string, int64, string, error) {
	agent := step.Agent
	if agent == "" {
		return "", 0, "", errors.New("hub: the step has no agent")
	}
	var task *store.Task
	var err error
	if step.Kind == store.StepChain {
		stages := make([]ChainStage, 0, len(step.Stages))
		for _, stage := range step.Stages {
			stages = append(stages, ChainStage{Kind: stage.TaskKind, Args: stage.Args})
		}
		var chain *Chain
		task, chain, err = h.SubmitChain(agent, step.Title, stages)
		if err != nil {
			return "", 0, "", err
		}
		if chain == nil {
			return "", 0, "", errors.New("hub: the chain was not started")
		}
	} else {
		task, err = h.SubmitTask(agent, step.TaskKind, step.Args)
		if err != nil {
			return "", 0, "", err
		}
	}
	if task == nil {
		return "", 0, "", errors.New("hub: the task was not queued")
	}
	deadline := time.Now().Add(WorkflowStepTimeout)
	for {
		current, ok := h.store.Task(task.ID)
		if !ok {
			return task.ID, 0, "", errors.New("hub: the task vanished")
		}
		switch current.State {
		case store.TaskDone, store.TaskFailed, store.TaskCancelled:
			out := string(current.Output)
			if len(out) > WorkflowOutputLimit {
				out = out[:WorkflowOutputLimit]
			}
			return current.ID, current.Code, out, nil
		}
		if time.Now().After(deadline) {
			return current.ID, current.Code, "", fmt.Errorf(
				"hub: the step timed out after %s", WorkflowStepTimeout)
		}
		time.Sleep(WorkflowPollInterval)
	}
}

// SetAlertRules replaces the alert rules of the running server.
//
// The rules are kept in the store, so they survive a restart, and the
// change is an event: the team sees who changed the rules.
func (h *Hub) SetAlertRules(rules []config.AlertRule, by string) {
	h.store.SetAlertRules(rules)
	h.store.SaveAsync()
	h.Emit(Event{Kind: "alerts.changed", From: by,
		Data: map[string]any{"count": len(rules)}})
	h.log.Info("the alert rules were changed", "count", len(rules), "by", by)
}

// AlertRules returns the rules the server watches the journal with.
//
// The rules of the configuration file are the fallback: when the team has
// not written any, the server runs with the ones it was started with.
func (h *Hub) AlertRules() []config.AlertRule {
	rules := h.store.AlertRules()
	if len(rules) == 0 {
		rules = h.cfg.Server.Alerts
	}
	return rules
}
