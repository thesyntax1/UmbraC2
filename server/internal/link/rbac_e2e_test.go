package link_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/link"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

func rpc(t *testing.T, c *client, rid uint64, cmd string, args upk.Map) (bool, upk.Map) {
	t.Helper()
	c.send(t, wire.MsgOpRequest, upk.Map{"rid": rid, "cmd": cmd, "args": args})
	msgType, resp := c.recv(t)
	if msgType != wire.MsgOpResponse {
		t.Fatalf("%s: expected OP_RESPONSE, got %s", cmd, wire.TypeName(msgType))
	}
	ok, _ := resp["ok"].(bool)
	data, _ := resp["data"].(map[string]any)
	return ok, data
}

// A viewer token must be able to read everything and change nothing.
func TestViewerIsReadOnly(t *testing.T) {
	_, _, _, opAddr := newTestServer(t)
	viewer := dial(t, opAddr, viewerToken, crypt.RoleOperator, "viewer1")

	if ok, data := rpc(t, viewer, 1, "whoami", upk.Map{}); !ok {
		t.Fatalf("whoami failed: %v", data)
	} else if data["role"] != "viewer" {
		t.Fatalf("whoami reports role %v, want viewer", data["role"])
	}

	for _, cmd := range []string{"agents.list", "server.stats", "operators.list", "audit.tail"} {
		if ok, data := rpc(t, viewer, 2, cmd, upk.Map{}); !ok {
			t.Errorf("viewer was refused %s: %v", cmd, data)
		}
	}

	ok, data := rpc(t, viewer, 3, "task.submit", upk.Map{"id": "nobody", "kind": "ping"})
	if ok {
		t.Fatal("viewer was allowed to submit a task")
	}
	_ = data
	// The refusal must say what is required, not just "no".
	_, resp := func() (byte, map[string]any) {
		viewer.send(t, wire.MsgOpRequest, upk.Map{
			"rid": uint64(4), "cmd": "agents.kill", "args": upk.Map{"id": "nobody"},
		})
		return viewer.recv(t)
	}()
	errText, _ := resp["err"].(string)
	if errText == "" {
		t.Fatalf("refusal had no message: %v", resp)
	}
	for _, want := range []string{"permission denied", "operator", "viewer"} {
		if !contains(errText, want) {
			t.Errorf("refusal %q does not mention %q", errText, want)
		}
	}
}

// An operator may touch hosts but not manage the engagement.
func TestOperatorCannotManageEngagement(t *testing.T) {
	_, h, _, opAddr := newTestServer(t)
	op := dial(t, opAddr, opToken, crypt.RoleOperator, "op1")

	// Admin-only: removing a schedule someone else created.
	if ok, _ := rpc(t, op, 1, "schedule.remove", upk.Map{"schedule_id": "s-nope"}); ok {
		t.Fatal("operator removed a schedule (admin-only command)")
	}
	// But ordinary work is fine.
	if ok, data := rpc(t, op, 2, "schedule.list", upk.Map{}); !ok {
		t.Fatalf("schedule.list failed: %v", data)
	}
	if ok, data := rpc(t, op, 3, "chat.send", upk.Map{"text": "hi"}); !ok {
		t.Fatalf("chat.send failed: %v", data)
	}
	_ = h
}

// A denied call must be in the audit trail: authorisation decisions are part of
// the record, not just the operations that succeeded.
func TestDeniedCallsAreAudited(t *testing.T) {
	srv, _, _, opAddr := newTestServer(t)
	log := attachAudit(t, srv)

	viewer := dial(t, opAddr, viewerToken, crypt.RoleOperator, "viewer1")
	if ok, _ := rpc(t, viewer, 1, "agents.kill", upk.Map{"id": "x"}); ok {
		t.Fatal("viewer killed an agent")
	}

	entries := log.Tail(10)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	denied := entries[0]
	if denied.Cmd != "agents.kill" || denied.OK {
		t.Fatalf("denied call not recorded as a failure: %+v", denied)
	}
	if denied.Operator != "viewer1" {
		t.Errorf("denied call attributed to %q", denied.Operator)
	}
	if !contains(denied.Err, "permission denied") {
		t.Errorf("audit entry does not show the denial: %q", denied.Err)
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// attachAudit gives the test server a real audit file and returns the logger.
func attachAudit(t *testing.T, srv *link.Server) *audit.Logger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(audit.Options{Path: path})
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	srv.SetAudit(log)
	return log
}
