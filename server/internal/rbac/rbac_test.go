package rbac_test

import (
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
)

func TestRoleOrdering(t *testing.T) {
	if !rbac.AtLeast(rbac.Admin, rbac.Operator) || !rbac.AtLeast(rbac.Operator, rbac.Viewer) {
		t.Fatal("role ordering is wrong")
	}
	if rbac.AtLeast(rbac.Viewer, rbac.Operator) {
		t.Fatal("a viewer was granted operator privileges")
	}
	// Unknown roles must never be sufficient: a typo in the keyring denies.
	for _, bad := range []string{"", "administrator", "root", "Admin"} {
		if rbac.AtLeast(bad, rbac.Viewer) {
			t.Errorf("unknown role %q was treated as valid", bad)
		}
		if rbac.Valid(bad) {
			t.Errorf("unknown role %q reported valid", bad)
		}
	}
}

func TestPermissionsByCommand(t *testing.T) {
	cases := []struct {
		role string
		cmd  string
		want bool
	}{
		{rbac.Viewer, "agents.list", true},
		{rbac.Viewer, "audit.tail", true},
		{rbac.Viewer, "task.submit", false},
		{rbac.Viewer, "agents.kill", false},
		{rbac.Operator, "task.submit", true},
		{rbac.Operator, "agents.sleep", true},
		{rbac.Operator, "schedule.remove", false},
		{rbac.Admin, "schedule.remove", true},
		{rbac.Admin, "task.submit", true},
		// Unlisted commands fail closed.
		{rbac.Operator, "server.shutdown", false},
		{rbac.Admin, "server.shutdown", true},
	}
	for _, c := range cases {
		if got := rbac.Allowed(c.role, c.cmd); got != c.want {
			t.Errorf("Allowed(%q, %q) = %v, want %v", c.role, c.cmd, got, c.want)
		}
	}
}

func TestCapabilitiesAreMonotonic(t *testing.T) {
	viewer := rbac.CapabilitiesFor(rbac.Viewer)
	operator := rbac.CapabilitiesFor(rbac.Operator)
	admin := rbac.CapabilitiesFor(rbac.Admin)

	set := func(in []string) map[string]bool {
		m := make(map[string]bool, len(in))
		for _, c := range in {
			m[c] = true
		}
		return m
	}
	v, o := set(viewer), set(operator)
	for cmd := range v {
		if !o[cmd] {
			t.Errorf("%q is available to a viewer but not to an operator", cmd)
		}
	}
	if len(admin) <= len(operator) || len(operator) <= len(viewer) {
		t.Fatalf("capability sets are not nested: %d/%d/%d", len(viewer), len(operator), len(admin))
	}
}
