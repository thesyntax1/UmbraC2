// Package rbac decides which operator role may call which RPC.
//
// Authentication says *who* connected; authorisation says what they may do.
// Both matter: an engagement usually has one person who can queue commands on
// every host and several who should only watch, and an "operator" token handed
// to a junior analyst should not be able to kill every beacon.
//
// The table is deliberately declarative and total: every RPC has an entry, and
// an RPC with no entry is treated as admin-only. A new command therefore fails
// closed instead of quietly being available to everyone.
package rbac

// Roles, ordered by privilege.
const (
	// Viewer can read: agents, tasks, results, audit trail, operators, chat.
	Viewer = "viewer"
	// Operator can additionally queue work: tasks, sleeps, kills, chat, schedules.
	Operator = "operator"
	// Admin can do everything, including cancelling other operators' work.
	Admin = "admin"
)

// rank orders roles; a higher number is more privileged.
var rank = map[string]int{
	Viewer:   1,
	Operator: 2,
	Admin:    3,
}

// Roles is the list of valid role names, most privileged first. Used for
// validation and for `--help` output.
var Roles = []string{Admin, Operator, Viewer}

// Valid reports whether name is a known role.
func Valid(name string) bool {
	_, ok := rank[name]
	return ok
}

// AtLeast reports whether have is at or above want. An unknown role is never
// sufficient, so a typo in the keyring denies access instead of granting it.
func AtLeast(have, want string) bool {
	h, ok := rank[have]
	if !ok {
		return false
	}
	w, ok := rank[want]
	if !ok {
		return false
	}
	return h >= w
}

// requirements maps an RPC command to the minimum role allowed to call it.
//
// Everything that changes state on a host is Operator; everything that changes
// the engagement or another operator's work is Admin. Read-only commands are
// Viewer so that observers can follow along without being able to touch
// anything.
var requirements = map[string]string{
	// ---- read-only ----------------------------------------------------
	"ping":           Viewer,
	"whoami":         Viewer,
	"server.stats":   Viewer,
	"audit.tail":     Viewer,
	"operators.list": Viewer,
	"agents.list":    Viewer,
	"agents.info":    Viewer,
	"task.get":       Viewer,
	"task.list":      Viewer,
	"chat.history":   Viewer,
	"schedule.list":  Viewer,

	// ---- state-changing on a host -------------------------------------
	"task.submit": Operator,
	"task.cancel": Operator,
	"agents.kill": Operator,
	"agents.exit": Operator,
	"agents.sleep": Operator,
	"chat.send":    Operator,
	"schedule.add": Operator,

	// ---- affects the engagement or other operators --------------------
	"schedule.remove": Admin,
	"events.test":     Admin,
}

// MinRole returns the minimum role for cmd. An unknown command requires Admin.
func MinRole(cmd string) string {
	if role, ok := requirements[cmd]; ok && role != "" {
		return role
	}
	return Admin
}

// Allowed reports whether role may call cmd.
func Allowed(role, cmd string) bool {
	return AtLeast(role, MinRole(cmd))
}

// CapabilitiesFor returns every command the role may call, sorted by the caller.
// It is exposed to clients through `whoami` so a console can grey out actions
// instead of discovering the limit through a refusal.
func CapabilitiesFor(role string) []string {
	out := make([]string, 0, len(requirements))
	for cmd, need := range requirements {
		if need != "" && AtLeast(role, need) {
			out = append(out, cmd)
		}
	}
	return out
}

// Commands returns the commands in the table (documentation and checks).
func Commands() map[string]string {
	out := make(map[string]string, len(requirements))
	for cmd, role := range requirements {
		out[cmd] = role
	}
	return out
}
