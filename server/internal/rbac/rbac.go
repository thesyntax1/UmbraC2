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
	"ping":         Viewer,
	"whoami":       Viewer,
	"server.stats": Viewer,
	"audit.tail":   Viewer,
	// The verification of the ledger walks the whole file, so it is the
	// work of an operator: a viewer reads the trail, an operator proves
	// that it has not been edited.
	"audit.verify":   Operator,
	"operators.list": Viewer,
	"agents.list":    Viewer,
	"agents.info":    Viewer,
	"task.get":       Viewer,
	"task.list":      Viewer,
	"chat.history":   Viewer,
	// Who is in the channel is presence, like the operator list.
	"chat.operators": Viewer,
	"schedule.list":  Viewer,
	// The alert rules are configuration: reading them is harmless.
	"alerts.list": Viewer,

	// ---- state-changing on a host -------------------------------------
	"task.submit":     Operator,
	"events.list":     Viewer,
	"engagement.wipe": Admin,
	"sessions.list":   Viewer,
	"task.cancel":     Operator,
	"task.retry":      Operator,
	// The digest of the ledger of who asked is a reading, not a change,
	// so a viewer may carry it home.
	"task.ledger-dig": Viewer,
	// A hold is a hand on one queue: lifting and setting it changes what
	// a host is asked to do, so it is operator work, while reading the
	// pauses of the fleet is not.
	"queue.hold":    Operator,
	"queue.release": Operator,
	"queue.holds":   Viewer,
	// A freeze ties every hand in the engagement at once.  It is the
	// heaviest thing an operator can do, so it belongs to an admin; the
	// reading of the lock is harmless.
	"engagement.freeze": Admin,
	"engagement.state":  Viewer,
	// Comparing two hosts is reading the inventory twice.
	"fleet.compare": Viewer,
	// The sorting hat colours new joins: writing and erasing its
	// sentences changes the fleet, reading them does not.
	"tag.rule.add":    Operator,
	"tag.rule.list":   Viewer,
	"tag.rule.remove": Operator,
	// A bulk task reaches every agent the filter selects, so it is an
	// operator action like a single task: the difference is the reach, not
	// the privilege.
	"task.bulk": Operator,
	// A chain runs several tasks one after the other on the same host, so it
	// is an operator action like a single task.
	"task.chain":    Operator,
	"agents.kill":   Operator,
	"agents.exit":   Operator,
	"agents.sleep":  Operator,
	"agents.policy": Operator,
	"agents.tag":    Operator,
	"chat.send":     Operator,
	"schedule.add":  Operator,

	// ---- the server-side file store -------------------------------------
	// Reading the store is harmless; filling it and pushing its contents
	// to a host is an operator action.
	"artifact.list":   Viewer,
	"artifact.get":    Viewer,
	"artifact.put":    Operator,
	"artifact.remove": Operator,
	"artifact.push":   Operator,

	// ---- the credential vault -------------------------------------------
	// Reading the shape of the material is harmless; taking the value out
	// of the vault is an operator action, because that is the moment the
	// material leaves the framework.
	"creds.list":   Viewer,
	"creds.search": Viewer,
	"creds.export": Operator,

	// ---- the zero-footprint wipe ------------------------------------------
	// Reading the surface of a host is harmless: the survey, the report,
	// the verification and the timeline only look.
	"forensics.survey":   Viewer,
	"forensics.report":   Viewer,
	"forensics.verify":   Viewer,
	"forensics.timeline": Viewer,
	// The wipe removes files on a host, so it is an operator action.
	"forensics.wipe": Operator,
	// The self-destruction and the decommissioning are the end of an
	// engagement on that host, so they belong to the person who owns it.
	"forensics.self":         Admin,
	"forensics.decommission": Admin,
	// Arming the dead man's switch ends the implant on the host when the
	// operator goes quiet: it is the end of an engagement waiting to
	// happen, so it belongs to the person who owns it.
	"forensics.deadman": Admin,

	// ---- the hunt: the indicators of the team ---------------------------
	// Reading the catalogue of the indicators is harmless: it is a list
	// of hashes and paths, and knowing them changes nothing on a host.
	"hunt.list": Viewer,
	// Filling the catalogue and sending it to a host is the work of the
	// hunt, so it is an operator action.
	"hunt.add":    Operator,
	"hunt.remove": Operator,
	"hunt.sweep":  Operator,

	// ---- the health of the fleet ----------------------------------------
	// The score of the hosts is a read of the inventory: it says how
	// the engagement is going and it touches nothing.
	"health.fleet": Viewer,

	// ---- the evidence files ----------------------------------------------
	// Reading a case and its chain of custody is harmless.
	"case.list": Viewer,
	"case.get":  Viewer,
	// Opening a case, putting evidence into it and closing it are the
	// work of the engagement: they are operator actions.
	"case.create": Operator,
	"case.add":    Operator,
	"case.close":  Operator,

	// ---- the two-person rule ---------------------------------------------
	// The second factor of the operator.  Reading who has one is a
	// read; making one and taking it away changes the way the team
	// logs in, so it is the work of an admin.
	"operator.otp.status": Viewer,
	"operator.otp.rotate": Operator,
	"operator.otp.remove": Operator,

	// The notes of the team: reading them is the read of a viewer,
	// writing them the work of the operator, and taking them away
	// the work of the operator who wrote them or of an admin.
	"note.add":    Operator,
	"note.list":   Viewer,
	"note.remove": Operator,
	"note.show":   Viewer,

	// The baseline of the paths the team watches: reading it is a
	// read, planting a path and looking at it are the work of the
	// team.
	"baseline.add":    Operator,
	"baseline.list":   Viewer,
	"baseline.remove": Operator,
	"baseline.check":  Operator,

	// The wires to the outside world: writing one down, taking one
	// away and ringing one are the work of the operator, because a
	// wire is a place where the news of the engagement leaves the
	// server.  Reading the ledger is a read.
	"hook.add":    Operator,
	"hook.list":   Viewer,
	"hook.remove": Operator,
	"hook.test":   Operator,

	// The wall of the techniques and the digging box are reads, and
	// nothing more: the wall counts what is done and the box finds
	// what is written, so a viewer may look at both all day.
	"attack.coverage": Viewer,
	"search.query":    Viewer,

	// The rhythm of the beacons and the keys that open more than one
	// door are reads; the watches of the silences are promises to
	// worry, and a promise is written and taken away by the operator
	// who made it.
	"rhythm.get":      Viewer,
	"rhythm.fleet":    Viewer,
	"creds.reuse":     Viewer,
	"silence.add":     Operator,
	"silence.list":    Viewer,
	"silence.remove":  Operator,
	"onboard.add":     Operator,
	"onboard.list":    Viewer,
	"onboard.remove":  Operator,
	"onboard.run":     Operator,
	"pivot.map":       Viewer,
	"artifact.verify": Viewer,

	// Reading the queue of the approvals and one request of it is a read:
	// a viewer sees what the team is waiting for.
	"approval.list": Viewer,
	"approval.get":  Viewer,
	// Asking for an operation is an operator action.
	"approval.request": Operator,
	// Deciding is the work of the rule: an operator decides the requests
	// of the others.  The queue refuses the operator who asked, and the
	// role table is what keeps the rest of the team honest.
	"approval.approve": Operator,
	"approval.deny":    Operator,

	// ---- the tripwires ---------------------------------------------------
	// Reading the ledger of the canaries is harmless.
	"canary.list": Viewer,
	"canary.get":  Viewer,
	// Planting a file on a host, looking at it and stopping the watch are
	// the work of the engagement: they are operator actions.
	"canary.plant":  Operator,
	"canary.check":  Operator,
	"canary.remove": Operator,

	// ---- the file of a host ----------------------------------------------
	// The dossier is a read of everything the server knows about a host.
	"dossier.get":  Viewer,
	"dossier.list": Viewer,

	// ---- burning an engagement ------------------------------------------
	// A panic tells every selected beacon to exit and stops the server
	// from feeding it any more work.  It is the end of an engagement, so
	// it belongs to the person who owns it.
	"agents.panic": Admin,

	// ---- coordinating a shared engagement -----------------------------
	// A claim orders human work; it never touches a host, so a junior
	// operator may take and drop one.
	"task.claim":   Operator,
	"task.release": Operator,
	// Handing a task to a colleague orders human work as well.
	"task.assign": Operator,
	// Focus is presence: which agent this console is looking at.
	"operators.focus": Operator,

	// ---- the route of an agent ------------------------------------------
	// The route tells a beacon which transport it speaks.  Reading it is
	// harmless; changing it changes how the implant reaches the server,
	// so it is an operator action.
	"transport.get":  Viewer,
	"transport.list": Viewer,
	"transport.set":  Operator,

	// ---- pivoting ------------------------------------------------------
	// Opening a pivot reaches into a network the operator console cannot
	// see, so it is an operator action; listing them is harmless.
	"pivot.list":    Viewer,
	"pivot.open":    Operator,
	"pivot.close":   Operator,
	"pivot.claim":   Viewer,
	"pivot.release": Operator,
	// A leased pivot is rented, tied to time; extending the lease
	// re-opens the same door and is operator work, like closing is.
	"pivot.extend": Operator,

	// ---- layer-3 tunnel ------------------------------------------------
	"vpn.status":   Viewer,
	"vpn.peers":    Viewer,
	"vpn.allocate": Operator,
	"vpn.routes":   Viewer,
	"vpn.route":    Operator,
	"vpn.ping":     Operator,

	// ---- extensions ----------------------------------------------------
	// Reading the catalogue is harmless: searching it, asking what a
	// module needs and resolving its dependencies change nothing.
	"armory.list":     Viewer,
	"armory.search":   Viewer,
	"armory.needs":    Viewer,
	"armory.versions": Viewer,
	"armory.resolve":  Viewer,
	// Installing a module and importing a catalogue change what the
	// engagement is able to run, so they are operator actions.
	"armory.install": Operator,
	"armory.import":  Operator,
	"armory.remove":  Admin,
	"armory.run":     Operator,

	// ---- runtime command namespace -------------------------------------
	"alias.list": Viewer,
	"alias.run":  Operator,
	// The namespace is shared: the team writes the aliases everybody
	// uses, and the audit trail says who wrote what.
	"alias.add":    Operator,
	"alias.remove": Operator,

	// ---- the queue and the maintenance window ---------------------------
	// The quiet window stops the traffic of the server: it is an admin
	// decision, like burning an engagement.
	"server.quiet": Admin,
	// The keys of the server itself: the agent PSK and the operator
	// tokens.  Rotating a credential is the one thing that can lock the
	// whole engagement out, so it belongs to the admin.
	"keys.rotate":   Admin,
	"tokens.rotate": Admin,
	"tokens.list":   Viewer,
	// Reading the queue is harmless.
	"server.queue": Viewer,
	// The priority of a task is the operator's call.
	"task.priority": Operator,

	// ---- the workflow layer --------------------------------------------
	// A workflow is a named sequence of steps: writing one is operator
	// work, running one is operator work too (it queues tasks), and
	// watching one is harmless.
	"workflow.list":   Viewer,
	"workflow.status": Viewer,
	"workflow.add":    Operator,
	"workflow.remove": Operator,
	"workflow.run":    Operator,

	// ---- team synchronisation ------------------------------------------
	"team.sync": Viewer,
	// The handover document only reads the engagement.
	"team.handover": Viewer,

	// ---- affects the engagement or other operators --------------------
	"schedule.remove": Admin,
	"events.test":     Admin,
	// A stager carries the agent pre-shared key, so generating one is an
	// admin action: it hands out a credential that identifies an implant.
	"stager.generate": Admin,
}

// MinRole returns the minimum role for cmd. An unknown command requires Admin.
func MinRole(cmd string) string {
	if role, ok := requirements[cmd]; ok && role != "" {
		return role
	}
	return Admin
}

// Known reports whether cmd is a command of the protocol.
//
// The scopes of an operator name commands, and a scope that names a
// command nobody has heard of is a mistake: it is refused when the
// scope is set, not silently ignored later.
func Known(cmd string) bool {
	_, ok := requirements[cmd]
	return ok
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
