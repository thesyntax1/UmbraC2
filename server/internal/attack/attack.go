// Package attack is the wall of the techniques the team uses.
//
// The MITRE ATT&CK catalogue is the common tongue of the trade: an
// engagement is talked about in techniques, not in the names a tool
// happens to give its buttons.  The wall lies the task kinds of the
// beacon next to the techniques they belong to, and then counts the
// work the team has actually done: which techniques have been used, on
// how many hosts, and when last.
//
// The table is a statement, not a telemetry feed: it does not learn and
// it does not pretend.  A kind that means several things appears under
// each of them, the kinds of the server itself — the tripwires, the
// baseline, the hunts — are tools of the watch and not of the
// adversary, and the kind nobody mapped shows up in the unmapped list
// instead of being quietly lost.
//
// The mobile kinds ride the enterprise techniques where the work is
// genuinely the same, and carry their mobile number where it is not.
// The wall is humble that way on purpose: it would rather be looked at
// than be right in front of a lawyer of the catalogue.
package attack

import (
	"sort"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// Technique is one entry of the wall: the number and the name the
// trade talks in, the tactic it belongs to, and the task kinds that
// are the work of it.
type Technique struct {
	// ID is the number of the catalogue: "T1059".
	ID string `json:"id"`
	// Name is the name of the catalogue.
	Name string `json:"name"`
	// Tactic is the column of the wall the technique stands in.
	Tactic string `json:"tactic"`
	// Kinds are the task kinds the beacon knows that are this work.
	Kinds []string `json:"kinds"`
}

// Table is the wall itself.
//
// When a new task kind is born, it is born here too: a kind that is
// not in the table and not in the ignored list is reported as
// unmapped, so the wall cannot silently fall behind the implants.
var Table = []Technique{
	{ID: "T1595", Name: "Active Scanning", Tactic: "reconnaissance",
		Kinds: []string{"recon", "recon.suggest", "scan"}},
	{ID: "T1082", Name: "System Information Discovery", Tactic: "discovery",
		Kinds: []string{"sysinfo", "env", "triage", "pwd"}},
	{ID: "T1057", Name: "Process Discovery", Tactic: "discovery",
		Kinds: []string{"ps"}},
	{ID: "T1083", Name: "File and Directory Discovery", Tactic: "discovery",
		Kinds: []string{"ls", "dir", "find"}},
	{ID: "T1016", Name: "System Network Configuration Discovery", Tactic: "discovery",
		Kinds: []string{"netinfo", "wifi.profiles", "wifi.dump", "resolve"}},
	{ID: "T1018", Name: "Remote System Discovery", Tactic: "discovery",
		Kinds: []string{"domain.map"}},
	{ID: "T1046", Name: "Network Service Discovery", Tactic: "discovery",
		Kinds: []string{"scan"}},
	{ID: "T1518.001", Name: "Software Discovery: Security Software", Tactic: "discovery",
		Kinds: []string{"av.survey", "evade.posture"}},
	{ID: "T1120", Name: "Peripheral Device Discovery", Tactic: "discovery",
		Kinds: []string{"usb.history", "bluetooth.scan"}},
	{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "execution",
		Kinds: []string{"shell", "cmd", "script"}},
	{ID: "T1106", Name: "Native API", Tactic: "execution",
		Kinds: []string{"bof", "coff", "ext", "wasm"}},
	{ID: "T1516", Name: "Input Injection", Tactic: "execution",
		Kinds: []string{"ui.tap", "ui.text", "ui.scroll", "ui.global", "ui.events", "ui.stream"}},
	{ID: "T1547", Name: "Boot or Logon Autostart Execution", Tactic: "persistence",
		Kinds: []string{"persist", "persist.list", "persist.verify",
			"persist.migrate", "persist.health", "unpersist"}},
	{ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactic: "privilege-escalation",
		Kinds: []string{"privesc"}},
	{ID: "T1134", Name: "Access Token Manipulation", Tactic: "privilege-escalation",
		Kinds: []string{"token"}},
	{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion",
		Kinds: []string{"inject"}},
	{ID: "T1620", Name: "Reflective Code Loading", Tactic: "defense-evasion",
		Kinds: []string{"shellcode", "coff", "bof"}},
	{ID: "T1497", Name: "Virtualization/Sandbox Evasion", Tactic: "defense-evasion",
		Kinds: []string{"emulator.detect"}},
	{ID: "T1027", Name: "Obfuscation", Tactic: "defense-evasion",
		Kinds: []string{"evade.profile", "evade.shape", "hygiene.memory", "hygiene.process"}},
	{ID: "T1562", Name: "Impair Defenses", Tactic: "defense-evasion",
		Kinds: []string{"evade.killswitch", "evade.suicide"}},
	{ID: "T1070.004", Name: "Indicator Removal: File Deletion", Tactic: "defense-evasion",
		Kinds: []string{"anti.forensic", "wipe.survey", "wipe.run", "wipe.verify", "wipe.self"}},
	{ID: "T1070.006", Name: "Indicator Removal: Timestomp", Tactic: "defense-evasion",
		Kinds: []string{"touch"}},
	{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access",
		Kinds: []string{"creds"}},
	{ID: "T1552", Name: "Unsecured Credentials", Tactic: "credential-access",
		Kinds: []string{"wifi.profiles"}},
	{ID: "T1555", Name: "Credentials from Password Stores", Tactic: "credential-access",
		Kinds: []string{"browser.creds"}},
	{ID: "T1557", Name: "Adversary-in-the-Middle", Tactic: "credential-access",
		Kinds: []string{"phish.overlay"}},
	{ID: "T1021", Name: "Remote Services", Tactic: "lateral-movement",
		Kinds: []string{"wmi.exec", "smb.exec", "winrm.exec", "dcom.exec",
			"ssh.exec", "ldap.query"}},
	{ID: "T1005", Name: "Data from Local System", Tactic: "collection",
		Kinds: []string{"cat", "download", "tail", "app.dump", "call.logs",
			"sms.dump", "contacts.dump"}},
	{ID: "T1115", Name: "Clipboard Data", Tactic: "collection",
		Kinds: []string{"clipboard", "clipboard.watch", "clipboard.sniff"}},
	{ID: "T1056", Name: "Input Capture", Tactic: "collection",
		Kinds: []string{"keylog", "keylog.file"}},
	{ID: "T1113", Name: "Screen Capture", Tactic: "collection",
		Kinds: []string{"screenshot", "ui.screen", "screen.stream", "live.screen"}},
	{ID: "T1123", Name: "Audio Capture", Tactic: "collection",
		Kinds: []string{"media.mic"}},
	{ID: "T1125", Name: "Video Capture", Tactic: "collection",
		Kinds: []string{"media.camera"}},
	{ID: "T1430", Name: "Location Tracking", Tactic: "collection",
		Kinds: []string{"gps.locate"}},
	{ID: "T1119", Name: "Automated Collection", Tactic: "collection",
		Kinds: []string{"triage", "forensics.report", "forensics.timeline"}},
	{ID: "T1090", Name: "Proxy", Tactic: "command-and-control",
		Kinds: []string{"tunnel", "p2p", "session.open", "session.input", "session.close"}},
	{ID: "T1572", Name: "Protocol Tunneling", Tactic: "command-and-control",
		Kinds: []string{"tunnel"}},
	{ID: "T1105", Name: "Ingress Tool Transfer", Tactic: "command-and-control",
		Kinds: []string{"upload", "update"}},
}

// ignored are the kinds of the server itself: the tripwires, the
// baseline, the hunts and the housekeeping.  They are the tools of the
// watch, not the work of the adversary, and the wall does not count
// them against the catalogue — nor report them as unmapped.
var ignored = map[string]bool{
	"ping":          true,
	"sleep":         true,
	"exit":          true,
	"decommission":  true,
	"wipe.deadman":  true,
	"hunt.scan":     true,
	"canary.plant":  true,
	"canary.check":  true,
	"baseline.look": true,
	"host.guide":    true,
	"evade.report":  true,
	"hygiene.sleep": true,
}

// Usage is how one technique stands after the work the team did: how
// many finished tasks were the work of it, on which hosts, and when
// the last one was.  A technique with no tasks is a door the team has
// not tried, and that is the point of having the wall.
type Usage struct {
	// ID, Name and Tactic name the technique of the catalogue.
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
	// Tasks counts the finished tasks that were the work of it.
	Tasks int `json:"tasks"`
	// Agents are the hosts it was used on, sorted by name.
	Agents []string `json:"agents,omitempty"`
	// Last is when it was used last, zero when never.
	Last time.Time `json:"last,omitempty"`
}

// Coverage walks the finished tasks of the team and counts them
// against the wall.  Only the tasks that came back count: a queued
// intention is not a technique that was used, and a failure is a door
// that stayed closed, so the states are `done` and nothing else.
func Coverage(tasks []*store.Task) []Usage {
	out := make([]Usage, 0, len(Table))
	for _, technique := range Table {
		usage := Usage{ID: technique.ID, Name: technique.Name, Tactic: technique.Tactic}
		hosts := make(map[string]bool)
		for _, t := range tasks {
			if t.State != store.TaskDone {
				continue
			}
			if !has(technique.Kinds, t.Kind) {
				continue
			}
			usage.Tasks++
			if t.AgentID != "" {
				hosts[t.AgentID] = true
			}
			when := t.Completed
			if when.IsZero() {
				when = t.Created
			}
			if when.After(usage.Last) {
				usage.Last = when
			}
		}
		for id := range hosts {
			usage.Agents = append(usage.Agents, id)
		}
		sort.Strings(usage.Agents)
		out = append(out, usage)
	}
	return out
}

// Unmapped returns the kinds of the finished work that are neither on
// the wall nor on the ignored list.  A new task kind that nobody
// taught the wall about shows up here, louder with every engagement,
// until somebody writes it into the table.
func Unmapped(tasks []*store.Task) []string {
	seen := make(map[string]bool)
	for _, t := range tasks {
		if t.State != store.TaskDone || t.Kind == "" {
			continue
		}
		if ignored[t.Kind] {
			continue
		}
		known := false
		for _, technique := range Table {
			if has(technique.Kinds, t.Kind) {
				known = true
				break
			}
		}
		if !known {
			seen[t.Kind] = true
		}
	}
	out := make([]string, 0, len(seen))
	for kind := range seen {
		out = append(out, kind)
	}
	sort.Strings(out)
	return out
}

// Covered counts the techniques the team has used at least once.
func Covered(usages []Usage) int {
	n := 0
	for _, usage := range usages {
		if usage.Tasks > 0 {
			n++
		}
	}
	return n
}

// has reports whether the list names the kind.
func has(kinds []string, kind string) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}
