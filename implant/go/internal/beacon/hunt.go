package beacon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The hunt: the indicators of the team, looked for on this host.
//
// A wipe takes the traces of the engagement away; a hunt looks for the
// traces of somebody else.  The team keeps a catalogue of indicators --
// a hash, a path, a mutex, a registry key, a process -- and asks every
// host of the fleet whether it carries one of them.
//
// The rules of the module are the rules of the engagement:
//
//   - the hunt never changes the host.  It reads, it reports, and the
//     operator decides what to do with what it found;
//   - an indicator is matched exactly.  A "possible match" is a
//     finding the operator cannot act on;
//   - a limit is reported as a limit.  The hash of a file is expensive
//     to compute, so the number of files that are hashed is bounded,
//     and the report says so when the bound is reached.
//
// The kinds of indicator the module understands:
//
//	hash        the SHA-256 of a file
//	path        a path on the disk of the host
//	process     the name of a process
//	service     the name of a system service
//	mutex       the name of a mutex (Windows)
//	registry    a key of the registry (Windows)
//	certificate a thumbprint of the certificate store (Windows)
//
// The last three are Windows concepts.  On the other platforms the
// report says that the kind does not apply to the machine, instead of
// pretending that the host was checked.
const (
	// huntMaxHashedFiles bounds the work of one hunt.
	huntMaxHashedFiles = 20000
	// huntMaxHashedBytes bounds the bytes one hunt reads.
	huntMaxHashedBytes = 256 << 20
	// huntMaxDepth bounds the depth of the walk.
	huntMaxDepth = 24
	// huntMaxVisited bounds the files one hunt visits.
	huntMaxVisited = 200000
)

// huntIndicator is one indicator of the catalogue.
type huntIndicator struct {
	ID    string
	Kind  string
	Value string
	Label string
}

// huntFinding is one indicator that is on this host.
type huntFinding struct {
	ID    string
	Kind  string
	Value string
	Label string
	Place string
	Note  string
}

// huntReport is the result of one hunt.
type huntReport struct {
	findings []huntFinding
	skipped  []string
	limits   []string
	visited  uint64
	hashed   uint64
	bytes    uint64
	roots    []string
}

// huntIndicators reads the indicators of a task.
//
// The server sends the catalogue the operator chose and nothing else.
func huntIndicators(args map[string]any) []huntIndicator {
	raw, _ := args["indicators"].([]any)
	out := make([]huntIndicator, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		value := strings.TrimSpace(strOr(entry, "value", ""))
		if value == "" {
			continue
		}
		out = append(out, huntIndicator{
			ID:    strOr(entry, "id", ""),
			Kind:  strings.ToLower(strOr(entry, "kind", "")),
			Value: value,
			Label: strOr(entry, "label", ""),
		})
	}
	return out
}

// huntRoots returns the roots the hunt walks.
//
// Without a root the hunt looks in the home of the user, in the
// temporary directory and in the working directory of the implant.  The
// whole of the disk is a decision the operator has to make explicitly.
func huntRoots(args map[string]any) []string {
	out := make([]string, 0, 4)
	seen := func(p string) bool {
		if p == "" {
			return false
		}
		for _, existing := range out {
			if existing == p {
				return true
			}
		}
		return false
	}
	if raw, ok := args["roots"].([]any); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok {
				root := strings.TrimSpace(s)
				if root != "" && !seen(root) {
					out = append(out, root)
				}
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	if home, err := os.UserHomeDir(); err == nil && !seen(home) {
		out = append(out, home)
	}
	if tmp := os.TempDir(); !seen(tmp) {
		out = append(out, tmp)
	}
	if cwd, err := os.Getwd(); err == nil && !seen(cwd) {
		out = append(out, cwd)
	}
	return out
}

// taskHuntScan looks for the indicators of the team on this host.
func (b *Beacon) taskHuntScan(args map[string]any) Outcome {
	items := huntIndicators(args)
	if len(items) == 0 {
		return Outcome{Code: 1, Err: "hunt.scan: the hunt has no indicators"}
	}
	report := huntReport{roots: huntRoots(args)}

	// The paths and the processes are cheap, so they are checked first.
	for _, ind := range items {
		switch ind.Kind {
		case "path":
			huntCheckPath(&report, ind)
		case "process":
			huntCheckProcess(&report, ind)
		case "service":
			huntCheckService(&report, ind)
		case "mutex", "registry", "certificate":
			report.skipped = append(report.skipped,
				fmt.Sprintf("  skipped    %-10s the kind %q is a concept of windows",
					ind.ID, ind.Kind))
		case "hash":
			// The hashes are checked in the walk below.
		default:
			report.skipped = append(report.skipped,
				fmt.Sprintf("  skipped    %-10s the kind %q is not one this implant knows",
					ind.ID, ind.Kind))
		}
	}

	// The hashes are the expensive ones.
	var hashes []huntIndicator
	for _, ind := range items {
		if ind.Kind == "hash" {
			hashes = append(hashes, ind)
		}
	}
	if len(hashes) > 0 {
		for _, root := range report.roots {
			huntWalk(root, 0, hashes, &report)
			if len(report.limits) > 0 {
				break
			}
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "hunt.scan: %d indicators, %d found on this host\n",
		len(items), len(report.findings))
	for _, f := range report.findings {
		label := ""
		if f.Label != "" {
			label = fmt.Sprintf(" (%s)", f.Label)
		}
		fmt.Fprintf(&sb, "  %-10s %-40s %s%s\n", f.Kind, f.Value, f.Place, label)
		if f.Note != "" {
			fmt.Fprintf(&sb, "             %s\n", f.Note)
		}
	}
	for _, line := range report.skipped {
		sb.WriteString(line + "\n")
	}
	for _, limit := range report.limits {
		fmt.Fprintf(&sb, "  limit      %s\n", limit)
	}
	fmt.Fprintf(&sb, "hunt.scan: %d files visited, %d hashed, %d bytes read\n",
		report.visited, report.hashed, report.bytes)

	extra := map[string]any{
		"hunt_found":   len(report.findings),
		"hunt_visited": report.visited,
		"hunt_hashed":  report.hashed,
		"hunt_bytes":   report.bytes,
	}
	if len(report.skipped) > 0 {
		extra["hunt_skipped"] = report.skipped
	}
	if len(report.limits) > 0 {
		extra["hunt_limits"] = report.limits
	}
	return Outcome{Code: 0, Out: []byte(sb.String()), Extra: extra}
}

// huntCheckPath checks a path indicator.
func huntCheckPath(report *huntReport, ind huntIndicator) {
	info, err := os.Stat(ind.Value)
	if err != nil {
		return
	}
	note := "the path is a file of this host"
	if info.IsDir() {
		note = "the path is a directory of this host"
	}
	report.findings = append(report.findings, huntFinding{
		ID:    ind.ID,
		Kind:  ind.Kind,
		Value: ind.Value,
		Label: ind.Label,
		Place: ind.Value,
		Note:  fmt.Sprintf("%s, %d bytes", note, info.Size()),
	})
}

// huntCheckProcess checks a process indicator.
//
// The table of the processes is read through the shell, because the Go
// implant is deliberately small and the platform knows the answer.
func huntCheckProcess(report *huntReport, ind huntIndicator) {
	text, err := runSenses("ps -eo pid=,comm= 2>/dev/null")
	if err != nil {
		report.limits = append(report.limits,
			"the process table of this host could not be read")
		return
	}
	needle := strings.ToLower(ind.Value)
	for _, line := range nonEmptyLines(text) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToLower(fields[len(fields)-1])
		if name != needle && !strings.HasSuffix(name, "/"+needle) {
			continue
		}
		report.findings = append(report.findings, huntFinding{
			ID:    ind.ID,
			Kind:  ind.Kind,
			Value: ind.Value,
			Label: ind.Label,
			Place: fmt.Sprintf("pid %s (%s)", fields[0], name),
			Note:  fmt.Sprintf("the process %s is running on this host", name),
		})
	}
}

// huntCheckService checks a service indicator.
//
// The unit files of systemd are read on Linux; on the other platforms
// the kind is reported as one that does not apply.
func huntCheckService(report *huntReport, ind huntIndicator) {
	if runtime.GOOS != "linux" {
		report.skipped = append(report.skipped,
			fmt.Sprintf("  skipped    %-10s the kind \"service\" is looked for in the units of systemd, and this host does not have them",
				ind.ID))
		return
	}
	name := strings.TrimSuffix(ind.Value, ".service")
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/run/systemd/system"} {
		candidate := filepath.Join(dir, name+".service")
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		report.findings = append(report.findings, huntFinding{
			ID:    ind.ID,
			Kind:  ind.Kind,
			Value: ind.Value,
			Label: ind.Label,
			Place: candidate,
			Note:  "the service is installed on this host",
		})
		return
	}
	report.skipped = append(report.skipped,
		fmt.Sprintf("  skipped    %-10s the service is not installed on this host", ind.ID))
}

// huntWalk walks a tree and hashes the files, looking for the hashes.
func huntWalk(dir string, depth int, hashes []huntIndicator, report *huntReport) {
	if depth > huntMaxDepth {
		report.limits = append(report.limits,
			fmt.Sprintf("the tree below %s is deeper than %d levels", dir, huntMaxDepth))
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if entry.IsDir() {
			huntWalk(path, depth+1, hashes, report)
			if len(report.limits) > 0 {
				return
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		report.visited++
		if report.visited > huntMaxVisited {
			report.limits = append(report.limits,
				fmt.Sprintf("the hunt stopped after %d files", huntMaxVisited))
			return
		}
		if report.hashed >= huntMaxHashedFiles {
			report.limits = append(report.limits,
				fmt.Sprintf("the hunt hashed %d files and stopped", huntMaxHashedFiles))
			return
		}
		if report.bytes+uint64(info.Size()) > huntMaxHashedBytes {
			report.limits = append(report.limits,
				fmt.Sprintf("the hunt hashed %d bytes and stopped", huntMaxHashedBytes))
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		report.hashed++
		report.bytes += uint64(len(data))
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		for _, ind := range hashes {
			if !strings.EqualFold(ind.Value, digest) {
				continue
			}
			report.findings = append(report.findings, huntFinding{
				ID:    ind.ID,
				Kind:  ind.Kind,
				Value: ind.Value,
				Label: ind.Label,
				Place: path,
				Note:  fmt.Sprintf("the file carries the hash, %d bytes", len(data)),
			})
		}
	}
}
