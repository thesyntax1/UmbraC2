package beacon

// The baseline of a host: the paths the team watches and what the last
// look saw of them.
//
// A hunt looks for the indicators of somebody else.  A baseline asks a
// different question: is this host the host we saw yesterday?  The
// team names the paths that matter -- the configuration of the service,
// the script that starts it, the key that opens it -- and the implant
// reads each of them and reports the size, the time of the last change
// and the digest.
//
// The rules are the same as everywhere else:
//
//   - the baseline only reads.  A baseline that rewrote the file it
//     watches would destroy the very thing it is watching;
//   - what is not there is a finding.  A path that is gone is reported
//     as gone, because "no file" is what the team wanted to be told;
//   - the findings travel with the answer.  The snapshots travel in the
//     metadata of the answer as one short JSON string, so the ledger of
//     the server and the answer the operator reads cannot disagree.
//
// The look is signed like every other report of the engagement: a look
// that goes into the evidence file has to be provable.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// taskBaselineLook looks at the paths the server named and says what
// is there.
func (b *Beacon) taskBaselineLook(args map[string]any) Outcome {
	paths := baselineWanted(args)
	if len(paths) == 0 {
		return Outcome{Code: 1, Err: "baseline.look: no path was named"}
	}
	snaps := make([]baselineSnapshot, 0, len(paths))
	lines := make([]string, 0, len(paths))
	gone := int64(0)
	for _, path := range paths {
		snap := baselineSnap(path)
		var note string
		if snap.Exists {
			note = fmt.Sprintf("%d bytes, digest %s", snap.Size, snap.SHA256)
		} else {
			gone++
			note = "the file is gone"
		}
		lines = append(lines, fmt.Sprintf("  %-48s %s", path, stateWord(snap.Exists)))
		lines = append(lines, fmt.Sprintf("    %s", note))
		snaps = append(snaps, snap)
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(
		"baseline.look: %d paths looked at, %d of them are gone\n",
		len(paths), gone))
	for _, line := range lines {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	raw, err := json.Marshal(snaps)
	if err != nil {
		return Outcome{Code: 1, Err: fmt.Sprintf("baseline.look: %v", err)}
	}
	return Outcome{
		Code: 0,
		Out:  []byte(sb.String()),
		Extra: map[string]any{
			"baseline_snaps":   string(raw),
			"baseline_looked":  int64(len(snaps)),
			"baseline_missing": gone,
		},
	}
}

// snapshot is one look at one path.
type baselineSnapshot struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
	SHA256  string `json:"sha256,omitempty"`
	Exists  bool   `json:"exists"`
}

// baselineWanted reads the paths the server asked about.
func baselineWanted(args map[string]any) []string {
	out := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	if raw, ok := args["paths"].([]any); ok {
		for _, item := range raw {
			path := ""
			if s, ok := item.(string); ok {
				path = strings.TrimSpace(s)
			}
			if path != "" {
				if _, dup := seen[path]; !dup {
					seen[path] = struct{}{}
					out = append(out, path)
				}
			}
		}
	}
	// A single string of paths, one per line: a console that does not
	// carry a list can still name the paths.
	if len(out) == 0 {
		if raw, ok := args["paths"].(string); ok {
			for _, line := range strings.Split(raw, "\n") {
				path := strings.TrimSpace(line)
				if path != "" {
					if _, dup := seen[path]; !dup {
						seen[path] = struct{}{}
						out = append(out, path)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// stateWord is the word of the operator's table.
func stateWord(exists bool) string {
	if exists {
		return "present"
	}
	return "missing"
}

// baselineSnap is one look at one path, from the disk of the implant.
func baselineSnap(path string) baselineSnapshot {
	info, err := os.Stat(path)
	if err != nil {
		return baselineSnapshot{Path: path, Exists: false}
	}
	mtime := info.ModTime().Unix()
	data, err := os.ReadFile(path)
	if err != nil {
		return baselineSnapshot{
			Path:    path,
			Size:    info.Size(),
			ModTime: mtime,
			SHA256:  "",
			Exists:  false,
		}
	}
	sum := sha256.Sum256(data)
	return baselineSnapshot{
		Path:    path,
		Size:    info.Size(),
		ModTime: mtime,
		SHA256:  hex.EncodeToString(sum[:]),
		Exists:  true,
	}
}
