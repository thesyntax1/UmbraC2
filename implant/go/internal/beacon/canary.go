package beacon

// The tripwires of the engagement: small files that nobody touches.
//
// A canary is a small file with a secret in it.  The implant plants it
// in a place where nothing of the engagement belongs, and nobody knows
// that it is there -- so nobody touches it.  When the file changes or
// disappears, somebody else was on the host, and the operator learns
// about it while the engagement is still running.
//
// The rules of the module are three:
//
//   - the implant remembers what it planted.  The size, the time of
//     the last change and the digest of the file are written next to
//     the canary, because the implant is the only one that knows what
//     it wrote;
//   - the check never changes the host.  It reads the file and says
//     whether it is as it was planted; a check that repairs the canary
//     would hide the very thing it is looking for;
//   - the verdict travels with the answer.  The states of the canaries
//     travel in the metadata of the answer as one short string
//     ("c-0001=intact;c-0002=changed"), so the ledger of the server
//     and the answer the operator reads cannot disagree.
//
// The states are the three a tripwire can be in:
//
//	intact   the file is as it was planted
//	changed  the file was touched
//	missing  the file is gone
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// canaryStateIntact is a canary that is as it was planted.
	canaryStateIntact = "intact"
	// canaryStateChanged is a canary that was touched.
	canaryStateChanged = "changed"
	// canaryStateMissing is a canary that is gone.
	canaryStateMissing = "missing"
	// canaryStateDir is where the canaries and their facts are kept.
	canaryStateDir = "canaries"
)

// canaryFacts are the facts of one canary: what the implant wrote and
// where it wrote it.
type canaryFacts struct {
	ID     string
	Path   string
	Size   uint64
	Mtime  int64
	SHA256 string
}

// taskCanaryPlant plants one canary on this host.
//
// The file carries the token of the canary and nothing else.  The facts
// of it are written next to it, so the check knows what to compare
// against.
func (b *Beacon) taskCanaryPlant(args map[string]any) Outcome {
	id := strings.TrimSpace(strOr(args, "id", ""))
	if id == "" {
		return Outcome{Code: 1, Err: "canary.plant: the canary has no id"}
	}
	token := strings.TrimSpace(strOr(args, "token", ""))
	if token == "" {
		return Outcome{Code: 1, Err: "canary.plant: the canary has no token"}
	}
	dir := filepath.Join(forensicStateDir(), canaryStateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Outcome{Code: 1, Err: fmt.Sprintf("canary.plant: %s: %v", dir, err)}
	}
	// The operator may name the place of the canary; without a name the
	// canary goes into the state of the implant, which is a place where
	// nothing of the engagement belongs.
	path := strings.TrimSpace(strOr(args, "path", ""))
	if path == "" {
		path = filepath.Join(dir, id+".dat")
	}
	if parent := filepath.Dir(path); parent != "" {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return Outcome{Code: 1, Err: fmt.Sprintf("canary.plant: %s: %v", parent, err)}
		}
	}
	data := []byte(token)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return Outcome{Code: 1, Err: fmt.Sprintf("canary.plant: %s: %v", path, err)}
	}
	info, err := os.Stat(path)
	if err != nil {
		return Outcome{Code: 1, Err: fmt.Sprintf("canary.plant: %s: %v", path, err)}
	}
	sum := sha256.Sum256(data)
	facts := canaryFacts{
		ID:     id,
		Path:   path,
		Size:   uint64(len(data)),
		Mtime:  info.ModTime().Unix(),
		SHA256: hex.EncodeToString(sum[:]),
	}
	if err := writeCanaryFacts(dir, facts); err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	label := strOr(args, "label", "")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("canary.plant: %s is planted\n", id))
	if label != "" {
		sb.WriteString(fmt.Sprintf("  the label is %s\n", label))
	}
	sb.WriteString(fmt.Sprintf("  the file is %s\n", path))
	sb.WriteString(fmt.Sprintf("  %d bytes, written at %d, digest %s\n",
		facts.Size, facts.Mtime, facts.SHA256))
	return Outcome{
		Code: 0,
		Out:  []byte(sb.String()),
		Extra: map[string]any{
			"canary_planted": int64(1),
			"canary_id":      facts.ID,
			"canary_path":    facts.Path,
		},
	}
}

// taskCanaryCheck looks at the canaries of this host and says whether
// they are as they were planted.
//
// The check reads and reads only.
func (b *Beacon) taskCanaryCheck(args map[string]any) Outcome {
	ids := canaryWanted(args)
	if len(ids) == 0 {
		return Outcome{Code: 1, Err: "canary.check: no canary was named"}
	}
	dir := filepath.Join(forensicStateDir(), canaryStateDir)
	states := make([]string, 0, len(ids))
	lines := make([]string, 0, len(ids))
	touched := int64(0)
	for _, id := range ids {
		state, note := canaryLook(dir, id)
		if state == canaryStateChanged || state == canaryStateMissing {
			touched++
		}
		states = append(states, fmt.Sprintf("%s=%s:%s", id, state, note))
		lines = append(lines, fmt.Sprintf("  %-10s %-8s %s", id, state, note))
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(
		"canary.check: %d canaries looked at, %d of them are not as they were\n",
		len(ids), touched))
	for _, line := range lines {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return Outcome{
		Code: 0,
		Out:  []byte(sb.String()),
		Extra: map[string]any{
			"canary_states":  strings.Join(states, ";"),
			"canary_checked": int64(len(ids)),
			"canary_touched": touched,
		},
	}
}

// canaryWanted reads the canaries the server asked about.
func canaryWanted(args map[string]any) []string {
	out := make([]string, 0, 4)
	items, _ := args["canaries"].([]any)
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := strings.TrimSpace(strOr(entry, "id", ""))
		if id == "" {
			continue
		}
		seen := false
		for _, existing := range out {
			if existing == id {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		out = append(out, id)
	}
	return out
}

// canaryLook looks at one canary and says what state it is in.
func canaryLook(dir, id string) (string, string) {
	facts, ok := readCanaryFacts(dir, id)
	if !ok {
		return canaryStateMissing, "the implant does not know this canary"
	}
	info, err := os.Stat(facts.Path)
	if err != nil {
		return canaryStateMissing, "the file of the canary is gone"
	}
	if uint64(info.Size()) != facts.Size {
		return canaryStateChanged, fmt.Sprintf("the file of the canary is %d bytes now", info.Size())
	}
	data, err := os.ReadFile(facts.Path)
	if err != nil {
		return canaryStateMissing, "the file of the canary could not be read"
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != facts.SHA256 {
		return canaryStateChanged, "the file of the canary was touched"
	}
	// The content is the same.  The time of the last change is not part
	// of the verdict, but it is worth saying: a file that was written
	// again with the same content was written again.
	if mtime := info.ModTime().Unix(); mtime != facts.Mtime {
		return canaryStateIntact, fmt.Sprintf(
			"the file is as it was planted but it was written again at %d", mtime)
	}
	return canaryStateIntact, "the file is as it was planted"
}

// writeCanaryFacts writes the facts of one canary.
func writeCanaryFacts(dir string, facts canaryFacts) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("id=%s\n", facts.ID))
	sb.WriteString(fmt.Sprintf("path=%s\n", facts.Path))
	sb.WriteString(fmt.Sprintf("size=%d\n", facts.Size))
	sb.WriteString(fmt.Sprintf("mtime=%d\n", facts.Mtime))
	sb.WriteString(fmt.Sprintf("sha256=%s\n", facts.SHA256))
	path := filepath.Join(dir, facts.ID+".state")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("canary: write %s: %v", path, err)
	}
	return nil
}

// readCanaryFacts reads the facts of one canary.
func readCanaryFacts(dir, id string) (canaryFacts, bool) {
	facts := canaryFacts{ID: id}
	raw, err := os.ReadFile(filepath.Join(dir, id+".state"))
	if err != nil {
		return facts, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "id":
			facts.ID = value
		case "path":
			facts.Path = value
		case "size":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				n = 0
			}
			facts.Size = n
		case "mtime":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				n = 0
			}
			facts.Mtime = n
		case "sha256":
			facts.SHA256 = value
		}
	}
	if facts.Path == "" {
		return facts, false
	}
	return facts, true
}
