package beacon

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Process is one line of the process table.
type Process struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Name string `json:"name"`
	Args string `json:"args"`
}

// Inventory describes the host the implant runs on.
//
// Every field is read from the system the implant runs on; nothing here
// is guessed, and a field the system does not expose is left out
// instead of being filled with a plausible value.
func Inventory() map[string]any {
	inv := map[string]any{
		"os":     osName(),
		"arch":   archName(),
		"cpus":   uint64(runtime.NumCPU()),
		"pid":    uint64(os.Getpid()),
		"ppid":   uint64(os.Getppid()),
		"go":     runtime.Version(),
		"iver":   Version,
		"agent":  "go",
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		inv["host"] = host
	}
	if name := currentUser(); name != "" {
		inv["user"] = name
	}
	if uid := os.Getuid(); uid >= 0 {
		inv["uid"] = uint64(uid)
	}
	if gid := os.Getgid(); gid >= 0 {
		inv["gid"] = uint64(gid)
	}
	if exe, err := os.Executable(); err == nil {
		inv["exe"] = exe
	}
	if wd, err := os.Getwd(); err == nil {
		inv["cwd"] = wd
	}
	if tmp := os.TempDir(); tmp != "" {
		inv["tmp"] = tmp
	}
	if release := kernelRelease(); release != "" {
		inv["kernel"] = release
	}
	if boot := bootTime(); boot > 0 {
		inv["boot"] = boot
	}
	return inv
}

// NetworkInfo describes the network of the host.
func NetworkInfo() map[string]any {
	ifaces, err := net.Interfaces()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	list := make([]map[string]any, 0, len(ifaces))
	for _, iface := range ifaces {
		entry := map[string]any{
			"name":  iface.Name,
			"index": uint64(iface.Index),
			"mtu":   uint64(iface.MTU),
			"up":    iface.Flags&net.FlagUp != 0,
			"loop":  iface.Flags&net.FlagLoopback != 0,
		}
		if mac := iface.HardwareAddr.String(); mac != "" {
			entry["mac"] = mac
		}
		if addrs, err := iface.Addrs(); err == nil {
			names := make([]string, 0, len(addrs))
			for _, addr := range addrs {
				names = append(names, addr.String())
			}
			entry["addresses"] = names
		}
		list = append(list, entry)
	}
	return map[string]any{"interfaces": list, "count": uint64(len(list))}
}

// processList is the table of the processes of the host.
//
// The process table is not part of the standard library, so it is read
// from the one the system exposes: /proc on Linux.  On the systems that
// do not expose one, the implant reports what it knows about itself and
// says where the table would have to come from, so the operator is never
// shown a list that looks complete but is not.
func processList() ([]Process, string, string) {
	if runtime.GOOS == "linux" {
		procs, err := linuxProcesses()
		if err != nil {
			return nil, "proc", err.Error()
		}
		return procs, "proc", ""
	}
	self := Process{PID: os.Getpid(), PPID: os.Getppid(), Name: filepath.Base(os.Args[0])}
	if len(os.Args) > 1 {
		self.Args = strings.Join(os.Args[1:], " ")
	}
	return []Process{self}, "self", "this host does not expose the process table to the standard library"
}

// linuxProcesses reads the process table from /proc.
func linuxProcesses() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]Process, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		line := string(raw)
		open := strings.Index(line, "(")
		closed := strings.LastIndex(line, ")")
		if open < 0 || closed < open {
			continue
		}
		proc := Process{PID: pid, Name: line[open+1 : closed]}
		fields := strings.Fields(line[closed+1:])
		if len(fields) > 1 {
			proc.PPID, _ = strconv.Atoi(fields[1])
		}
		if data, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline"); err == nil {
			proc.Args = strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
		}
		out = append(out, proc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

// osName is the name of the operating system.
func osName() string { return runtime.GOOS }

// archName is the name of the architecture.
func archName() string { return runtime.GOARCH }

// currentUser is the name of the user the implant runs as.
func currentUser() string {
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	for _, key := range []string{"USER", "LOGNAME", "USERNAME"} {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

// kernelRelease is the release of the kernel of the host.
func kernelRelease() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// bootTime is the moment the host came up, in seconds since the epoch.
//
// The moment comes out of the statistics of the kernel, so it is the
// moment the kernel booted and not the moment the clock was last read.
func bootTime() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
		if err != nil {
			return 0
		}
		return value
	}
	return 0
}

// readLimited reads at most limit bytes of a file.
func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	buf := make([]byte, 0, 64<<10)
	if _, err := io.Copy(&buf, io.LimitReader(file, limit)); err != nil {
		return nil, err
	}
	return buf, nil
}

// lookupHost resolves a name with the resolver of the host.
func lookupHost(name string) ([]string, error) {
	addrs, err := net.LookupHost(name)
	if err != nil {
		return nil, err
	}
	sort.Strings(addrs)
	return addrs, nil
}

// jsonBytes encodes a value as indented JSON.
func jsonBytes(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// errUnsupported is the error of a task that this implant cannot do.
var errUnsupported = errors.New("this implant does not support that")
