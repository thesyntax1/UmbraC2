// Command umbra-server is the UmbraC2 team server: an asynchronous,
// multi-agent C2 backend that speaks the umbra/v1 protocol over TCP and HTTP.
//
// Quick start (development):
//
//	export UMBRA_AGENT_PSK=$(umbra-server -gen-psk)
//	export UMBRA_OPERATOR_TOKENS="operator1:$(umbra-server -gen-token)"
//	umbra-server -config deploy/server.dev.json
//
// See docs/OPERATIONS.md for production deployment.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/link"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "umbra-server: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		cfgPath    = flag.String("config", "", "path to the JSON configuration file")
		agentAddr  = flag.String("listen-agent", "", "override server.agent_listen")
		opAddr     = flag.String("listen-operator", "", "override server.operator_listen")
		httpAddr   = flag.String("listen-http", "", "override server.http_listen (\"\" disables HTTP)")
		dataPath   = flag.String("data", "", "override server.data_file")
		logLevel   = flag.String("log-level", "", "debug|info|warn|error")
		genPSK     = flag.Bool("gen-psk", false, "print a fresh 32-byte agent PSK and exit")
		genToken   = flag.Bool("gen-token", false, "print a fresh 32-byte operator token and exit")
		genConfig  = flag.Bool("gen-config", false, "print the default configuration as JSON and exit")
		printVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	switch {
	case *printVer:
		fmt.Printf("umbra-server %s (protocol umbra/v1)\n", hub.Version)
		return nil
	case *genPSK, *genToken:
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(b))
		return nil
	case *genConfig:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(config.Default().Server)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	applyOverrides(cfg, *agentAddr, *opAddr, *httpAddr, *dataPath, *logLevel)

	logger := newLogger(cfg.Server.LogLevel)
	slog.SetDefault(logger)

	st, err := store.Open(cfg.Server.DataFile)
	if err != nil {
		return err
	}
	h := hub.New(cfg, st, logger)
	srv := link.New(cfg, h, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		return err
	}
	logFingerprints(logger, cfg)
	logger.Warn("this build is for authorised lab use only")

	// Persist state periodically so a crash loses at most a few seconds.
	persist := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := st.Save(); err != nil {
					logger.Warn("state save failed", "err", err)
				}
			case <-persist:
				return
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Info("shutting down")
	cancel()
	close(persist)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Warn("shutdown", "err", err)
	}
	if err := st.Save(); err != nil {
		logger.Warn("final state save failed", "err", err)
	}
	logger.Info("stopped")
	return nil
}

func applyOverrides(cfg *config.Config, agentAddr, opAddr, httpAddr, dataPath, logLevel string) {
	if agentAddr != "" {
		cfg.Server.AgentListen = agentAddr
	}
	if opAddr != "" {
		cfg.Server.OperatorListen = opAddr
	}
	if httpAddr != "" {
		cfg.Server.HTTPListen = httpAddr
	}
	if dataPath != "" {
		cfg.Server.DataFile = dataPath
	}
	if logLevel != "" {
		cfg.Server.LogLevel = logLevel
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func logFingerprints(logger *slog.Logger, cfg *config.Config) {
	fp := cfg.TokenHashes()
	names := make([]string, 0, len(fp))
	for n := range fp {
		names = append(names, n)
	}
	for _, n := range names {
		// Only fingerprints are ever logged, never the tokens themselves.
		logger.Info("operator token loaded", "operator", n, "sha256_prefix", fp[n])
	}
	if cfg.Server.DataFile != "" {
		if abs, err := filepath.Abs(cfg.Server.DataFile); err == nil {
			logger.Info("state file", "path", abs)
		}
	}
}
