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
	"sort"
	"syscall"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/alias"
	"github.com/thesyntax1/UmbraC2/server/internal/armory"
	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/dash"
	"github.com/thesyntax1/UmbraC2/server/internal/dnstun"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/link"
	"github.com/thesyntax1/UmbraC2/server/internal/mtls"
	"github.com/thesyntax1/UmbraC2/server/internal/pivot"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/vpn"
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
	if st.Recovered() {
		// Falling back to the previous generation means the last few seconds of
		// state are gone; say so instead of pretending the load was clean.
		logger.Warn("state recovered from the backup generation",
			"path", cfg.Server.DataFile+".bak",
			"note", "recent tasks or claims may be missing")
	}
	// Background saves must not fail silently: losing the queue is invisible
	// to operators until they restart.
	st.SetSaveErrorHandler(func(err error) {
		logger.Warn("background state save failed", "err", err)
	})
	h := hub.New(cfg, st, logger)
	srv := link.New(cfg, h, logger)

	// Pivoting: agent callback sessions, SOCKS5 proxies and port forwards.
	// The manager is always created, but it only opens a session when an
	// operator asks for a tunnel.
	pivotMgr := pivot.New(h, logger)
	srv.SetPivot(pivotMgr)

	// Extensions: a signed catalogue of post-exploitation modules.
	armoryReg, err := armory.New(armory.Options{
		Dir:           cfg.Server.ArmoryDir,
		PublicKeyPath: cfg.Server.ArmoryKey,
		Log:           logger,
	})
	if err != nil {
		return err
	}
	srv.SetArmory(armoryReg)
	if armoryReg.PublicKey() == nil {
		logger.Warn("armory signature checking is disabled: no armory_key configured")
	}

	// The runtime command namespace: named task templates.  The built-in
	// ones are the one-liners everybody types; the team can replace them.
	srv.SetAliases(alias.NewWithDefaults())

	// The layer-3 tunnel between the console and the beacons.
	if cfg.Server.VPNListen != "" {
		vpnSrv, err := vpn.New(vpn.Config{
			Listen:       cfg.Server.VPNListen,
			Network:      cfg.Server.VPNNetwork,
			AgentKeys:    [][]byte{cfg.Keyring.AgentPSK},
			OperatorKeys: operatorKeys(cfg),
		}, logger)
		if err != nil {
			return err
		}
		if err := vpnSrv.Start(); err != nil {
			return err
		}
		srv.SetVPN(vpnSrv)
		defer func() { _ = vpnSrv.Close() }()
	}

	// The DNS tunnel: the fallback for networks where nothing else gets
	// through.  It only answers for its own domain.
	if cfg.Server.DNSListen != "" {
		dnsSrv := dnstun.New(dnstun.Config{
			Listen: cfg.Server.DNSListen,
			Domain: cfg.Server.DNSDomain,
		}, logger)
		if err := dnsSrv.Start(); err != nil {
			return err
		}
		srv.SetDNS(dnsSrv)
		defer func() { _ = dnsSrv.Close() }()
	}

	// The mutual TLS listener.  A peer has to present a certificate that the
	// client CA signed, so a stolen token alone is not enough to take over an
	// operation.
	if cfg.Server.TLSListen != "" {
		tlsSrv, err := mtls.Load(mtls.Options{
			CertFile:          cfg.Server.TLSCert,
			KeyFile:           cfg.Server.TLSKey,
			ClientCAFile:      cfg.Server.TLSClientCA,
			RequireClientCert: true,
			MinVersion:        "1.3",
		})
		if err != nil {
			return err
		}
		srv.SetTLS(tlsSrv.Config)
		logger.Info("mutual TLS listener enabled",
			"cert", cfg.Server.TLSCert,
			"client_ca", cfg.Server.TLSClientCA)
	}

	auditLog, err := audit.Open(audit.Options{
		Path:     cfg.Server.AuditFile,
		MaxBytes: int64(cfg.Server.AuditMaxSizeMB) << 20,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := auditLog.Close(); err != nil {
			logger.Warn("audit close", "err", err)
		}
	}()
	srv.SetAudit(auditLog)
	if auditLog.Enabled() {
		logger.Info("operator audit log enabled", "file", auditLog.Path())
	} else {
		logger.Warn("operator audit log disabled (audit_file is empty)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		return err
	}

	// The operator's web dashboard: the inventory, the tasks and the event
	// stream on a second screen.  It accepts the operator tokens, so it is
	// as protected as the console, and it can be told to be read-only.
	if cfg.Server.DashboardListen != "" {
		token := firstOperatorToken(cfg)
		if token == "" {
			logger.Warn("the dashboard is disabled: no operator token is configured")
		} else {
			dashSrv := dash.New(dash.Config{
				Listen:   cfg.Server.DashboardListen,
				Token:    token,
				ReadOnly: cfg.Server.DashboardReadOnly,
			}, h, logger)
			go func() {
				if err := dashSrv.Serve(ctx); err != nil {
					logger.Error("the dashboard stopped", "error", err)
				}
			}()
		}
	}

	// A persistent SOCKS5 proxy is opened as soon as its agent is reachable.
	// The agent may only come online later, so the loop keeps trying until it
	// succeeds and then keeps the tunnel alive.
	if cfg.Server.SocksListen != "" {
		go keepSocksOpen(ctx, pivotMgr, cfg, logger)
	}
	// Recurring tasks are driven from the hub, so they survive restarts (the
	// schedule lives in the store) and fire regardless of which transport the
	// agent uses.
	h.StartScheduler(ctx)
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
	pivotMgr.CloseAll()
	if err := st.Flush(); err != nil {
		logger.Warn("final state save failed", "err", err)
	}
	logger.Info("stopped")
	return nil
}

// firstOperatorToken returns the token of the first operator.
//
// The dashboard uses one token: the one of the first operator in the
// keyring.  A deployment that wants a token of its own can give the
// dashboard the token of a dedicated operator identity.
func firstOperatorToken(cfg *config.Config) string {
	names := make([]string, 0, len(cfg.Keyring.Operators))
	for name := range cfg.Keyring.Operators {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(cfg.Keyring.Operators[name]) > 0 {
			return string(cfg.Keyring.Operators[name])
		}
	}
	return ""
}

// operatorKeys returns every operator token as a tunnel credential.
func operatorKeys(cfg *config.Config) [][]byte {
	out := make([][]byte, 0, len(cfg.Keyring.Operators))
	for _, tok := range cfg.Keyring.Operators {
		if len(tok) > 0 {
			out = append(out, tok)
		}
	}
	return out
}

// keepSocksOpen maintains the configured persistent SOCKS5 proxy.
//
// The proxy is a single tunnel: when the agent goes away the tunnel dies
// with it, so the loop re-opens it. It never opens a second tunnel while one
// is alive, otherwise every retry would leak a listener.
func keepSocksOpen(ctx context.Context, mgr *pivot.Manager, cfg *config.Config, logger *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if !socksOpen(mgr, cfg.Server.SocksListen) {
			tun, err := mgr.Open(cfg.Server.SocksAgent, pivot.ModeSOCKS, "", 0, cfg.Server.SocksListen)
			if err != nil {
				logger.Debug("persistent socks proxy not open yet", "err", err)
			} else {
				logger.Info("persistent socks proxy open", "listen", tun.Listen, "agent", tun.AgentID)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// socksOpen reports whether the persistent proxy is already listening.
func socksOpen(mgr *pivot.Manager, listen string) bool {
	for _, tun := range mgr.List() {
		if tun.Mode == pivot.ModeSOCKS && tun.Listen == listen {
			return true
		}
	}
	return false
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
