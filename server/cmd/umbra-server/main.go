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
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/alias"
	"github.com/thesyntax1/UmbraC2/server/internal/armory"
	"github.com/thesyntax1/UmbraC2/server/internal/artifact"
	"github.com/thesyntax1/UmbraC2/server/internal/approval"
	"github.com/thesyntax1/UmbraC2/server/internal/audit"
	"github.com/thesyntax1/UmbraC2/server/internal/canary"
	"github.com/thesyntax1/UmbraC2/server/internal/casefile"
	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/dash"
	"github.com/thesyntax1/UmbraC2/server/internal/dnstun"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/hunt"
	"github.com/thesyntax1/UmbraC2/server/internal/link"
	"github.com/thesyntax1/UmbraC2/server/internal/mtls"
	"github.com/thesyntax1/UmbraC2/server/internal/pivot"
	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
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
		cfgPath   = flag.String("config", "", "path to the JSON configuration file")
		agentAddr = flag.String("listen-agent", "", "override server.agent_listen")
		opAddr    = flag.String("listen-operator", "", "override server.operator_listen")
		httpAddr  = flag.String("listen-http", "", "override server.http_listen (\"\" disables HTTP)")
		dataPath  = flag.String("data", "", "override server.data_file")
		logLevel  = flag.String("log-level", "", "debug|info|warn|error")
		genPSK    = flag.Bool("gen-psk", false, "print a fresh 32-byte agent PSK and exit")
		genToken  = flag.Bool("gen-token", false, "print a fresh 32-byte operator token and exit")
		genConfig = flag.Bool("gen-config", false, "print the default configuration as JSON and exit")
	genSPKI  = flag.String("gen-spki", "", "print the pinned public key of a certificate and exit")
		printVer  = flag.Bool("version", false, "print the version and exit")
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
	case *genSPKI != "":
		// The pinned public key of a certificate: what the operator
		// writes into the configuration of the server and into the
		// command line of the console.
		fingerprint, err := mtls.SPKIOfFile(*genSPKI)
		if err != nil {
			return err
		}
		fmt.Println(fingerprint)
		return nil
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
	pivotMgr.SetDeny(pivotDenyRules(cfg.Server.PivotDeny))
	// The peer link is authenticated with the agent key: the beacons of
	// one team already share it.
	pivotMgr.SetPSK(cfg.Keyring.AgentPSK)
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

	// The server-side file store: the operator drops a file here once and
	// pushes it to every host that needs it.  It lives next to the state
	// file, so a deployment that already gives the server a writable data
	// directory needs no extra setup.
	//
	// The store is sealed when the configuration gives a key: the files
	// the operator stored on the server are then encrypted at rest, and
	// a store that cannot be opened with the key refuses to open at all.
	artifactStore, err := openArtifactStore(cfg)
	if err != nil {
		return err
	}
	srv.SetArtifact(artifactStore)
	logger.Info("artifact store ready", "dir", artifactStore.Dir(), "encrypted", artifactStore.Encrypted())

	// The runtime command namespace: named task templates.  The built-in
	// ones are the one-liners everybody types; the team can replace them.
	//
	// The namespace is shared, so it lives next to the state file: the
	// template one operator wrote has to be there for the next one.
	aliases := alias.NewWithDefaults()
	aliases.SetPath(aliasPath(cfg.Server.DataFile))
	if err := aliases.Load(); err != nil {
		logger.Warn("the command namespace could not be read", "err", err)
	}
	srv.SetAliases(aliases)

	// The catalogue of the indicators the team hunts with.  It is
	// shared by the team and it outlives the engagement: an indicator
	// that was found once is worth checking everywhere, so the
	// catalogue lives next to the state file.
	huntCatalogue := hunt.New()
	huntCatalogue.SetPath(huntPath(cfg.Server.DataFile))
	if err := huntCatalogue.Load(); err != nil {
		logger.Warn("the indicator catalogue could not be read", "err", err)
	}
	srv.SetHunt(huntCatalogue)

	// The evidence files: the cases the operator hands over when the
	// engagement ends.  The chain of custody of every case lives here.
	caseRegistry := casefile.New()
	caseRegistry.SetPath(casePath(cfg.Server.DataFile))
	if err := caseRegistry.Load(); err != nil {
		logger.Warn("the case registry could not be read", "err", err)
	}
	srv.SetCases(caseRegistry)

	// The two-person rule: the queue of the requests that wait for a
	// second pair of eyes.  The queue is shared by the team, so it
	// lives next to the state file: a request one operator wrote has
	// to be there for the operator who decides it.
	approvals := approval.New()
	approvals.SetPath(approvalPath(cfg.Server.DataFile))
	if err := approvals.Load(); err != nil {
		logger.Warn("the queue of approvals could not be read", "err", err)
	}
	srv.SetApprovals(approvals)

	// The tripwires: the canaries the team planted on the hosts.  The
	// ledger outlives the engagement, so it lives next to the state
	// file as well.
	canaries := canary.New()
	canaries.SetPath(canaryPath(cfg.Server.DataFile))
	if err := canaries.Load(); err != nil {
		logger.Warn("the ledger of the canaries could not be read", "err", err)
	}
	srv.SetCanaries(canaries)

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
			ClientCN:          cfg.Server.TLSClientCN,
			ClientSPKI:        cfg.Server.TLSClientSPKI,
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

	// The mail transport: the beacon mails its frames to the SMTP listener
	// and fetches the answer from its mailbox with POP3.  It is the
	// transport for a network where the mail server is the only thing
	// that gets through.
	if cfg.Server.SMTPListen != "" {
		mailSrv := link.NewMailServer(srv, cfg.Keyring.AgentPSK, cfg.Server.MailDomain)
		if err := mailSrv.Start(ctx, cfg.Server.SMTPListen, cfg.Server.POP3Listen); err != nil {
			return err
		}
		logger.Info("mail transport enabled",
			"smtp", cfg.Server.SMTPListen, "pop3", cfg.Server.POP3Listen)
	}

	// The object transport: the beacon reads its work from one bucket and
	// writes its results into another.
	if cfg.Server.S3Listen != "" {
		s3Srv := link.NewS3Server(srv, cfg.Keyring.AgentPSK, cfg.Server.S3Region)
		s3Srv.TasksBucket = cfg.Server.S3TasksBucket
		s3Srv.ResultsBucket = cfg.Server.S3ResultsBucket
		if err := s3Srv.Start(ctx, cfg.Server.S3Listen); err != nil {
			return err
		}
		defer func() { s3Srv.Close() }()
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
				// The dashboard draws the pivots, so it needs the
				// picture of the reach.
				Topology: func() any { return pivotMgr.Topology() },
				// The dashboard runs the operator commands with the
				// role of the operator it belongs to.
				Role:     dashboardRole(cfg),
				Dispatch: srv.DispatchOperator,
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

	// The queue of the two-person rule is swept every minute: a request
	// that nobody decided goes stale on its own, and the ledger on the
	// disk says so even when nobody opens the queue.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if n := approvals.Expire(); n > 0 {
					if err := approvals.Save(); err != nil {
						logger.Warn("the queue of approvals could not be saved", "err", err)
					}
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

// dashboardRole is the role the dashboard runs the operator commands with.
//
// The dashboard uses the token of the first operator, so it runs with the
// role of that operator: a viewer token on the dashboard is a viewer
// everywhere, and the role table is checked by the server.
func dashboardRole(cfg *config.Config) string {
	for name := range cfg.Keyring.Operators {
		if len(cfg.Keyring.Operators[name]) > 0 {
			return cfg.Keyring.Role(name)
		}
	}
	return rbac.Viewer
}

// openArtifactStore opens the artifact store, sealed when the
// configuration asks for it.
func openArtifactStore(cfg *config.Config) (*artifact.Store, error) {
	dir := artifactDir(cfg.Server.DataFile)
	key := strings.TrimSpace(cfg.Server.ArtifactKey)
	if key == "" {
		return artifact.Open(dir)
	}
	return artifact.OpenEncrypted(dir, []byte(key))
}

// artifactDir is where the server-side file store lives.
//
// The store sits next to the state file: a deployment already gives the
// server a writable data directory for the queue, and the artifacts belong
// to the same engagement record.
// aliasPath is where the shared command namespace is kept.
func aliasPath(dataFile string) string {
	if dataFile == "" {
		return filepath.Join("data", "aliases.json")
	}
	return filepath.Join(filepath.Dir(dataFile), "aliases.json")
}

func artifactDir(dataFile string) string {
	if dataFile == "" {
		return filepath.Join("data", "artifacts")
	}
	return filepath.Join(filepath.Dir(dataFile), "artifacts")
}

// huntPath is where the catalogue of the indicators is kept.
//
// The catalogue is shared by the team and it outlives the engagement,
// so it sits next to the state file and not inside it: wiping the
// engagement must not throw away the indicators of last week.
func huntPath(dataFile string) string {
	if dataFile == "" {
		return filepath.Join("data", "hunt.json")
	}
	return filepath.Join(filepath.Dir(dataFile), "hunt.json")
}

// casePath is where the evidence files are kept.
//
// The cases are the record of the engagement: they have to survive the
// wipe of the engagement and the restart of the server.
func casePath(dataFile string) string {
	if dataFile == "" {
		return filepath.Join("data", "cases.json")
	}
	return filepath.Join(filepath.Dir(dataFile), "cases.json")
}

// approvalPath is where the queue of the two-person rule is kept.
//
// The queue belongs to the team and not to one operator: the request
// one operator wrote has to be there for the operator who decides it,
// even after a restart of the server.
func approvalPath(dataFile string) string {
	if dataFile == "" {
		return filepath.Join("data", "approval.json")
	}
	return filepath.Join(filepath.Dir(dataFile), "approval.json")
}

// canaryPath is where the ledger of the tripwires is kept.
//
// The ledger outlives the engagement: a canary that was planted last
// week is still a canary, and the operator who comes back after the
// weekend has to find it.
func canaryPath(dataFile string) string {
	if dataFile == "" {
		return filepath.Join("data", "canary.json")
	}
	return filepath.Join(filepath.Dir(dataFile), "canary.json")
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
			tun, err := mgr.Open(cfg.Server.SocksAgent, pivot.Options{
				Mode:     pivot.ModeSOCKS,
				Listen:   cfg.Server.SocksListen,
				User:     cfg.Server.SocksUser,
				Password: cfg.Server.SocksPassword,
			})
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

// pivotDenyRules reads the deny list of the configuration.
//
// An entry is "host" or "host:port".  A host without a port refuses every
// port of it; a port of zero in the rule means the same.
func pivotDenyRules(entries []string) []pivot.DenyRule {
	out := make([]pivot.DenyRule, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, port := entry, 0
		if h, p, err := net.SplitHostPort(entry); err == nil {
			host = h
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
		out = append(out, pivot.DenyRule{Host: host, Port: port})
	}
	return out
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
