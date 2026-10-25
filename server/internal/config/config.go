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
)

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

	PSKFile       string   `json:"psk_file"`
	AgentPSK      string   `json:"agent_psk_env"`      // env var that holds the agent PSK
	OperatorToken []string `json:"operator_token_env"` // env vars holding "name:token" pairs

	DataFile string `json:"data_file"`
	LogLevel string `json:"log_level"`

	Beacon         Beacon `json:"beacon"`
	Limits         Limits `json:"limits"`
	MaxClockSkewS  int    `json:"max_clock_skew_s"`
	SessionTimeout int    `json:"session_timeout_s"`
}

// Keyring is the set of pre-shared keys the server accepts.
type Keyring struct {
	AgentPSK []byte
	// Operators maps operator identity -> raw token bytes.
	Operators map[string][]byte
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
		DataFile:        "data/state.json",
		LogLevel:        "info",
		Beacon:          Beacon{Sleep: 5, Jitter: 20},
		Limits:          Limits{MaxAgents: 512, MaxOperators: 16, HandshakeTimeoutSec: 15, IdleTimeoutSec: 120, MaxFrameBytesPerConn: 64 << 20},
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

	agentPSK := os.Getenv(c.Server.AgentPSK)
	if agentPSK == "" && c.Server.PSKFile != "" {
		if raw, err := os.ReadFile(c.Server.PSKFile); err == nil {
			agentPSK = strings.TrimSpace(string(raw))
		}
	}
	if agentPSK != "" {
		c.Keyring.AgentPSK = []byte(agentPSK)
	}

	for _, envName := range c.Server.OperatorToken {
		raw := os.Getenv(envName)
		for _, pair := range strings.Split(raw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name, token, ok := strings.Cut(pair, ":")
			if !ok || name == "" || token == "" {
				return fmt.Errorf("config: %s entry %q must be name:token", envName, pair)
			}
			c.Keyring.Operators[name] = []byte(token)
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
func (c *Config) MaxSkew() time.Duration {
	return time.Duration(c.Server.MaxClockSkewS) * time.Second
}
