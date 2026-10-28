// Package armory is the extension registry: a signed catalogue of
// post-exploitation modules that operators can install and run on an agent.
//
// An extension is a blob plus a manifest. The manifest is signed with an
// Ed25519 key and carries the SHA-256 digest of the blob, so the server can
// prove that what it is about to ship to a beacon is exactly what the
// catalogue published. A mirror that rewrites a module breaks the signature
// and the digest, and the install fails loudly instead of pushing modified
// code into a target.
//
// The blobs themselves are executed in memory by the agent (see the `bof` and
// `ext` task kinds): nothing is written to disk on the target.
package armory

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/coff"
)

// Limits. An extension is a module, not a disk image: a couple of megabytes
// is generous, and the cap keeps a hostile catalogue from filling the disk.
const (
	// MaxBlobSize is the largest extension the server accepts.
	MaxBlobSize = 8 << 20
	// MaxFetchSize is the largest download the server accepts.
	MaxFetchSize = 16 << 20
	// MaxCatalogEntries bounds the catalogue.
	MaxCatalogEntries = 512
	// FetchTimeout bounds a catalogue download.
	FetchTimeout = 60 * time.Second
)

// Errors the operator sees.
var (
	ErrNoSuchExtension = errors.New("armory: no such extension")
	ErrNotInstalled    = errors.New("armory: extension is not installed")
	ErrBadSignature    = errors.New("armory: signature verification failed")
	ErrBadDigest       = errors.New("armory: digest mismatch")
	ErrTooLarge        = errors.New("armory: extension is too large")
)

// Manifest describes one extension.
//
// The first block is the legacy catalogue: a name, a version, a platform and
// a digest. The second block is the module ABI (see abi.go): the magic, the
// ABI number, the argument schema, the output schema, the capabilities the
// module needs from the host and the other modules it depends on.
//
// A manifest without the ABI block is a legacy entry. It is still valid and
// still signed, but it says nothing about what it needs, so the server
// treats it as a module that needs nothing.
type Manifest struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	Format      string   `json:"format"`
	SHA256      string   `json:"sha256"`
	Size        int64    `json:"size"`
	Signature   string   `json:"signature"`
	Args        []string `json:"args"`
	Description string   `json:"description"`
	URL         string   `json:"url"`

	// ---- the module ABI ------------------------------------------------
	// Magic opens the manifest and ABI says which dialect it is written
	// in. Both are empty in a legacy catalogue entry.
	Magic string `json:"magic,omitempty"`
	// ABI is the version of the module ABI the manifest is written in.
	ABI int `json:"abi,omitempty"`
	// ArgSchema is the declared argument list of the module.
	ArgSchema []ArgSpec `json:"arg_schema,omitempty"`
	// Output describes what the module answers.
	Output *OutputSpec `json:"output,omitempty"`
	// Caps are the host capabilities the module needs.
	Caps []string `json:"caps,omitempty"`
	// Requires are the other modules the module depends on.
	Requires []string `json:"requires,omitempty"`
}

// signingBytes is the canonical byte string a signature covers.
//
// It is a purpose-built encoding rather than "the JSON of the manifest": the
// fields are written in a fixed order with explicit lengths, so a re-serialiser
// cannot produce a different byte string for the same manifest.
//
// The encoding depends on the ABI the manifest declares, and the ABI is
// inside the signed bytes. A catalogue that is tampered with therefore
// cannot change the dialect of a manifest without breaking the signature:
// dropping the ABI turns the v2 bytes into the v1 bytes, and the signature
// that was made over the v2 bytes no longer verifies.
func (m Manifest) signingBytes() []byte {
	if m.ABI >= ManifestABI {
		return m.signingBytesV2()
	}
	return m.signingBytesLegacy()
}

// signingBytesLegacy is the encoding of a catalogue entry that predates the
// module ABI. It is kept byte for byte: the signatures of the catalogues
// that are already deployed must still verify.
func (m Manifest) signingBytesLegacy() []byte {
	var b strings.Builder
	b.WriteString("umbra/armory/v1\n")
	b.WriteString(m.Name)
	b.WriteByte('\n')
	b.WriteString(m.Version)
	b.WriteByte('\n')
	b.WriteString(m.OS)
	b.WriteByte('\n')
	b.WriteString(m.Arch)
	b.WriteByte('\n')
	b.WriteString(m.Format)
	b.WriteByte('\n')
	b.WriteString(strings.ToLower(m.SHA256))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%d", m.Size)
	b.WriteByte('\n')
	b.WriteString(strings.Join(m.Args, ","))
	b.WriteByte('\n')
	b.WriteString(m.Description)
	return []byte(b.String())
}

// Catalog is the signed list of extensions the server knows about.
type Catalog struct {
	Entries  []Manifest `json:"entries"`
	Updated  time.Time  `json:"updated"`
	Source   string     `json:"source"`
	Verified bool       `json:"verified"`
}

// Extension is an installed extension: its manifest and where the blob is.
type Extension struct {
	Manifest  Manifest   `json:"manifest"`
	Path      string     `json:"path"`
	Installed time.Time  `json:"installed"`
	Bytes     int64      `json:"bytes"`
	// Details describes the blob when the server could read it: a COFF
	// module is summarised here, so the operator sees what it exports
	// before it runs on a target.
	Details string `json:"details,omitempty"`
	// Exports lists the external symbols of an in-memory module.
	Exports []string `json:"exports,omitempty"`
}

// Registry owns the catalogue and the installed extensions.
type Registry struct {
	dir     string
	pub     ed25519.PublicKey
	log     Logger
	mu      sync.RWMutex
	catalog Catalog
	byName  map[string]*Extension
}

// Logger is the minimal logging surface the registry needs.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// Options configures a registry.
type Options struct {
	// Dir is where the catalogue and the blobs live.
	Dir string
	// PublicKeyPath is a PEM file holding the Ed25519 public key that signs
	// the catalogue. An empty path disables signature checking, which the
	// server logs loudly at start-up.
	PublicKeyPath string
	// Log receives operational messages; nil disables logging.
	Log Logger
}

// New opens a registry.
func New(opts Options) (*Registry, error) {
	r := &Registry{
		dir:     opts.Dir,
		log:     opts.Log,
		byName:  make(map[string]*Extension),
		catalog: Catalog{Entries: []Manifest{}},
	}
	if opts.PublicKeyPath != "" {
		raw, err := os.ReadFile(opts.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("armory: read public key: %w", err)
		}
		pub, err := parsePublicKey(raw)
		if err != nil {
			return nil, err
		}
		r.pub = pub
	}
	if r.dir != "" {
		if err := os.MkdirAll(r.dir, 0o700); err != nil {
			return nil, fmt.Errorf("armory: create %s: %w", r.dir, err)
		}
		r.loadInstalled()
		r.loadCatalog()
	}
	return r, nil
}

// parsePublicKey reads an Ed25519 public key in PEM (PKIX) form.
func parsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("armory: the public key file is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("armory: parse public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("armory: the public key is not an Ed25519 key")
	}
	return pub, nil
}

// PublicKey returns the configured verification key (nil when disabled).
func (r *Registry) PublicKey() ed25519.PublicKey { return r.pub }

// Verified reports whether the catalogue signature was checked.
func (r *Registry) Verified() bool { return r.pub != nil }

// Catalog returns the current catalogue.
func (r *Registry) Catalog() Catalog {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.catalog
}

// List returns the installed extensions, sorted by name.
func (r *Registry) List() []Extension {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Extension, 0, len(r.byName))
	for _, ext := range r.byName {
		out = append(out, *ext)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.Name < out[j].Manifest.Name })
	return out
}

// Get returns one installed extension.
func (r *Registry) Get(name string) (*Extension, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ext, ok := r.byName[name]
	if !ok {
		return nil, false
	}
	cp := *ext
	return &cp, true
}

// Verify checks the signature of a manifest.
func (r *Registry) Verify(m Manifest) error {
	if r.pub == nil {
		return nil // signature checking is disabled
	}
	sig, err := hex.DecodeString(strings.TrimSpace(m.Signature))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: wrong signature length", ErrBadSignature)
	}
	if !ed25519.Verify(r.pub, m.signingBytes(), sig) {
		return ErrBadSignature
	}
	return nil
}

// Install stores a blob after checking the manifest signature and the digest.
//
// The blob is written to a temporary file and renamed into place, so a crash
// never leaves a half-written module that would later fail its digest check
// for no obvious reason.
func (r *Registry) Install(m Manifest, blob []byte) (*Extension, error) {
	if m.Name == "" {
		return nil, errors.New("armory: an extension needs a name")
	}
	if len(blob) == 0 {
		return nil, errors.New("armory: the extension blob is empty")
	}
	if len(blob) > MaxBlobSize {
		return nil, ErrTooLarge
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := r.Verify(m); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(blob)
	digest := hex.EncodeToString(sum[:])
	if m.SHA256 != "" && !strings.EqualFold(m.SHA256, digest) {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrBadDigest, m.SHA256, digest)
	}
	m.SHA256 = digest
	m.Size = int64(len(blob))
	if r.dir == "" {
		return nil, errors.New("armory: no armory directory configured")
	}
	// A module that claims to be a COFF object has to be one: the parser
	// is read-only, and an object the loader cannot read is not worth
	// shipping to an implant.
	var details string
	var exports []string
	if isObjectFormat(m.Format) {
		obj, err := coff.Parse(blob)
		if err != nil {
			return nil, fmt.Errorf("armory: %s is not a loadable object: %w", m.Name, err)
		}
		details = obj.Describe()
		exports = obj.Exports()
	}
	if isWebAssemblyFormat(m.Format) {
		if !isWebAssembly(blob) {
			return nil, fmt.Errorf("armory: %s is not a webassembly module", m.Name)
		}
	}
	path := filepath.Join(r.dir, sanitize(m.Name)+".bin")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return nil, fmt.Errorf("armory: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("armory: install %s: %w", m.Name, err)
	}
	ext := &Extension{
		Manifest:  m,
		Path:      path,
		Installed: time.Now().UTC(),
		Bytes:     int64(len(blob)),
		Details:   details,
		Exports:   exports,
	}
	r.mu.Lock()
	r.byName[m.Name] = ext
	r.mu.Unlock()
	if r.log != nil {
		r.log.Info("armory extension installed", "name", m.Name, "bytes", len(blob))
	}
	cp := *ext
	return &cp, nil
}

// Validate checks that the server understands the manifest.
//
// A manifest with a magic this server does not know, or an ABI from the
// future, is refused: the fields the operator would read are not the fields
// the module was built with, and pushing it would be a guess.
func (m Manifest) Validate() error {
	if m.Magic != "" && m.Magic != ManifestMagic {
		return fmt.Errorf("armory: %s has a manifest of another kind: %s", m.Name, m.Magic)
	}
	if m.ABI > ManifestABI {
		return fmt.Errorf("armory: %s speaks the module ABI %d, this server speaks %d",
			m.Name, m.ABI, ManifestABI)
	}
	for _, arg := range m.Schema() {
		switch arg.Type {
		case ArgString, ArgInt, ArgBool, ArgBytes:
		case "":
			return fmt.Errorf("armory: %s declares the argument %s without a type", m.Name, arg.Name)
		default:
			return fmt.Errorf("armory: %s declares the argument %s of the unknown type %s",
				m.Name, arg.Name, arg.Type)
		}
	}
	return nil
}

// InstallFrom installs an extension from the catalogue, fetching the blob if
// it is not cached yet.
func (r *Registry) InstallFrom(name string) (*Extension, error) {
	return r.InstallVersion(name, "")
}

// blob returns the extension bytes, downloading them when needed.
func (r *Registry) blob(m *Manifest) ([]byte, error) {
	if r.dir != "" {
		path := filepath.Join(r.dir, sanitize(m.Name)+".bin")
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
			return raw, nil
		}
	}
	if m.URL == "" {
		return nil, fmt.Errorf("armory: %s has no cached blob and no url", m.Name)
	}
	if !strings.HasPrefix(m.URL, "https://") {
		return nil, fmt.Errorf("armory: %s must be fetched over https", m.Name)
	}
	client := &http.Client{Timeout: FetchTimeout}
	resp, err := client.Get(m.URL)
	if err != nil {
		return nil, fmt.Errorf("armory: fetch %s: %w", m.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("armory: fetch %s: HTTP %d", m.URL, resp.StatusCode)
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, MaxFetchSize+1))
	if err != nil {
		return nil, fmt.Errorf("armory: read %s: %w", m.URL, err)
	}
	if len(blob) > MaxFetchSize {
		return nil, ErrTooLarge
	}
	return blob, nil
}

// Remove deletes an installed extension.
func (r *Registry) Remove(name string) error {
	r.mu.Lock()
	ext, ok := r.byName[name]
	if ok {
		delete(r.byName, name)
	}
	r.mu.Unlock()
	if !ok {
		return ErrNotInstalled
	}
	if ext.Path != "" {
		_ = os.Remove(ext.Path)
	}
	return nil
}

// LoadCatalog reads the catalogue from disk and verifies every entry.
func (r *Registry) LoadCatalog(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("armory: read catalogue: %w", err)
	}
	var cat Catalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return fmt.Errorf("armory: parse catalogue: %w", err)
	}
	if len(cat.Entries) > MaxCatalogEntries {
		return errors.New("armory: the catalogue is too large")
	}
	for _, m := range cat.Entries {
		if err := r.Verify(m); err != nil {
			return fmt.Errorf("armory: catalogue entry %q: %w", m.Name, err)
		}
	}
	r.mu.Lock()
	r.catalog = cat
	r.catalog.Verified = r.pub != nil
	r.mu.Unlock()
	return nil
}

// loadCatalog reads the default catalogue file, ignoring a missing one.
func (r *Registry) loadCatalog() {
	if r.dir == "" {
		return
	}
	path := filepath.Join(r.dir, "catalog.json")
	if _, err := os.Stat(path); err != nil {
		return
	}
	if err := r.LoadCatalog(path); err != nil && r.log != nil {
		r.log.Warn("armory catalogue rejected", "err", err)
	}
}

// loadInstalled re-reads the blobs that are already on disk.
func (r *Registry) loadInstalled() {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".bin")
		path := filepath.Join(r.dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		r.byName[name] = &Extension{
			Manifest: Manifest{
				Name:   name,
				SHA256: hex.EncodeToString(sum[:]),
				Size:   int64(len(raw)),
			},
			Path:      path,
			Installed: time.Now().UTC(),
			Bytes:     int64(len(raw)),
		}
	}
}

// isObjectFormat reports whether a manifest describes an in-memory object the
// server can parse before it hands it to an implant.
func isObjectFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "coff", "bof", "beacon-object-file", "object":
		return true
	}
	return false
}

// isWebAssemblyFormat reports whether a manifest describes a webassembly
// module. The server checks the magic before it installs one: a module that
// claims to be webassembly and is not would fail on the target, where the
// failure is much harder to read.
func isWebAssemblyFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "wasm", "webassembly":
		return true
	}
	return false
}

// isWebAssembly reports whether the blob is a webassembly module.
//
// The magic is four bytes: "\0asm" followed by the version 1.
func isWebAssembly(blob []byte) bool {
	return len(blob) >= 8 && string(blob[:4]) == "\x00asm" && blob[4] == 1
}

// sanitize keeps an extension name usable as a file name.
func sanitize(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "extension"
	}
	return string(out)
}
