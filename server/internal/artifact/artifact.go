// Package artifact is the team server's file store.
//
// The armory holds modules, this holds files: the operator drops a binary, a
// configuration or a payload on the server once and then pushes it to every
// agent that needs it, instead of uploading the same bytes again for every
// host.
//
// A stored artifact is a blob plus an entry in the index. The blob is
// content addressed: it is written under the SHA-256 of its contents, so two
// uploads of the same file share one copy on disk, and the digest travels
// with the entry so a console can prove what it is holding.
//
// Uploads are chunked. The operator frames are bounded (the wire carries at
// most a megabyte per frame), so a large file arrives as a series of
// appends; the store keeps the partial upload in memory until the operator
// says the last chunk is the last one, and only then the blob is written and
// the digest is computed.
package artifact

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Limits. The store is a working area for an operator, not a backup system.
const (
	// MaxArtifactSize is the largest artifact the server accepts.
	MaxArtifactSize = 256 << 20
	// MaxChunkSize is the largest single append the server accepts. It is
	// well below the frame budget, so a chunk always fits in one RPC.
	MaxChunkSize = 256 << 10
	// MaxIndexEntries bounds the index.
	MaxIndexEntries = 4096
	// MaxNameLength bounds an artifact name.
	MaxNameLength = 200
)

// Errors the operator sees.
var (
	ErrNoSuchArtifact = errors.New("artifact: no such artifact")
	ErrTooLarge       = errors.New("artifact: artifact is too large")
	ErrBadChunk       = errors.New("artifact: chunk does not fit")
	ErrOffset         = errors.New("artifact: chunk is out of order")
	ErrBadName        = errors.New("artifact: bad name")
	ErrStoreFull      = errors.New("artifact: the store is full")
	// ErrWrongKey is what a store says when the key does not fit the
	// data.  It is a refusal, not a guess: the store would rather say
	// nothing than hand out garbage.
	ErrWrongKey = errors.New("artifact: the key does not open this store")
)

// envelope is the magic that starts every encrypted blob.
//
// A file that does not start with it is either a plain store or somebody
// else's file, and both are refused rather than misread.
const envelope = "UMB1"

// nonceSize is the size of the nonce of the envelope.
const nonceSize = 12

// Entry describes one stored artifact.
type Entry struct {
	// Name is the operator's label for the artifact ("mimikatz.dll").
	Name string `json:"name"`
	// SHA256 is the digest of the contents, and the name of the blob on disk.
	SHA256 string `json:"sha256"`
	// Size is the length of the contents in bytes.
	Size int64 `json:"size"`
	// Created is when the artifact entered the store.
	Created time.Time `json:"created"`
	// Updated is when the artifact was last replaced.
	Updated time.Time `json:"updated"`
}

// index is the on-disk manifest of the store.
type index struct {
	Version   int     `json:"version"`
	Updated   string  `json:"updated"`
	Artifacts []Entry `json:"artifacts"`
}

// upload is an artifact that is still being written.
type upload struct {
	name string
	buf  []byte
}

// Store keeps artifacts on disk.
//
// The store can keep its blobs in the clear or sealed with a key.  When a
// key is set, every blob is written as an authenticated envelope: the
// bytes are encrypted with AES-256-GCM under a key derived from the
// configured one, and a blob that does not authenticate is refused.  A
// wrong key never returns garbage: it returns an error.
type Store struct {
	dir string

	// key is the seal key, empty when the store is in the clear.
	key []byte
	// aead is the cipher built from the key.
	aead cipher.AEAD

	mu      sync.RWMutex
	entries map[string]Entry
	pending map[string]*upload
}

// Open opens (and creates) a store rooted at dir.
//
// The store keeps its files in the clear; use OpenEncrypted when the
// operator asked for the files to be sealed.
func Open(dir string) (*Store, error) {
	return openStore(dir, nil)
}

// OpenEncrypted opens a store whose blobs are sealed with key.
//
// The key is the one from the configuration.  It is stretched into a
// 256-bit key with SHA-256, which is what the server does with the vault
// key as well: one passphrase, one derivation, no ambiguity.
func OpenEncrypted(dir string, key []byte) (*Store, error) {
	if len(key) == 0 {
		return nil, errors.New("artifact: no key")
	}
	return openStore(dir, key)
}

// openStore opens a store, optionally sealed.
func openStore(dir string, key []byte) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("artifact: no directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("artifact: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, "blobs"), 0o750); err != nil {
		return nil, fmt.Errorf("artifact: %w", err)
	}
	s := &Store{
		dir:     abs,
		entries: make(map[string]Entry),
		pending: make(map[string]*upload),
	}
	if len(key) > 0 {
		derived := sha256.Sum256(key)
		block, err := aes.NewCipher(derived[:])
		if err != nil {
			return nil, fmt.Errorf("artifact: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("artifact: %w", err)
		}
		s.key = append([]byte(nil), derived[:]...)
		s.aead = aead
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Encrypted reports whether the store seals its blobs.
func (s *Store) Encrypted() bool { return s != nil && s.aead != nil }

// Dir returns the directory the store lives in.
func (s *Store) Dir() string { return s.dir }

// load reads the index from disk.
//
// A missing or broken index is not fatal for a store in the clear: the
// store starts empty and the blobs on disk stay where they are.  A sealed
// store is different: if the index is there and the key does not open it,
// the store refuses to open at all.  A store that cannot be read must not
// pretend it is empty.
func (s *Store) load() error {
	raw, err := os.ReadFile(s.indexPath())
	if err != nil {
		return nil
	}
	if s.aead != nil {
		plain, err := s.open(raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrWrongKey, err)
		}
		raw = plain
	} else if bytes.HasPrefix(raw, []byte(envelope)) {
		// The index is sealed and this store has no key: refusing is the
		// only honest answer.
		return fmt.Errorf("%w: the index is sealed", ErrWrongKey)
	}
	var idx index
	if err := json.Unmarshal(raw, &idx); err != nil {
		if s.aead != nil {
			return fmt.Errorf("artifact: the index is broken: %w", err)
		}
		return nil
	}
	for _, e := range idx.Artifacts {
		if e.Name == "" || e.SHA256 == "" {
			continue
		}
		s.entries[e.Name] = e
	}
	return nil
}

// save writes the index. The caller holds the lock.
func (s *Store) save() {
	idx := index{Version: 1, Updated: time.Now().UTC().Format(time.RFC3339)}
	names := make([]string, 0, len(s.entries))
	for name := range s.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		idx.Artifacts = append(idx.Artifacts, s.entries[name])
	}
	raw, err := json.MarshalIndent(&idx, "", "  ")
	if err != nil {
		return
	}
	if s.aead != nil {
		raw, err = s.seal(raw)
		if err != nil {
			return
		}
	}
	tmp := s.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return
	}
	_ = os.Rename(tmp, s.indexPath())
}

// seal encrypts bytes into the envelope.
func (s *Store) seal(plain []byte) ([]byte, error) {
	if s.aead == nil {
		return plain, nil
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("artifact: no randomness: %w", err)
	}
	out := make([]byte, 0, len(envelope)+len(nonce)+len(plain)+16)
	out = append(out, envelope...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plain, nil), nil
}

// open decrypts an envelope.
//
// A blob that does not authenticate is refused: the caller gets an error,
// never the bytes it thinks it decrypted.
func (s *Store) open(sealed []byte) ([]byte, error) {
	if s.aead == nil {
		return sealed, nil
	}
	if len(sealed) < len(envelope)+nonceSize+16 {
		return nil, ErrWrongKey
	}
	if string(sealed[:len(envelope)]) != envelope {
		return nil, fmt.Errorf("%w: the file is not a sealed artifact", ErrWrongKey)
	}
	nonce := sealed[len(envelope) : len(envelope)+nonceSize]
	body := sealed[len(envelope)+nonceSize:]
	plain, err := s.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, ErrWrongKey
	}
	return plain, nil
}

func (s *Store) indexPath() string { return filepath.Join(s.dir, "index.json") }

func (s *Store) blobPath(digest string) string {
	return filepath.Join(s.dir, "blobs", digest+".bin")
}

// List returns every stored artifact, sorted by name.
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the entry for a name.
func (s *Store) Get(name string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[name]
	return e, ok
}

// Read returns the contents of an artifact.
func (s *Store) Read(name string) ([]byte, Entry, error) {
	s.mu.RLock()
	e, ok := s.entries[name]
	s.mu.RUnlock()
	if !ok {
		return nil, Entry{}, ErrNoSuchArtifact
	}
	raw, err := os.ReadFile(s.blobPath(e.SHA256))
	if err != nil {
		return nil, Entry{}, fmt.Errorf("artifact: %w", err)
	}
	if s.aead != nil {
		plain, err := s.open(raw)
		if err != nil {
			return nil, Entry{}, err
		}
		raw = plain
	} else if bytes.HasPrefix(raw, []byte(envelope)) {
		return nil, Entry{}, fmt.Errorf("%w: the blob is sealed", ErrWrongKey)
	}
	return raw, e, nil
}

// ReadRange returns a slice of an artifact, for a chunked download.
func (s *Store) ReadRange(name string, offset, limit int64) ([]byte, Entry, error) {
	raw, e, err := s.Read(name)
	if err != nil {
		return nil, Entry{}, err
	}
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(raw)) {
		offset = int64(len(raw))
	}
	end := int64(len(raw))
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return raw[offset:end], e, nil
}

// Put stores a whole artifact in one go.
func (s *Store) Put(name string, data []byte) (Entry, error) {
	if err := s.checkName(name); err != nil {
		return Entry{}, err
	}
	if int64(len(data)) > MaxArtifactSize {
		return Entry{}, ErrTooLarge
	}
	digest := sha256.Sum256(data)
	hexed := hex.EncodeToString(digest[:])
	if err := s.writeBlob(hexed, data); err != nil {
		return Entry{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[name]; !ok && len(s.entries) >= MaxIndexEntries {
		return Entry{}, ErrStoreFull
	}
	now := time.Now().UTC()
	entry := Entry{Name: name, SHA256: hexed, Size: int64(len(data)), Created: now, Updated: now}
	if old, ok := s.entries[name]; ok {
		entry.Created = old.Created
	}
	s.entries[name] = entry
	s.save()
	return entry, nil
}

// Begin starts (or restarts) a chunked upload.
func (s *Store) Begin(name string) error {
	if err := s.checkName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[name] = &upload{name: name}
	return nil
}

// Append adds a chunk to a chunked upload.
//
// The chunk has to arrive at the offset the store expects: a lost or
// duplicated chunk would otherwise be written into the middle of the file
// and the digest would no longer match what the operator uploaded.
func (s *Store) Append(name string, offset int64, data []byte) (int, error) {
	if err := s.checkName(name); err != nil {
		return 0, err
	}
	if int64(len(data)) > MaxChunkSize {
		return 0, ErrBadChunk
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	up, ok := s.pending[name]
	if !ok {
		if _, exists := s.entries[name]; exists {
			// A finished artifact is replaced from the start.
			up = &upload{name: name}
			s.pending[name] = up
		} else {
			return 0, fmt.Errorf("artifact: %w", ErrOffset)
		}
	}
	if offset != int64(len(up.buf)) {
		return 0, fmt.Errorf("artifact: %w", ErrOffset)
	}
	if int64(len(up.buf)+len(data)) > MaxArtifactSize {
		return 0, ErrTooLarge
	}
	up.buf = append(up.buf, data...)
	return len(up.buf), nil
}

// Finish closes a chunked upload and writes the blob.
func (s *Store) Finish(name string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	up, ok := s.pending[name]
	if !ok {
		return Entry{}, fmt.Errorf("artifact: %w", ErrNoSuchArtifact)
	}
	data := up.buf
	delete(s.pending, name)
	if int64(len(data)) > MaxArtifactSize {
		return Entry{}, ErrTooLarge
	}
	digest := sha256.Sum256(data)
	hexed := hex.EncodeToString(digest[:])
	if err := s.writeBlob(hexed, data); err != nil {
		return Entry{}, err
	}
	if _, ok := s.entries[name]; !ok && len(s.entries) >= MaxIndexEntries {
		return Entry{}, ErrStoreFull
	}
	now := time.Now().UTC()
	entry := Entry{Name: name, SHA256: hexed, Size: int64(len(data)), Created: now, Updated: now}
	if old, ok := s.entries[name]; ok {
		entry.Created = old.Created
	}
	s.entries[name] = entry
	s.save()
	return entry, nil
}

// Abort drops a partial upload.
func (s *Store) Abort(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, name)
}

// Pending reports how many bytes of a chunked upload have arrived.
func (s *Store) Pending(name string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if up, ok := s.pending[name]; ok {
		return len(up.buf)
	}
	return 0
}

// Remove deletes an artifact.
//
// The blob is only deleted when no other entry points at it: the same
// contents uploaded under two names are stored once.
func (s *Store) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[name]
	if !ok {
		return ErrNoSuchArtifact
	}
	delete(s.entries, name)
	delete(s.pending, name)
	stillUsed := false
	for _, e := range s.entries {
		if e.SHA256 == entry.SHA256 {
			stillUsed = true
			break
		}
	}
	if !stillUsed {
		_ = os.Remove(s.blobPath(entry.SHA256))
	}
	s.save()
	return nil
}

// writeBlob stores the bytes under their digest.
//
// The write goes to a temporary file first: a half-written blob that is
// renamed into place would be indistinguishable from a good one.
func (s *Store) writeBlob(digest string, data []byte) error {
	path := s.blobPath(digest)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if s.aead != nil {
		sealed, err := s.seal(data)
		if err != nil {
			return err
		}
		data = sealed
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("artifact: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("artifact: %w", err)
	}
	return nil
}

// checkName rejects a name that cannot be used as a store key.
func (s *Store) checkName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrBadName
	}
	if len(name) > MaxNameLength {
		return ErrBadName
	}
	if strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
		return ErrBadName
	}
	return nil
}

// Wipe removes every artifact and every pending upload.
func (s *Store) Wipe() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.entries {
		entry := s.entries[name]
		_ = os.Remove(s.blobPath(entry.SHA256))
	}
	s.entries = make(map[string]Entry)
	s.pending = make(map[string]*upload)
	s.save()
	return nil
}
