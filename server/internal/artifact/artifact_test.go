package artifact

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheStoreKeepsTheFilesInTheClearWithoutAKey(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if store.Encrypted() {
		t.Fatal("the store claims to be encrypted")
	}
	if _, err := store.Put("note.txt", []byte("hello")); err != nil {
		t.Fatalf("put: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "blobs",
		entryDigest(t, store, "note.txt")+".bin"))
	if err != nil {
		t.Fatalf("read the blob: %v", err)
	}
	if !bytes.Contains(raw, []byte("hello")) {
		t.Fatal("the blob is not in the clear")
	}
}

func TestTheStoreIsSealedWhenAKeyIsGiven(t *testing.T) {
	dir := t.TempDir()
	key := []byte("the artifact key of the operator")
	store, err := OpenEncrypted(dir, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !store.Encrypted() {
		t.Fatal("the store is not encrypted")
	}
	secret := []byte("the contents of the artifact")
	if _, err := store.Put("secret.bin", secret); err != nil {
		t.Fatalf("put: %v", err)
	}
	// The bytes on disk are not the bytes the operator stored.
	raw, err := os.ReadFile(filepath.Join(dir, "blobs",
		entryDigest(t, store, "secret.bin")+".bin"))
	if err != nil {
		t.Fatalf("read the blob: %v", err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("the blob is in the clear on the disk")
	}
	if !bytes.HasPrefix(raw, []byte(envelope)) {
		t.Fatalf("the blob does not carry the envelope: %q", raw[:4])
	}
	// The store gives the contents back.
	back, _, err := store.Read("secret.bin")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(back, secret) {
		t.Fatal("the contents came back different")
	}
}

func TestTheStoreRefusesTheWrongKey(t *testing.T) {
	dir := t.TempDir()
	key := []byte("the artifact key of the operator")
	store, err := OpenEncrypted(dir, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := store.Put("secret.bin", []byte("the contents")); err != nil {
		t.Fatalf("put: %v", err)
	}
	// The store refuses to open with another key: it does not pretend to
	// be empty and it does not hand out garbage.
	if _, err := OpenEncrypted(dir, []byte("another key entirely")); err == nil {
		t.Fatal("the store opened with the wrong key")
	} else if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("the error is not the wrong-key error: %v", err)
	}
	if !strings.Contains(err.Error(), "key") {
		t.Fatalf("the error does not mention the key: %v", err)
	}
	// And a store without a key refuses to open a sealed one: it does not
	// pretend to be empty.
	if _, err := Open(dir); err == nil {
		t.Fatal("a sealed store was opened without a key")
	}
}

func TestTheIndexIsSealedAsWell(t *testing.T) {
	dir := t.TempDir()
	key := []byte("the artifact key of the operator")
	store, err := OpenEncrypted(dir, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := store.Put("secret.bin", []byte("the contents")); err != nil {
		t.Fatalf("put: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("read the index: %v", err)
	}
	if bytes.Contains(raw, []byte("secret.bin")) {
		t.Fatal("the index is in the clear on the disk")
	}
}

// entryDigest returns the digest of an artifact in the store.
func entryDigest(t *testing.T, store *Store, name string) string {
	t.Helper()
	entry, ok := store.Get(name)
	if !ok {
		t.Fatalf("no artifact called %q", name)
	}
	return entry.SHA256
}
