package armory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The catalogue: the list of modules the server is willing to install, plus
// the tools an operator needs to make sense of it.
//
// A catalogue is more than a list of names. It holds several versions of the
// same module, it holds modules that depend on each other, and it holds the
// declaration of what each module needs from the host. The functions in this
// file turn that into the four questions an operator actually asks:
//
//	"which module do I want?"      -> Search
//	"which versions are there?"     -> Versions
//	"what does this thing need?"    -> Needs
//	"what has to be installed first?" -> Resolve

// ErrNoSuchVersion is returned when the catalogue does not have that version
// of the module.
var ErrNoSuchVersion = errors.New("armory: no such version of the module")

// Search returns the catalogue entries that match the query.
//
// The query is matched against the name, the description, the platform, the
// format and the capability list of the module, case insensitively. An empty
// query returns the whole catalogue.
func (r *Registry) Search(query string) []Manifest {
	needle := strings.ToLower(strings.TrimSpace(query))
	cat := r.Catalog()
	out := make([]Manifest, 0, len(cat.Entries))
	for _, m := range cat.Entries {
		if needle == "" || m.Matches(needle) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return compareVersions(out[i].Version, out[j].Version) > 0
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Matches reports whether the manifest matches a lower case query.
func (m Manifest) Matches(needle string) bool {
	fields := []string{m.Name, m.Description, m.OS, m.Arch, m.Format, m.Version}
	fields = append(fields, m.Caps...)
	fields = append(fields, m.Requires...)
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	for _, arg := range m.Schema() {
		if strings.Contains(strings.ToLower(arg.Name+" "+arg.Help), needle) {
			return true
		}
	}
	return false
}

// Versions returns the versions of the module the catalogue knows about,
// newest first.
func (r *Registry) Versions(name string) []string {
	cat := r.Catalog()
	out := []string{}
	for _, m := range cat.Entries {
		if m.Name == name {
			out = append(out, m.Version)
		}
	}
	sort.Slice(out, func(i, j int) bool { return compareVersions(out[i], out[j]) > 0 })
	return out
}

// Lookup returns the newest catalogue entry of a module.
func (r *Registry) Lookup(name string) (*Manifest, bool) {
	cat := r.Catalog()
	var best *Manifest
	for i := range cat.Entries {
		m := cat.Entries[i]
		if m.Name != name {
			continue
		}
		if best == nil || compareVersions(m.Version, best.Version) > 0 {
			entry := m
			best = &entry
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

// Needs describes what a module needs.
//
// It is the answer to "what does it need", both from the host (the
// capability list) and from the catalogue (the dependencies).
func (r *Registry) Needs(name string) (Needs, error) {
	manifest, ok := r.Lookup(name)
	if !ok {
		return Needs{}, fmt.Errorf("%w: %s", ErrNoSuchModule, name)
	}
	out := Needs{
		Name:     manifest.Name,
		Version:  manifest.Version,
		Format:   manifest.Format,
		OS:       manifest.OS,
		Arch:     manifest.Arch,
		Digest:   manifest.SHA256,
		Caps:     append([]string(nil), manifest.Caps...),
		Args:     manifest.Schema(),
		Output:   manifest.Output,
		Requires: append([]string(nil), manifest.Requires...),
	}
	if out.Caps == nil {
		out.Caps = []string{}
	}
	if out.Requires == nil {
		out.Requires = []string{}
	}
	cat := r.Catalog()
	for _, dep := range manifest.Requires {
		found := false
		for _, m := range cat.Entries {
			if m.Name == dep {
				found = true
				break
			}
		}
		if !found {
			out.Missing = append(out.Missing, dep)
		}
	}
	if out.Missing == nil {
		out.Missing = []string{}
	}
	return out, nil
}

// Resolve returns the modules that have to be installed for a module to work,
// in the order they have to be installed.
//
// The dependencies come first and the module itself comes last. A dependency
// that the catalogue does not have is an error: installing the module alone
// would leave it half working, and the operator has to know that before the
// module reaches a target.
func (r *Registry) Resolve(name string) ([]Manifest, error) {
	cat := r.Catalog()
	byName := map[string]Manifest{}
	for _, m := range cat.Entries {
		current, seen := byName[m.Name]
		if !seen || compareVersions(m.Version, current.Version) > 0 {
			byName[m.Name] = m
		}
	}
	var out []Manifest
	state := map[string]int{} // 0 = unvisited, 1 = on the stack, 2 = done
	var visit func(string) error
	visit = func(current string) error {
		switch state[current] {
		case 1:
			return fmt.Errorf("%w: %s", ErrDependencyCycle, current)
		case 2:
			return nil
		}
		manifest, ok := byName[current]
		if !ok {
			return fmt.Errorf("%w: %s", ErrNoSuchModule, current)
		}
		state[current] = 1
		for _, dep := range manifest.Requires {
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[current] = 2
		out = append(out, manifest)
		return nil
	}
	if err := visit(name); err != nil {
		return nil, err
	}
	return out, nil
}

// InstallVersion installs a module from the catalogue.
//
// An empty version means the newest one the catalogue has. The name may
// carry the version itself ("whoami@1.2.0"), which is what the console
// passes when the operator picks a version by hand.
func (r *Registry) InstallVersion(name, version string) (*Extension, error) {
	if version == "" {
		if at := strings.LastIndex(name, "@"); at > 0 {
			version = name[at+1:]
			name = name[:at]
		}
	}
	cat := r.Catalog()
	var chosen *Manifest
	for i := range cat.Entries {
		m := cat.Entries[i]
		if m.Name != name {
			continue
		}
		if version != "" && m.Version != version {
			continue
		}
		if chosen == nil || compareVersions(m.Version, chosen.Version) > 0 {
			entry := m
			chosen = &entry
		}
	}
	if chosen == nil {
		if version == "" {
			return nil, fmt.Errorf("%w: %s", ErrNoSuchModule, name)
		}
		return nil, fmt.Errorf("%w: %s@%s", ErrNoSuchVersion, name, version)
	}
	if err := r.Verify(*chosen); err != nil {
		return nil, err
	}
	blob, err := r.blob(chosen)
	if err != nil {
		return nil, err
	}
	return r.Install(*chosen, blob)
}

// ImportCatalog fetches a catalogue from a mirror and merges it into the
// local one.
//
// Every entry of the fetched catalogue is verified before it is merged: a
// mirror that rewrites a module breaks the signature and the import fails
// loudly. The merge keeps the local entries that the mirror does not mention,
// so an import never removes a module the operator already relies on.
func (r *Registry) ImportCatalog(ctx context.Context, rawURL string) (Catalog, error) {
	if rawURL == "" {
		return Catalog{}, errors.New("armory: the import needs an url")
	}
	if !strings.HasPrefix(rawURL, "https://") {
		return Catalog{}, fmt.Errorf("armory: a catalogue must be fetched over https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Catalog{}, fmt.Errorf("armory: import %s: %w", rawURL, err)
	}
	client := &http.Client{Timeout: FetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return Catalog{}, fmt.Errorf("armory: import %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Catalog{}, fmt.Errorf("armory: import %s: HTTP %d", rawURL, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxFetchSize+1))
	if err != nil {
		return Catalog{}, fmt.Errorf("armory: import %s: %w", rawURL, err)
	}
	if len(raw) > MaxFetchSize {
		return Catalog{}, ErrTooLarge
	}
	var cat Catalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return Catalog{}, fmt.Errorf("armory: parse catalogue: %w", err)
	}
	if len(cat.Entries) > MaxCatalogEntries {
		return Catalog{}, errors.New("armory: the catalogue is too large")
	}
	for _, m := range cat.Entries {
		if err := r.Verify(m); err != nil {
			return Catalog{}, fmt.Errorf("armory: catalogue entry %q: %w", m.Name, err)
		}
	}
	merged := r.mergeCatalog(cat)
	r.mu.Lock()
	r.catalog = merged
	r.catalog.Verified = r.pub != nil
	r.mu.Unlock()
	if err := r.SaveCatalog(); err != nil {
		return merged, err
	}
	if r.log != nil {
		r.log.Info("armory catalogue imported",
			"url", rawURL, "entries", len(cat.Entries), "total", len(merged.Entries))
	}
	return merged, nil
}

// mergeCatalog merges an imported catalogue into the local one.
//
// An imported entry replaces the local entry of the same name and version;
// everything else is kept.
func (r *Registry) mergeCatalog(imported Catalog) Catalog {
	local := r.Catalog()
	merged := Catalog{
		Entries:  make([]Manifest, 0, len(local.Entries)+len(imported.Entries)),
		Updated:  local.Updated,
		Source:   imported.Source,
		Verified: r.pub != nil,
	}
	if merged.Source == "" {
		merged.Source = local.Source
	}
	index := map[string]int{}
	for _, m := range local.Entries {
		index[entryKey(m)] = len(merged.Entries)
		merged.Entries = append(merged.Entries, m)
	}
	for _, m := range imported.Entries {
		key := entryKey(m)
		if at, seen := index[key]; seen {
			merged.Entries[at] = m
			continue
		}
		index[key] = len(merged.Entries)
		merged.Entries = append(merged.Entries, m)
	}
	sort.Slice(merged.Entries, func(i, j int) bool {
		if merged.Entries[i].Name == merged.Entries[j].Name {
			return compareVersions(merged.Entries[i].Version, merged.Entries[j].Version) > 0
		}
		return merged.Entries[i].Name < merged.Entries[j].Name
	})
	return merged
}

// SaveCatalog writes the catalogue back to the armory directory.
//
// The file is written to a temporary name and renamed into place, so a crash
// never leaves a catalogue that is half written: a catalogue that cannot be
// parsed is a catalogue the server refuses to trust.
func (r *Registry) SaveCatalog() error {
	if r.dir == "" {
		return errors.New("armory: no armory directory configured")
	}
	r.mu.RLock()
	cat := r.catalog
	r.mu.RUnlock()
	raw, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return fmt.Errorf("armory: encode catalogue: %w", err)
	}
	path := filepath.Join(r.dir, "catalog.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("armory: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("armory: save catalogue: %w", err)
	}
	return nil
}

// entryKey is the identity of a catalogue entry: its name and its version.
func entryKey(m Manifest) string {
	return m.Name + "@" + m.Version
}

// compareVersions compares two dotted version strings.
//
// The comparison is numeric per part, so "1.10.0" is newer than "1.9.0".
// A part that is not a number compares as text, which keeps a pre-release
// tag ("1.0.0-rc1") below the release it belongs to.
func compareVersions(a, b string) int {
	left := strings.Split(strings.TrimSpace(a), ".")
	right := strings.Split(strings.TrimSpace(b), ".")
	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r string
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		ln, lerr := strconv.Atoi(l)
		rn, rerr := strconv.Atoi(r)
		switch {
		case lerr == nil && rerr == nil:
			if ln != rn {
				if ln > rn {
					return 1
				}
				return -1
			}
		case lerr == nil:
			return 1
		case rerr == nil:
			return -1
		default:
			if l != r {
				if l > r {
					return 1
				}
				return -1
			}
		}
	}
	return 0
}
