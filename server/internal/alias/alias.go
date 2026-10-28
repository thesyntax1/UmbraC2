// Package alias implements the runtime command namespace.
//
// An alias is a named template: a task kind plus a fixed set of arguments.
// Operators register the templates they use ("bloodhound", "kerberoast",
// "screenshot") and then run them by name against any agent, which is how a
// team keeps one agreed-upon way of running a tool on every host.
//
// An alias may also point at an armory extension instead of a built-in task
// kind, which is what makes the namespace extensible at runtime: the
// extension is verified by the registry and executed in memory by the agent.
package alias

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Limits.
const (
	// MaxAliases bounds the namespace.
	MaxAliases = 256
	// MaxNameLen bounds an alias name.
	MaxNameLen = 64
	// MaxArgs bounds the arguments of one alias.
	MaxArgs = 32
)

// Errors.
var (
	ErrNoSuchAlias = errors.New("alias: no such alias")
	ErrDuplicate   = errors.New("alias: the alias already exists")
)

// Alias is one named template.
type Alias struct {
	Name string `json:"name"`
	// Kind is the task kind the alias expands to.
	Kind string `json:"kind"`
	// Extension is the armory extension to run instead of a task kind.
	Extension string `json:"extension,omitempty"`
	// Args are the fixed arguments of the template.
	Args map[string]any `json:"args"`
	// ArgsSpec documents the parameters the alias accepts at call time.
	ArgsSpec []string `json:"args_spec,omitempty"`
	// Description is the operator-facing help text.
	Description string `json:"description"`
	// CreatedBy is the operator who registered the alias.
	CreatedBy string `json:"created_by,omitempty"`
	// Created is when the alias was registered.
	Created time.Time `json:"created"`
}

// Clone returns a copy with its own argument map.
func (a Alias) Clone() Alias {
	c := a
	c.Args = make(map[string]any, len(a.Args))
	for k, v := range a.Args {
		c.Args[k] = v
	}
	return c
}

// Registry holds the aliases of one server.
type Registry struct {
	mu     sync.RWMutex
	byName map[string]Alias
	// path is where the namespace is kept between two runs of the server.
	// The namespace is shared by the team, so a template that one operator
	// wrote has to be there for the next one.
	path string
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{byName: make(map[string]Alias)}
}

// Defaults returns the built-in command templates.
//
// They are the one-liners an operator types a hundred times a day.  The
// team can replace them, remove them or add their own; the registry is the
// same one either way.
func Defaults() []Alias {
	return []Alias{
		{Name: "whoami", Kind: "exec", Args: map[string]any{"cmd": "whoami"},
			Description: "who the implant runs as"},
		{Name: "hostname", Kind: "exec", Args: map[string]any{"cmd": "hostname"},
			Description: "the name of the host"},
		{Name: "system", Kind: "sysinfo", Args: map[string]any{},
			Description: "the system information of the host"},
		{Name: "processes", Kind: "ps", Args: map[string]any{},
			Description: "the running processes"},
		{Name: "network", Kind: "netinfo", Args: map[string]any{},
			Description: "the interfaces, the routes and the neighbours"},
		{Name: "screenshot", Kind: "screenshot", Args: map[string]any{},
			Description: "a picture of the desktop"},
		{Name: "listening", Kind: "exec",
			Args:        map[string]any{"cmd": "ss -tulpn 2>/dev/null || netstat -anb 2>/dev/null"},
			Description: "the listening sockets"},
		{Name: "routes", Kind: "exec",
			Args:        map[string]any{"cmd": "ip route 2>/dev/null || route print 2>/dev/null"},
			Description: "the routing table"},
		{Name: "services", Kind: "exec",
			Args:        map[string]any{"cmd": "systemctl list-units --type=service --state=running 2>/dev/null || sc query type= service state= all 2>/dev/null"},
			Description: "the running services"},
		{Name: "triage", Kind: "triage", Args: map[string]any{}, ArgsSpec: []string{"path"},
			Description: "the hash, the entropy and the file type of a file"},
		{Name: "find", Kind: "find", Args: map[string]any{}, ArgsSpec: []string{"name", "path", "content"},
			Description: "a search by name or by content"},
	}
}

// NewWithDefaults creates a registry that already holds the built-ins.
func NewWithDefaults() *Registry {
	r := New()
	for _, a := range Defaults() {
		// The built-ins are well formed by construction.
		_ = r.Register(a)
	}
	return r
}

// Register adds or replaces an alias.
func (r *Registry) Register(a Alias) error {
	name := a.Name
	if name == "" {
		return errors.New("alias: an alias needs a name")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("alias: the name is longer than %d characters", MaxNameLen)
	}
	if a.Kind == "" && a.Extension == "" {
		return errors.New("alias: an alias needs a task kind or an extension")
	}
	if a.Kind != "" && a.Extension != "" {
		return errors.New("alias: an alias has either a task kind or an extension, not both")
	}
	if len(a.Args) > MaxArgs {
		return fmt.Errorf("alias: too many arguments (max %d)", MaxArgs)
	}
	if a.Created.IsZero() {
		a.Created = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.byName) >= MaxAliases {
		if _, exists := r.byName[name]; !exists {
			return fmt.Errorf("alias: the namespace holds at most %d aliases", MaxAliases)
		}
	}
	r.byName[name] = a.Clone()
	return nil
}

// Remove deletes an alias.
func (r *Registry) Remove(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byName[name]; !ok {
		return ErrNoSuchAlias
	}
	delete(r.byName, name)
	return nil
}

// Get returns one alias.
func (r *Registry) Get(name string) (Alias, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byName[name]
	if !ok {
		return Alias{}, false
	}
	return a.Clone(), true
}

// List returns every alias, sorted by name.
func (r *Registry) List() []Alias {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Alias, 0, len(r.byName))
	for _, a := range r.byName {
		out = append(out, a.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Expand merges the call-time arguments into the template.
//
// The template's own arguments win: an alias is a fixed recipe, and letting a
// caller silently override it would make the registered name a lie.
func (r *Registry) Expand(name string, extra map[string]any) (kind string, args map[string]any, extension string, err error) {
	a, ok := r.Get(name)
	if !ok {
		return "", nil, "", ErrNoSuchAlias
	}
	merged := a.Clone().Args
	for k, v := range extra {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}
	if a.Extension != "" {
		return "ext", merged, a.Extension, nil
	}
	return a.Kind, merged, "", nil
}

// SetPath tells the registry where to keep the namespace.
//
// The path is a file: the namespace is written as a JSON list of the
// templates the team wrote.
func (r *Registry) SetPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path = path
}

// Path is where the namespace is kept, empty when it is not kept.
func (r *Registry) Path() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.path
}

// Load reads the namespace back.
//
// A file that cannot be read is not fatal: the server starts with the
// built-in templates and says so, because a namespace that is lost is a
// nuisance and a namespace that is silently wrong is a trap.
func (r *Registry) Load() error {
	r.mu.RLock()
	path := r.path
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("alias: read %s: %w", path, err)
	}
	var list []Alias
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("alias: parse %s: %w", path, err)
	}
	for _, a := range list {
		if a.Name == "" {
			continue
		}
		// A template the team wrote replaces the built-in one of the same
		// name: the namespace belongs to the team, not to the binary.
		_ = r.Remove(a.Name)
		if err := r.Register(a); err != nil {
			// A template that cannot be registered is skipped: one broken
			// entry must not take the whole namespace with it.
			continue
		}
	}
	return nil
}

// Save writes the namespace to the disk.
//
// The file is written to a temporary name and renamed into place, so a
// crash never leaves a namespace that is half written.
func (r *Registry) Save() error {
	r.mu.RLock()
	path := r.path
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	list := r.List()
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("alias: encode the namespace: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("alias: create %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("alias: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("alias: save the namespace: %w", err)
	}
	return nil
}
