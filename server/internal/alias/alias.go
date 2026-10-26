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
	"errors"
	"fmt"
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
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{byName: make(map[string]Alias)}
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
