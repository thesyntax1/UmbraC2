package armory

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The module ABI.
//
// A module is a blob plus a manifest, and the manifest is versioned: the
// magic opens it and the ABI number says which dialect it is written in.
// The server refuses a manifest it cannot read, so a module built for a
// different version of the framework is never pushed to an agent; the
// implant refuses the same manifest for the same reason.
//
// The manifest says three things the old "a bag of argument names" could not:
//
//   - what the module needs from the host (the capability list), so the
//     server can refuse to push it to a host that cannot do it,
//   - what the module takes (the argument schema), so a missing argument or
//     a value of the wrong kind is caught before the module runs,
//   - what the module answers (the output schema), so the operator knows
//     what the result will look like before it is sent.
//
// A module that declares nothing needs nothing: an empty capability list is
// not a claim on the host.
const (
	// ManifestMagic opens a module manifest.
	ManifestMagic = "UMBRAMOD1"
	// ManifestABI is the version of the module ABI the server speaks.
	ManifestABI = 1
)

// The argument types a module may declare.
const (
	// ArgString is a text argument.
	ArgString = "string"
	// ArgInt is a whole number.
	ArgInt = "int"
	// ArgBool is a flag.
	ArgBool = "bool"
	// ArgBytes is a blob.
	ArgBytes = "bytes"
)

// ErrNoSuchModule is returned when the catalogue does not have the module.
var ErrNoSuchModule = errors.New("armory: no such module")

// ErrDependencyCycle is returned when the modules depend on each other in a
// circle. Such a set can never be installed in an order that works, so the
// resolver says so instead of looping.
var ErrDependencyCycle = errors.New("armory: the modules depend on each other in a circle")

// ArgSpec is one declared argument of a module.
type ArgSpec struct {
	// Name is the name of the argument.
	Name string `json:"name"`
	// Type is one of string, int, bool or bytes.
	Type string `json:"type"`
	// Required is set when the module refuses to run without it.
	Required bool `json:"required,omitempty"`
	// Default is the value the module uses when the operator says nothing.
	Default string `json:"default,omitempty"`
	// Help is the one line description of the argument.
	Help string `json:"help,omitempty"`
}

// OutputSpec describes what a module answers.
type OutputSpec struct {
	// Type is the shape of the answer: text, json, binary or none.
	Type string `json:"type"`
	// Description is the one line description of the answer.
	Description string `json:"description,omitempty"`
}

// Schema returns the declared arguments of the module.
//
// A legacy catalogue entry has only names: they become optional string
// arguments, so the implant accepts exactly what the old catalogues sent.
func (m Manifest) Schema() []ArgSpec {
	if len(m.ArgSchema) > 0 {
		out := make([]ArgSpec, len(m.ArgSchema))
		copy(out, m.ArgSchema)
		return out
	}
	out := make([]ArgSpec, 0, len(m.Args))
	for _, name := range m.Args {
		out = append(out, ArgSpec{Name: name, Type: ArgString})
	}
	return out
}

// ABIManifest renders the manifest the way the implant expects it.
//
// The implant refuses a module whose manifest it cannot read, so the server
// always sends a complete one. A legacy entry (one without an ABI) is
// upgraded on the way out: it keeps its name, its version and its argument
// names, and it declares no capability, because it never said what it needed.
func (m Manifest) ABIManifest() map[string]any {
	out := map[string]any{
		"magic": ManifestMagic,
		"abi":   int64(ManifestABI),
		"name":  m.Name,
	}
	if m.Version != "" {
		out["version"] = m.Version
	}
	if m.Description != "" {
		out["description"] = m.Description
	}
	if m.OS != "" {
		out["os"] = m.OS
	}
	if m.Arch != "" {
		out["arch"] = m.Arch
	}
	if m.Format != "" {
		out["format"] = m.Format
	}
	if m.SHA256 != "" {
		out["digest"] = "sha256:" + strings.ToLower(m.SHA256)
	}
	if len(m.Caps) > 0 {
		caps := make([]any, 0, len(m.Caps))
		for _, cap := range m.Caps {
			caps = append(caps, cap)
		}
		out["caps"] = caps
	}
	if schema := m.Schema(); len(schema) > 0 {
		args := make([]any, 0, len(schema))
		for _, arg := range schema {
			entry := map[string]any{
				"name": arg.Name,
				"type": arg.Type,
			}
			if arg.Required {
				entry["required"] = true
			}
			if arg.Default != "" {
				entry["default"] = arg.Default
			}
			if arg.Help != "" {
				entry["help"] = arg.Help
			}
			args = append(args, entry)
		}
		out["args"] = args
	}
	if m.Output != nil {
		output := map[string]any{"type": m.Output.Type}
		if m.Output.Description != "" {
			output["description"] = m.Output.Description
		}
		out["output"] = output
	}
	return out
}

// Needs describes what a module needs from the host and from the catalogue.
//
// It is the "what does it need" view: the capabilities the host must have,
// the arguments the operator has to supply, the platform the module is for
// and the other modules it depends on.
type Needs struct {
	// Name is the name of the module.
	Name string `json:"name"`
	// Version is the version of the module.
	Version string `json:"version"`
	// Format is the shape of the blob: coff, pe, shellcode, wasm or script.
	Format string `json:"format"`
	// OS is the operating system the module is for (empty = every one).
	OS string `json:"os"`
	// Arch is the architecture the module is for (empty = every one).
	Arch string `json:"arch"`
	// Digest is the digest of the blob.
	Digest string `json:"digest"`
	// Caps are the host capabilities the module needs.
	Caps []string `json:"caps"`
	// Args is the argument schema.
	Args []ArgSpec `json:"args"`
	// Output is what the module answers.
	Output *OutputSpec `json:"output,omitempty"`
	// Requires are the other modules the module depends on.
	Requires []string `json:"requires"`
	// Missing are the dependencies the catalogue does not have.
	Missing []string `json:"missing"`
}

// signingBytesV2 is the canonical byte string of an ABI manifest.
//
// Every field that changes the meaning of the module is inside the
// signature: the capability list, the argument schema, the output schema and
// the dependencies. A catalogue that is tampered with therefore fails the
// signature check instead of quietly changing what a module is allowed to
// do on a target.
func (m Manifest) signingBytesV2() []byte {
	var b strings.Builder
	b.WriteString("umbra/armory/v2\n")
	writeSignedField(&b, m.Magic)
	fmt.Fprintf(&b, "%d\n", m.ABI)
	writeSignedField(&b, m.Name)
	writeSignedField(&b, m.Version)
	writeSignedField(&b, m.OS)
	writeSignedField(&b, m.Arch)
	writeSignedField(&b, m.Format)
	writeSignedField(&b, strings.ToLower(m.SHA256))
	fmt.Fprintf(&b, "%d\n", m.Size)
	writeSignedField(&b, m.Description)
	writeSignedField(&b, m.URL)
	writeSignedField(&b, strings.Join(m.Caps, ","))
	writeSignedField(&b, strings.Join(m.Requires, ","))
	writeSignedField(&b, strings.Join(m.Args, ","))
	for _, arg := range m.Schema() {
		b.WriteString(escapeSignedField(arg.Name))
		b.WriteByte('|')
		b.WriteString(escapeSignedField(arg.Type))
		b.WriteByte('|')
		if arg.Required {
			b.WriteString("1")
		} else {
			b.WriteString("0")
		}
		b.WriteByte('|')
		b.WriteString(escapeSignedField(arg.Default))
		b.WriteByte('|')
		b.WriteString(escapeSignedField(arg.Help))
		b.WriteByte('\n')
	}
	if m.Output != nil {
		b.WriteString(escapeSignedField(m.Output.Type))
		b.WriteByte('|')
		b.WriteString(escapeSignedField(m.Output.Description))
		b.WriteByte('\n')
	} else {
		b.WriteString("|\n")
	}
	return []byte(b.String())
}

// writeSignedField writes one field of a signed manifest.
func writeSignedField(b *strings.Builder, value string) {
	b.WriteString(escapeSignedField(value))
	b.WriteByte('\n')
}

// escapeSignedField keeps a field on one line.
//
// A newline or a separator inside a value would let two different manifests
// produce the same signed bytes, which is exactly what a signature is there
// to prevent.
func escapeSignedField(value string) string {
	return strings.NewReplacer(
		"\\", "\\\\",
		"\n", "\\n",
		"\r", "\\r",
		"|", "\\|",
	).Replace(value)
}

// MissingCapabilities returns the capabilities the module needs and the host
// does not have.
//
// An empty capability list on the host means "the beacon never said": such a
// host is allowed everything, because refusing would break every agent that
// predates the handshake that carries the list.
func MissingCapabilities(moduleCaps, hostCaps []string) []string {
	if len(hostCaps) == 0 {
		return nil
	}
	var out []string
	for _, cap := range moduleCaps {
		found := false
		for _, have := range hostCaps {
			if have == cap {
				found = true
				break
			}
		}
		if !found {
			out = append(out, cap)
		}
	}
	sort.Strings(out)
	return out
}
