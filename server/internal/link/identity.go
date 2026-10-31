package link

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Identity and metadata hygiene at the door.
//
// A beacon is not a trusted component: it is a program running on a host
// somebody else controls, and it can introduce itself with any string it
// likes.  Everything the server stores about it (the identity, the host
// name, the user, the transport label, the version) later travels to the
// consoles, to the dashboard, to the audit ledger and to the dossiers.
// A string that is stored raw is a string that has to be escaped by every
// reader for ever; the cheapest place to settle it is once, here, at the
// door.
//
// The rules are deliberately narrow and they are the same in every
// implementation (see docs/PROTOCOL.md, "The name of a peer"):
//
//   - an identity is 1..128 characters of [A-Za-z0-9._:@-].  Host names,
//     user names and generated ids all fit; a space, a quote, a slash or
//     a tag do not, and an identity is not the place for them;
//   - a metadata string is any valid UTF-8 without control characters and
//     without the five characters that mean something to a markup reader
//     (< > & " ').  A host name with an accent survives; a host name that
//     wants to be an HTML tag does not.
const (
	// identityMax is the longest identity the protocol carries.
	identityMax = 128
	// metaMax is the longest metadata string the server keeps.
	metaMax = 256
)

// validIdentity reports whether a peer may call itself this.
//
// An empty identity is not valid for an agent (the handshake refuses it
// earlier with a clearer message) and not valid here either: a name is
// the first thing a log line needs.
func validIdentity(id string) bool {
	if id == "" || len(id) > identityMax {
		return false
	}
	// The identity is carried as bytes, so ASCII is the whole alphabet:
	// a name with a multi-byte rune would have to be normalised before it
	// could be compared, and two spellings of one name is two identities.
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == ':' || c == '@':
		default:
			return false
		}
	}
	return true
}

// identityRefusal is the one message a peer is refused with.
//
// It is a function so that the reason a beacon cannot join is written
// once: the message names the alphabet and the bound, because the person
// who reads it is writing the beacon.
func identityRefusal(id string) *HandshakeError {
	return handshakeErr("invalid identity %q: a name is [A-Za-z0-9._:@-], at most %d characters",
		id, identityMax)
}

// markupHostile are the characters a markup reader treats as structure.
//
// They are stripped from metadata rather than escaped, because no
// legitimate host name, user name or version string contains one, and a
// stripped value is safe in every consumer that will ever read it.
const markupHostile = "<>&\"'`"

// cleanMeta returns a metadata string that is safe to store and to render
// everywhere, or the empty string when nothing survives.
//
// The function is idempotent: cleaning a cleaned value changes nothing,
// which is what lets the console clean what it shows without the server
// and the console disagreeing.
func cleanMeta(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	count := 0
	for _, r := range s {
		if count >= metaMax {
			break
		}
		if r == utf8.RuneError {
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		if strings.ContainsRune(markupHostile, r) {
			continue
		}
		b.WriteRune(r)
		count++
	}
	return strings.TrimSpace(b.String())
}

// cleanMetaMap cleans every string of a metadata map, one level deep,
// which is the shape the handshake allows.
//
// The keys are cleaned too: a key is not rendered anywhere today, and a
// map whose keys are clean stays safe the day somebody renders one.
func cleanMetaMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		key := cleanMeta(k)
		if key == "" {
			continue
		}
		if s, ok := v.(string); ok {
			out[key] = cleanMeta(s)
			continue
		}
		if inner, ok := v.(map[string]any); ok {
			cleaned := make(map[string]any, len(inner))
			for ik, iv := range inner {
				ikey := cleanMeta(ik)
				if ikey == "" {
					continue
				}
				if s, ok := iv.(string); ok {
					cleaned[ikey] = cleanMeta(s)
				} else {
					cleaned[ikey] = iv
				}
			}
			out[key] = cleaned
			continue
		}
		out[key] = v
	}
	return out
}
