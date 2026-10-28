package link

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/config"
	"github.com/thesyntax1/UmbraC2/server/internal/hub"
	"github.com/thesyntax1/UmbraC2/server/internal/keyring"
	"github.com/thesyntax1/UmbraC2/server/internal/rbac"
	"github.com/thesyntax1/UmbraC2/server/internal/upk"
)

// touchOperator records that an operator was seen.
//
// The keyring may be absent (a server that was wired up by hand in a
// test), and a missing keyring simply has nothing to remember.
func (s *Server) touchOperator(name string) {
	if s.Keys == nil {
		return
	}
	s.Keys.Touch(name)
}

// operatorAccess returns the role and the scopes of an operator.
//
// The answer comes from the runtime keyring, not from the configuration:
// a token whose scopes were narrowed ten minutes ago must be narrowed
// now, not after the next restart.  When the keyring knows the operator
// it is the only word: an operator that was taken out of the keyring
// does not get its old role back from the configuration.
func (s *Server) operatorAccess(name string) (string, []string) {
	if s.Keys != nil {
		if op, ok := s.Keys.Operator(name); ok {
			return op.Role, append([]string(nil), op.Scopes...)
		}
		return config.DefaultOperatorRole, nil
	}
	if s.Cfg != nil {
		return s.Cfg.Keyring.Role(name), append([]string(nil), s.Cfg.Keyring.Scopes[name]...)
	}
	return config.DefaultOperatorRole, nil
}

// operatorIdentity returns the role and the scopes of a connected console
// as they are right now.
//
// The hub remembers what the console looked like when it connected, but
// the scopes of a token can be narrowed while it is connected: the narrow
// one is the one that counts, and it is read from the keyring on every
// call so that a console cannot keep a permission it has lost.
func (s *Server) operatorIdentity(op *hub.Operator) (string, []string) {
	if op == nil {
		return "", nil
	}
	if s.Keys != nil {
		if live, ok := s.Keys.Operator(op.Name); ok {
			return live.Role, append([]string(nil), live.Scopes...)
		}
	}
	return op.Role, append([]string(nil), op.Scopes...)
}

// operatorAllowed says whether an operator may call a command.
//
// The rule itself lives in the keyring, so the server, the tests and the
// documentation all say the same thing.
func (s *Server) operatorAllowed(op *hub.Operator, cmd string) bool {
	if op == nil {
		return false
	}
	role, scopes := s.operatorIdentity(op)
	return keyring.Permits(role, scopes, cmd)
}

// handleKeysRotate rotates the credentials of the server.
//
// The agent PSK is the key every beacon authenticates with, and the
// operator tokens are the keys every console authenticates with.  Both
// can be rotated while the server runs: the new credential is accepted
// immediately, and the old one keeps working for the overlap, so nothing
// that is asleep is locked out in the middle of an engagement.
//
// The result is a secret, and the audit log never sees it: the response
// is the only place it appears.
func (s *Server) handleKeysRotate(op *hub.Operator, args map[string]any,
	reply func(upk.Map) upk.Map, fail func(string, ...any) upk.Map) upk.Map {
	if s.Keys == nil {
		return fail("keys.rotate: the server has no keyring")
	}
	target := strings.TrimSpace(stringArg(args, "target"))
	if target == "" {
		target = "agent"
	}
	switch target {
	case "agent", "agent_psk", "psk":
		// The operator may bring its own key (a key management system
		// that hands it out) or let the server generate one.
		var fresh []byte
		if brought := strings.TrimSpace(stringArg(args, "psk")); brought != "" {
			if err := s.Keys.SetAgentPSK([]byte(brought)); err != nil {
				return fail("keys.rotate: %v", err)
			}
			fresh = []byte(brought)
		} else {
			generated, err := s.Keys.RotateAgentPSK()
			if err != nil {
				return fail("keys.rotate: %v", err)
			}
			fresh = generated
		}
		overlap := s.Keys.Overlap()
		s.Hub.Emit(hub.Event{Kind: "keys.rotated", From: operatorName(op), Data: map[string]any{
			"target":  "agent",
			"overlap": int64(overlap.Seconds()),
		}})
		return reply(upk.Map{
			"target": "agent",
			// The new key is a text: the operator copies it into the
			// configuration of the beacons, so it has to be typeable.
			"psk":     string(fresh),
			"overlap": int64(overlap.Seconds()),
			"note":    "the previous key still works for the overlap; give the new key to the beacons",
		})
	default:
		// Rotating an operator's token is the job of tokens.rotate: this
		// one only knows the agent key, and it says so instead of
		// guessing.
		return fail(
			"keys.rotate: unknown target %q (want agent, or use tokens.rotate for an operator)", target)
	}
}

// handleTokensRotate rotates the token of one operator.
//
// The new token is returned once and never stored in the clear: the
// operator has to write it down or hand it to the console.  The previous
// token keeps working for the overlap.
func (s *Server) handleTokensRotate(op *hub.Operator, args map[string]any,
	reply func(upk.Map) upk.Map, fail func(string, ...any) upk.Map) upk.Map {
	if s.Keys == nil {
		return fail("tokens.rotate: the server has no keyring")
	}
	name := strings.TrimSpace(stringArg(args, "operator"))
	if name == "" {
		name = strings.TrimSpace(stringArg(args, "name"))
	}
	if name == "" {
		return fail("tokens.rotate: an operator is required")
	}
	// The role is only changed when the caller says so: a rotation that
	// quietly demoted an admin to an operator would be a surprise of the
	// worst kind.
	role := strings.TrimSpace(stringArg(args, "role"))
	if role == "" {
		role = rbac.Operator
		if existing, ok := s.Keys.Operator(name); ok && existing.Role != "" {
			role = existing.Role
		}
	}
	scopes, err := scopeArgs(args)
	if err != nil {
		return fail("tokens.rotate: %v", err)
	}
	expires, err := expiryArg(args)
	if err != nil {
		return fail("tokens.rotate: %v", err)
	}
	var token []byte
	if raw := strings.TrimSpace(stringArg(args, "token")); raw != "" {
		token = []byte(raw)
	} else {
		generated, gerr := keyring.NewTokenBytes()
		if gerr != nil {
			return fail("tokens.rotate: %v", gerr)
		}
		token = generated
	}
	if len(token) < 16 {
		return fail("tokens.rotate: the token must be at least 16 characters")
	}
	if err := s.Keys.SetOperator(name, role, scopes, expires, token); err != nil {
		return fail("tokens.rotate: %v", err)
	}
	overlap := s.Keys.Overlap()
	s.Hub.Emit(hub.Event{Kind: "token.rotated", From: operatorName(op), Data: map[string]any{
		"target": name,
		"role":   role,
	}})
	expiresOut := int64(0)
	if !expires.IsZero() {
		expiresOut = expires.Unix()
	}
	return reply(upk.Map{
		"operator": name,
		"role":     role,
		"scopes":   scopeList(scopes),
		"expires":  expiresOut,
		"token":    string(token),
		"overlap":  int64(overlap.Seconds()),
		"note":     "the previous token still works for the overlap",
	})
}

// handleTokensList lists the operator tokens and their state.
//
// The tokens themselves are never in the list: only who has one, what it
// may do, when it expires and when it was last used.
func (s *Server) handleTokensList(reply func(upk.Map) upk.Map, fail func(string, ...any) upk.Map) upk.Map {
	if s.Keys == nil {
		return fail("tokens.list: no keyring")
	}
	ops := s.Keys.Operators()
	out := make([]any, 0, len(ops))
	for _, o := range ops {
		expires := int64(0)
		if !o.Expires.IsZero() {
			expires = o.Expires.Unix()
		}
		lastUsed := int64(0)
		if !o.LastUsed.IsZero() {
			lastUsed = o.LastUsed.Unix()
		}
		rotated := int64(0)
		if !o.RotatedAt.IsZero() {
			rotated = o.RotatedAt.Unix()
		}
		out = append(out, upk.Map{
			"operator":  o.Name,
			"role":      o.Role,
			"scopes":    scopeList(o.Scopes),
			"expires":   expires,
			"expired":   o.Expired(time.Now()),
			"last_used": lastUsed,
			"rotated":   rotated,
		})
	}
	return reply(upk.Map{"tokens": out, "count": int64(len(out))})
}

// scopeArgs reads the scopes of a token.
//
// The scopes may be a list of command names or a comma separated string:
// a console sends a list, a script sends a string.
func scopeArgs(args map[string]any) ([]string, error) {
	out := make([]string, 0, 8)
	seen := map[string]bool{}
	add := func(name string) error {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		if name != "*" && !rbac.Known(name) {
			return fmt.Errorf("unknown command %q in the scopes", name)
		}
		if seen[name] {
			return nil
		}
		seen[name] = true
		out = append(out, name)
		return nil
	}
	switch raw := args["scopes"].(type) {
	case []any:
		for _, item := range raw {
			if err := add(fmt.Sprintf("%v", item)); err != nil {
				return nil, err
			}
		}
	case []string:
		for _, item := range raw {
			if err := add(item); err != nil {
				return nil, err
			}
		}
	case string:
		for _, item := range strings.Split(raw, ",") {
			if err := add(item); err != nil {
				return nil, err
			}
		}
	case nil:
	default:
		return nil, fmt.Errorf("the scopes must be a list or a string")
	}
	sort.Strings(out)
	return out, nil
}

// expiryArg reads the expiry of a token.
//
// The expiry is a unix time in seconds; zero means the token never
// expires.
func expiryArg(args map[string]any) (time.Time, error) {
	switch raw := args["expires_at"].(type) {
	case nil:
		return time.Time{}, nil
	case int64:
		if raw == 0 {
			return time.Time{}, nil
		}
		return time.Unix(raw, 0).UTC(), nil
	case float64:
		if int64(raw) == 0 {
			return time.Time{}, nil
		}
		return time.Unix(int64(raw), 0).UTC(), nil
	case string:
		text := strings.TrimSpace(raw)
		if text == "" || text == "0" {
			return time.Time{}, nil
		}
		var seconds int64
		if _, err := fmt.Sscanf(text, "%d", &seconds); err != nil {
			return time.Time{}, fmt.Errorf("the expiry must be a unix time in seconds")
		}
		if seconds == 0 {
			return time.Time{}, nil
		}
		return time.Unix(seconds, 0).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("the expiry must be a unix time in seconds")
	}
}

// scopeList turns a scope list into the form the wire understands.
func scopeList(scopes []string) []any {
	out := make([]any, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, scope)
	}
	return out
}

// operatorName is the name of a console, or the empty string.
func operatorName(op *hub.Operator) string {
	if op == nil {
		return ""
	}
	return op.Name
}

// stringArg reads a string argument, or the empty string.
func stringArg(args map[string]any, name string) string {
	value, _ := args[name].(string)
	return value
}
