package beacon

// The helpers below read the maps that come off the wire.
//
// The decoder of Umbra Pack produces uint64 for the unsigned integers,
// int64 for the signed ones, string for the text, []byte for the binary
// and []any for the arrays, so every read is a type switch that returns a
// flag instead of a panic: a hostile or buggy peer must never be able to
// stop the implant with a malformed frame.

// strField reads a text field.
func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// strOr reads a text field with a fallback.
func strOr(m map[string]any, key, fallback string) string {
	if m == nil {
		return fallback
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return fallback
}

// u64Field reads an unsigned field.
func u64Field(m map[string]any, key string) (uint64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[key].(type) {
	case uint64:
		return v, true
	case int64:
		if v >= 0 {
			return uint64(v), true
		}
	}
	return 0, false
}

// u64Or reads an unsigned field with a fallback.
func u64Or(m map[string]any, key string, fallback uint64) uint64 {
	if v, ok := u64Field(m, key); ok {
		return v
	}
	return fallback
}

// i64Or reads a signed field with a fallback.
func i64Or(m map[string]any, key string, fallback int64) int64 {
	if m == nil {
		return fallback
	}
	switch v := m[key].(type) {
	case int64:
		return v
	case uint64:
		return int64(v)
	}
	return fallback
}

// boolOr reads a boolean field with a fallback.
func boolOr(m map[string]any, key string, fallback bool) bool {
	if m == nil {
		return fallback
	}
	if b, ok := m[key].(bool); ok {
		return b
	}
	return fallback
}

// binField reads a binary field.
func binField(m map[string]any, key string) []byte {
	if m == nil {
		return nil
	}
	b, _ := m[key].([]byte)
	return b
}

// arrField reads an array field.
func arrField(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	a, _ := m[key].([]any)
	return a
}

// mapField reads a nested map.
func mapField(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	nested, _ := m[key].(map[string]any)
	return nested
}
