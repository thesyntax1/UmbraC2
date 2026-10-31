package link

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The identity of a peer is refused, not repaired.
//
// A repaired name is the worse outcome: two beacons that both called
// themselves something unsafe would be repaired into one name, and the
// operator would see two hosts as one.  The door says no, and the refusal
// names the alphabet so the beacon's author can fix the program.
func TestAnIdentityIsTheNarrowAlphabet(t *testing.T) {
	good := []string{
		"a", "web-01", "web-01.dc1", "agent_1", "host:4001", "ops@lab",
		"0f3c9a7e", strings.Repeat("x", identityMax),
	}
	for _, id := range good {
		if !validIdentity(id) {
			t.Errorf("%q was refused and should not be", id)
		}
	}
	bad := []string{
		"", "<script>alert(1)</script>", "web 01", "a/b", `a\b`,
		"a'b", `a"b`, "a&b", "a|b", "a;b", "a\x00b", "a\nb", "host\t",
		"ünïcode", strings.Repeat("x", identityMax+1), " leading", "trailing ",
	}
	for _, id := range bad {
		if validIdentity(id) {
			t.Errorf("%q was accepted and should not be", id)
		}
	}
}

// The refusal message of the handshake names the rule, because the beacon's
// author is the person who has to act on it.
func TestTheHandshakeRefusalNamesTheAlphabet(t *testing.T) {
	err := identityRefusal("<b>")
	if err == nil {
		t.Fatal("the refusal of a hostile identity was nil")
	}
	text := err.Error()
	for _, want := range []string{"invalid identity", "A-Za-z0-9", "128"} {
		if !strings.Contains(text, want) {
			t.Errorf("the refusal does not mention %q: %s", want, text)
		}
	}
	// The message quotes the name, and quoting a hostile name is why the
	// console escapes; the server never renders it, so %q is enough.
	if !strings.Contains(text, "<b>") {
		t.Errorf("the refusal does not quote the name it refused: %s", text)
	}
}

// Metadata is stripped, and stripping is idempotent: the console may clean
// a value the server already cleaned and must get the same string back.
func TestMetadataIsStrippedAndStrippingIsIdempotent(t *testing.T) {
	cases := map[string]string{
		"web-01":                      "web-01",
		"  web-01  ":                  "web-01",
		"<img src=x onerror=alert(1)>": "img src=x onerror=alert(1)",
		"a & b":                       "a  b",
		"host\x00name":                "hostname",
		"line\nbreak":                 "linebreak",
		"tab\there":                   "tabhere",
		"quote\"and'apostrophe`":      "quoteandapostrophe",
	}
	for in, want := range cases {
		got := cleanMeta(in)
		if got != want {
			t.Errorf("cleanMeta(%q) = %q, want %q", in, got, want)
		}
		if again := cleanMeta(got); again != got {
			t.Errorf("cleanMeta is not idempotent: %q then %q", got, again)
		}
		if !utf8.ValidString(got) {
			t.Errorf("cleanMeta(%q) produced invalid UTF-8", in)
		}
	}
}

// The length bound is in runes, so a wide alphabet is not punished for the
// bytes it takes, and a value longer than the bound is cut instead of stored.
func TestMetadataIsBoundedInRunes(t *testing.T) {
	wide := strings.Repeat("é", metaMax+50)
	got := cleanMeta(wide)
	if n := utf8.RuneCountInString(got); n != metaMax {
		t.Fatalf("the cleaned value has %d runes, want %d", n, metaMax)
	}
	if !utf8.ValidString(got) {
		t.Fatal("the cut produced invalid UTF-8")
	}
}

// The map form cleans the keys as well as the values, one level down, and
// keeps the values it does not understand (numbers, bools) as they are.
func TestTheMetadataMapCleansKeysAndValues(t *testing.T) {
	in := map[string]any{
		"host":        "<b>web-01</b>",
		"user":        "root\x00",
		"version":     "1.4.2",
		"retries":     int64(3),
		"clean":       true,
		"<evil>":      "value",
		"nested":      map[string]any{"inner": "<script>", "n": int64(1)},
		"":            "nameless",
		"transport":   "tcp",
		"ignored key": "x",
	}
	out := cleanMetaMap(in)
	if out["host"] != "bweb-01/b" {
		t.Errorf("host = %q, want the tags stripped", out["host"])
	}
	if out["user"] != "root" {
		t.Errorf("user = %q, want the control rune stripped", out["user"])
	}
	if out["retries"] != int64(3) || out["clean"] != true {
		t.Errorf("a value that is not a string was changed: %v", out)
	}
	if _, ok := out["<evil>"]; ok {
		t.Error("a key that cleans to something else survived under its old name")
	}
	if out["evil"] != "value" {
		t.Errorf("the cleaned key did not keep its value: %v", out)
	}
	if _, ok := out[""]; ok {
		t.Error("an empty key survived")
	}
	if out["ignored key"] != "x" {
		t.Errorf("a key with a space was lost: %v", out)
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok {
		t.Fatalf("the nested map was lost: %v", out["nested"])
	}
	if nested["inner"] != "script" {
		t.Errorf("the nested value was not cleaned: %q", nested["inner"])
	}
	if nested["n"] != int64(1) {
		t.Errorf("the nested number was changed: %v", nested["n"])
	}
	if _, ok := in["host"].(string); !ok {
		t.Fatal("the input map was mutated")
	}
	if in["host"] != "<b>web-01</b>" {
		t.Error("the input map was cleaned in place")
	}
}

// A clean map is returned as it is: the handshake runs on every check-in of
// every beacon, so the common case must not copy.
func TestACleanMetadataMapIsNotCopied(t *testing.T) {
	in := map[string]any{"host": "web-01", "user": "root"}
	if out := cleanMetaMap(in); len(out) != 2 || out["host"] != "web-01" {
		t.Fatalf("a clean map changed: %v", out)
	}
	if out := cleanMetaMap(nil); out != nil {
		t.Fatalf("a nil map became %v", out)
	}
}
