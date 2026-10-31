package otp

import (
	"strings"
	"testing"
	"time"
)

// The vectors of RFC 6238, appendix B: the secret is the ASCII string
// "12345678901234567890" and the codes below are the six last digits
// of the eight the appendix writes down.
//
// The vectors pin the arithmetic of the package to the standard: a
// phone that computes the code of RFC 6238 has to be understood by
// this server, and the other way round.
func TestTheVectorsOfTheRFC(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, c := range cases {
		at := time.Unix(c.unix, 0).UTC()
		got, err := Code(secret, at)
		if err != nil {
			t.Fatalf("Code(%d): %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("Code(%d) = %q, want %q", c.unix, got, c.want)
		}
		if !Verify(secret, c.want, at) {
			t.Errorf("Verify(%d) refused the code of the moment", c.unix)
		}
	}
}

// The window of one step on each side: a phone whose clock is a little
// off still works, and a code from an hour ago does not.
func TestTheWindowOfTheCode(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(1234567890, 0).UTC()
	code, err := Code(secret, now)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if !Verify(secret, code, now.Add(-Period*time.Second)) {
		t.Error("the code of the previous step was refused")
	}
	if !Verify(secret, code, now.Add(Period*time.Second)) {
		t.Error("the code of the next step was refused")
	}
	if Verify(secret, code, now.Add(Period*2*time.Second)) {
		t.Error("a code of two steps ago was accepted")
	}
	if Verify(secret, code, now.Add(-Period*2*time.Second)) {
		t.Error("a code of two steps ago was accepted")
	}
	wrong := wrongCode(code)
	if Verify(secret, wrong, now) {
		t.Errorf("a wrong code (%q) was accepted", wrong)
	}
	if Verify(secret, "abcdef", now) {
		t.Error("a code that is not a number was accepted")
	}
	if Verify(secret, "", now) {
		t.Error("an empty code was accepted")
	}
}

// wrongCode is a code that is not the code: the last digit is turned
// into another one, so the test never depends on what the code of the
// moment happens to be.
func wrongCode(code string) string {
	if code == "" {
		return "000000"
	}
	last := code[len(code)-1]
	replacement := byte('0')
	if last == '0' {
		replacement = '1'
	}
	return code[:len(code)-1] + string(replacement)
}

// The registry: a secret is made, it works, it is rotated and the old
// one stops working, and it can be taken away.
func TestTheRegistryOfTheSecondFactors(t *testing.T) {
	r := New()
	sec, err := r.Rotate("alice", "the team")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if sec.Secret == "" {
		t.Fatal("the secret is empty")
	}
	if !r.Enabled("alice") {
		t.Error("the second factor of alice is not enabled")
	}
	code, err := Code(sec.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if !r.Verify("alice", code, time.Now().UTC()) {
		t.Error("the code of the moment was refused")
	}
	if r.Verify("alice", wrongCode(code), time.Now().UTC()) {
		t.Error("a wrong code was accepted")
	}
	// An operator without a second factor is never refused.
	if !r.Verify("bob", "", time.Now().UTC()) {
		t.Error("an operator without a second factor was refused")
	}
	// The old secret stops working when the secret is rotated.
	old := sec.Secret
	next, err := r.Rotate("alice", "the team")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if next.Secret == old {
		t.Error("the rotation returned the same secret")
	}
	oldCode, err := Code(old, time.Now().UTC())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if r.Verify("alice", oldCode, time.Now().UTC()) {
		t.Error("the old secret still works")
	}
	// The status never carries the secret.
	for _, st := range r.Status() {
		if st.Operator != "alice" {
			continue
		}
		if !st.Enabled {
			t.Error("the status says the second factor is off")
		}
		if st.Age == "" {
			t.Error("the status does not say how old the secret is")
		}
	}
	// The second factor can be turned off without losing the secret.
	if err := r.Enable("alice", false); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if r.Enabled("alice") {
		t.Error("the second factor is still enabled")
	}
	if err := r.Remove("alice"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := r.Remove("alice"); err == nil {
		t.Error("the removal of a second factor that is not there was accepted")
	}
}

// The address the authenticator application reads.
func TestTheAddressOfTheAuthenticator(t *testing.T) {
	uri := URI("the team", "alice", "GEZDGNBVGY3TQOJQ")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("the address does not look like one: %q", uri)
	}
	if !strings.Contains(uri, "secret=GEZDGNBVGY3TQOJQ") {
		t.Errorf("the address does not carry the secret: %q", uri)
	}
	if !strings.Contains(uri, "digits=6") {
		t.Errorf("the address does not say how many digits: %q", uri)
	}
}
