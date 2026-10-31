package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/thesyntax1/UmbraC2/server/internal/store"
)

// TestTheSameKeyOpensOtherDoors checks that the vault says when one
// secret serves on more than one host — and says it by digest, never
// by value.
func TestTheSameKeyOpensOtherDoors(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	now := time.Now().UTC()
	put := func(agent, account, target, kind, digest string, at time.Time) {
		st.AddCredential(&store.Credential{
			AgentID: agent, Account: account, Target: target, Kind: kind,
			Digest: digest, Collected: at,
		})
	}
	put("web-01", "svc-sql", "db.corp", "password", strings.Repeat("aa", 32), now)
	put("db-02", "svc-sql", "db.corp", "password", strings.Repeat("aa", 32), now.Add(time.Hour))
	// The same account on one host twice is bookkeeping, not reuse.
	put("web-01", "svc-sql", "db.corp", "password", strings.Repeat("bb", 32), now)
	put("web-01", "svc-sql2", "db.corp", "password", strings.Repeat("bb", 32), now)

	groups := st.CredentialReuse()
	if len(groups) != 1 {
		t.Fatalf("one key was reused across hosts; the vault says %d groups", len(groups))
	}
	group := groups[0]
	if group.Digest != strings.Repeat("aa", 6) {
		t.Fatalf("the group says too much or too little of the digest: %q", group.Digest)
	}
	if group.Count != 2 || len(group.Hosts) != 2 || group.Kind != "password" {
		t.Fatalf("the group miscounted: %+v", group)
	}
	if group.Hosts[0] != "db-02" || group.Hosts[1] != "web-01" {
		t.Fatalf("the group names the wrong doors: %+v", group.Hosts)
	}
	if !group.Last.Equal(now.Add(time.Hour)) {
		t.Fatalf("the group forgot when the key came home last: %+v", group)
	}
}
