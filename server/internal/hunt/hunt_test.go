package hunt_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thesyntax1/UmbraC2/server/internal/hunt"
)

func TestTheCatalogueKeepsTheIndicators(t *testing.T) {
	c := hunt.New()
	first, err := c.Add(hunt.Indicator{
		Kind:  hunt.KindHash,
		Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Label: "the loader of the ticket of March",
		Note:  "seen on web-01",
		Source: "TICKET-1138",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if first.ID == "" {
		t.Fatalf("the indicator has no id: %+v", first)
	}
	second, err := c.Add(hunt.Indicator{Kind: hunt.KindPath, Value: "/tmp/.loader"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if second.ID == first.ID {
		t.Fatalf("two indicators share the id %q", first.ID)
	}
	if got := len(c.List()); got != 2 {
		t.Fatalf("the catalogue holds %d indicators, want 2", got)
	}
}

func TestTheSameIndicatorIsNotAddedTwice(t *testing.T) {
	c := hunt.New()
	value := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if _, err := c.Add(hunt.Indicator{Kind: hunt.KindHash, Value: value}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := c.Add(hunt.Indicator{Kind: hunt.KindHash, Value: value}); err == nil {
		t.Fatalf("the same indicator was added twice")
	}
	if got := len(c.List()); got != 1 {
		t.Fatalf("the catalogue holds %d indicators, want 1", got)
	}
}

func TestAnIndicatorWithoutAValueIsRefused(t *testing.T) {
	c := hunt.New()
	if _, err := c.Add(hunt.Indicator{Kind: hunt.KindPath, Value: "   "}); err == nil {
		t.Fatalf("an indicator without a value was accepted")
	}
	if _, err := c.Add(hunt.Indicator{Kind: "smoke-signal", Value: "x"}); err == nil {
		t.Fatalf("an indicator of an unknown kind was accepted")
	}
}

func TestAHashIsRecognisedByItsShape(t *testing.T) {
	c := hunt.New()
	ind, err := c.Add(hunt.Indicator{
		Value: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if ind.Kind != hunt.KindHash {
		t.Fatalf("the kind of the indicator is %q, want %q", ind.Kind, hunt.KindHash)
	}
}

func TestTheSearchFindsTheIndicatorTheOperatorRemembers(t *testing.T) {
	c := hunt.New()
	if _, err := c.Add(hunt.Indicator{
		Kind:   hunt.KindHash,
		Value:  "aaaa",
		Label:  "the loader of March",
		Source: "TICKET-1138",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := c.Add(hunt.Indicator{Kind: hunt.KindPath, Value: "/tmp/other"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := len(c.Search("march", "")); got != 1 {
		t.Fatalf("the search found %d indicators, want 1", got)
	}
	if got := len(c.Search("", hunt.KindPath)); got != 1 {
		t.Fatalf("the search by kind found %d indicators, want 1", got)
	}
	if got := len(c.Search("", "")); got != 2 {
		t.Fatalf("the whole catalogue holds %d indicators, want 2", got)
	}
}

func TestTheCatalogueSurvivesTheDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hunt.json")
	c := hunt.New()
	c.SetPath(path)
	if _, err := c.Add(hunt.Indicator{Kind: hunt.KindMutex, Value: "Global\\LoadOrder"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	back := hunt.New()
	back.SetPath(path)
	if err := back.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := len(back.List()); got != 1 {
		t.Fatalf("the catalogue read back holds %d indicators, want 1", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the catalogue is written with the mode %o, want 600", perm)
	}
}

func TestAnIndicatorLeavesTheCatalogue(t *testing.T) {
	c := hunt.New()
	ind, err := c.Add(hunt.Indicator{Kind: hunt.KindProcess, Value: "loader.exe"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := c.Remove(ind.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := c.Remove(ind.ID); err == nil {
		t.Fatalf("the indicator was removed twice")
	}
	if got := len(c.List()); got != 0 {
		t.Fatalf("the catalogue holds %d indicators, want 0", got)
	}
}

func TestTheHitsOfAnIndicatorAreCounted(t *testing.T) {
	c := hunt.New()
	ind, err := c.Add(hunt.Indicator{Kind: hunt.KindPath, Value: "/tmp/.loader"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !c.CountHits(ind.ID, 3) {
		t.Fatalf("the hits of an unknown indicator were counted")
	}
	got, ok := c.Get(ind.ID)
	if !ok {
		t.Fatalf("the indicator is gone")
	}
	if got.Hits != 3 {
		t.Fatalf("the indicator was found %d times, want 3", got.Hits)
	}
}
