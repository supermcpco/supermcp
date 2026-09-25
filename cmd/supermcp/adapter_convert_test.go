package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var corpusDir = filepath.Join("..", "..", "pkg", "adapter", "v1", "testdata", "corpus")

// The catalogue leaves out adapters whose authentication is not
// implemented; they stay in the corpus for the converter tests. A skipped
// slug is neither written nor mentioned in the report.
func TestConvertSkipLeavesAnAdapterOutOfTheCatalogue(t *testing.T) {
	out := t.TempDir()
	report := filepath.Join(out, "report.json")
	if err := adapterConvert([]string{"-in", corpusDir, "-out", out, "-report", report, "-skip", "sorare, immobilienscout24"}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"intl/sorare", "de/immobilienscout24"} {
		if _, err := os.Stat(filepath.Join(out, dir)); !os.IsNotExist(err) {
			t.Errorf("%s was written although it was skipped (stat: %v)", dir, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "intl", "ghost", "adapter.yaml")); err != nil {
		t.Errorf("an adapter that was not skipped is missing: %v", err)
	}
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var findings []struct{ Slug string }
	if err := json.Unmarshal(b, &findings); err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Slug == "sorare" || f.Slug == "immobilienscout24" {
			t.Errorf("the report still has a finding for skipped %s", f.Slug)
		}
	}
}

// A misspelt slug would otherwise ship the adapter it meant to leave out.
func TestConvertSkipRefusesASlugThatIsNotInTheCorpus(t *testing.T) {
	err := adapterConvert([]string{"-in", corpusDir, "-out", t.TempDir(), "-skip", "sorare,imobilienscout24"})
	if err == nil || !strings.Contains(err.Error(), "imobilienscout24") {
		t.Fatalf("an unknown slug in -skip was accepted: %v", err)
	}
}
