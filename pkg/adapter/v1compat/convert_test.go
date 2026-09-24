package v1compat

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/pkg/adapter"
	v1 "github.com/supermcpco/supermcp/pkg/adapter/v1"
)

func loadCorpus(t *testing.T) []v1.File {
	t.Helper()
	files, err := v1.LoadDir(filepath.Join("..", "v1", "testdata", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 257 {
		t.Fatalf("expected 257 adapters, got %d", len(files))
	}
	return files
}

// TestConvertCorpus converts every v1 adapter, round-trips it through YAML
// and reports findings. Blockers fail the test except for the two adapters
// known to need hand authoring.
func TestConvertCorpus(t *testing.T) {
	files := loadCorpus(t)
	results, err := ConvertAll(files)
	if err != nil {
		t.Fatal(err)
	}
	knownBlockers := map[string]bool{}
	counts := map[Level]int{}
	byMessage := map[string]int{}
	toolCount := 0
	for i, r := range results {
		toolCount += len(r.Adapter.Tools)
		for _, f := range r.Findings {
			counts[f.Level]++
			key := string(f.Level) + " " + generalise(f.Message)
			byMessage[key]++
			if f.Level == Blocker && !knownBlockers[f.Slug] {
				t.Errorf("%s: BLOCKER %s: %s", f.Slug, f.Path, f.Message)
			}
		}
		out, err := adapter.Marshal(r.Adapter)
		if err != nil {
			t.Fatalf("%s: marshal: %v", files[i].Adapter.Slug, err)
		}
		back, err := adapter.Parse(out)
		if err != nil {
			t.Fatalf("%s: re-parse: %v\n%s", files[i].Adapter.Slug, err, out)
		}
		if len(back.Tools) != len(r.Adapter.Tools) {
			t.Errorf("%s: tool count changed on round trip", files[i].Adapter.Slug)
		}
		out2, _ := adapter.Marshal(back)
		if string(out) != string(out2) {
			t.Errorf("%s: YAML is not stable across round trip", files[i].Adapter.Slug)
		}
	}
	if toolCount != 2385 {
		t.Errorf("expected 2385 tools, got %d", toolCount)
	}
	keys := make([]string, 0, len(byMessage))
	for k := range byMessage {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("findings: %d info, %d review, %d blocker", counts[Info], counts[Review], counts[Blocker])
	for _, k := range keys {
		t.Logf("%4d  %s", byMessage[k], k)
	}
}

// generalise collapses variable parts of a message so similar findings
// group together in the summary.
func generalise(msg string) string {
	if i := strings.Index(msg, ":"); i > 0 && i < 40 {
		return msg[:i]
	}
	if i := strings.Index(msg, " %"); i > 0 {
		return msg[:i]
	}
	words := strings.Fields(msg)
	if len(words) > 6 {
		return strings.Join(words[:6], " ")
	}
	return msg
}
