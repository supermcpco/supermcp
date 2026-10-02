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

// TestReadHints checks what the converter says about tools sent with a
// writing method: a read gets readOnlyHint true, a tool named like a read
// that is known to write gets false, and everything else is left to the
// server's derivation.
func TestReadHints(t *testing.T) {
	results, err := ConvertAll(loadCorpus(t))
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]*adapter.Tool{}
	for _, r := range results {
		for i := range r.Adapter.Tools {
			tools[r.Adapter.Tools[i].Name] = &r.Adapter.Tools[i]
		}
	}
	hint := func(name string) string {
		tl, ok := tools[name]
		switch {
		case !ok:
			t.Fatalf("no tool %s in the corpus", name)
		case tl.Annotations == nil || tl.Annotations.ReadOnlyHint == nil:
			return "none"
		case *tl.Annotations.ReadOnlyHint:
			return "true"
		}
		return "false"
	}
	for name, want := range map[string]string{
		"teamleader_list_companies":  "true",  // POST that reads
		"plaid_item_get":             "true",  // POST that reads, not named like one
		"opentable_autocomplete":     "true",  // PUT that reads
		"telegram_bot_get_updates":   "false", // named like a read, drops what it read
		"apollo_search_people":       "false", // named like a read, costs credits
		"paystack_create_refund":     "none",  // POST that writes
		"freshdesk_delete_ticket":    "none",  // DELETE
		"hackernews_get_item":        "none",  // GET needs no hint
		"slab_search_posts":          "none",  // GraphQL query
		"freshservice_update_ticket": "none",  // PUT that writes
	} {
		if got := hint(name); got != want {
			t.Errorf("%s: readOnlyHint %s, want %s", name, got, want)
		}
	}
	// Every hint comes from the table, none from a name alone.
	for name, tl := range tools {
		if _, listed := readOnlyTools[name]; !listed && tl.Annotations != nil {
			t.Errorf("%s has annotations but is not in readOnlyTools", name)
		}
	}
	// A listed tool that is gone, or no longer sent with a writing method,
	// is a stale entry.
	for name := range readOnlyTools {
		tl, ok := tools[name]
		if !ok {
			t.Errorf("readOnlyTools lists %s, which is not in the corpus", name)
			continue
		}
		switch tl.Operation.Method {
		case "POST", "PUT", "PATCH":
		default:
			t.Errorf("readOnlyTools lists %s, which is sent as %q", name, tl.Operation.Method)
		}
	}
}

// TestReadNamedToolMustBeListed checks that a tool named like a read and
// sent as POST stops the conversion rather than being published as a read
// on the strength of its name.
func TestReadNamedToolMustBeListed(t *testing.T) {
	c := &converter{slug: "acme"}
	tl := adapter.Tool{Name: "acme_get_or_create_contact", Operation: adapter.Operation{Method: "POST"}}
	if got := c.readHint(&tl); got != nil {
		t.Errorf("unlisted tool got a hint: %+v", got)
	}
	if len(c.findings) != 1 || c.findings[0].Level != Blocker {
		t.Errorf("findings = %+v, want one blocker", c.findings)
	}
}
