package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/supermcpco/supermcp/pkg/adapter"
	v1 "github.com/supermcpco/supermcp/pkg/adapter/v1"
	"github.com/supermcpco/supermcp/pkg/adapter/v1compat"
)

const adapterUsage = `Usage: supermcp adapter <subcommand> [flags]

Subcommands:
  convert   convert legacy v1 JSON adapters to v2 YAML
  validate  validate adapter directories
  index     generate the catalog index
  record    record cassettes against a live upstream
  test      replay every cassette offline
`

func adapterCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, adapterUsage)
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "convert":
		return adapterConvert(args[1:])
	case "validate":
		return adapterValidate(args[1:])
	case "record":
		return adapterRecord(args[1:])
	case "test":
		return adapterTest(args[1:])
	case "index":
		return adapterIndex(args[1:])
	default:
		fmt.Fprint(os.Stderr, adapterUsage)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func adapterConvert(args []string) error {
	fs := flag.NewFlagSet("adapter convert", flag.ContinueOnError)
	in := fs.String("in", "", "directory of v1 adapters (<region>/<slug>.json)")
	out := fs.String("out", "adapters", "output root (<region>/<slug>/adapter.yaml)")
	report := fs.String("report", "", "write findings as JSON to this file")
	failOnBlocker := fs.Bool("fail-on-blocker", true, "exit non-zero if any adapter has a blocker")
	skip := fs.String("skip", "", "comma-separated slugs to leave out of the output and the report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	files, err := v1.LoadDir(*in)
	if err != nil {
		return err
	}
	// A slug in -skip is still read, so a typo fails here instead of
	// quietly shipping the adapter it meant to leave out.
	if *skip != "" {
		drop := map[string]bool{}
		for _, s := range strings.Split(*skip, ",") {
			if s = strings.TrimSpace(s); s != "" {
				drop[s] = true
			}
		}
		kept := files[:0]
		for _, f := range files {
			if drop[f.Adapter.Slug] {
				delete(drop, f.Adapter.Slug)
				continue
			}
			kept = append(kept, f)
		}
		if len(drop) > 0 {
			missing := make([]string, 0, len(drop))
			for s := range drop {
				missing = append(missing, s)
			}
			sort.Strings(missing)
			return fmt.Errorf("-skip names adapters not in %s: %s", *in, strings.Join(missing, ", "))
		}
		files = kept
	}
	results, err := v1compat.ConvertAll(files)
	if err != nil {
		return err
	}
	var findings []v1compat.Finding
	counts := map[v1compat.Level]int{}
	blocked := 0
	for _, r := range results {
		findings = append(findings, r.Findings...)
		for _, f := range r.Findings {
			counts[f.Level]++
		}
		if r.HasBlockers() {
			blocked++
			continue
		}
		dir := filepath.Join(*out, filepath.FromSlash(v1compat.OutputDir(r.Adapter)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		data, err := adapter.Marshal(r.Adapter)
		if err != nil {
			return fmt.Errorf("%s: %w", r.Adapter.Metadata.Slug, err)
		}
		if err := os.WriteFile(filepath.Join(dir, adapter.FileName), data, 0o644); err != nil {
			return err
		}
	}
	if *report != "" {
		b, _ := json.MarshalIndent(findings, "", "  ")
		if err := os.WriteFile(*report, b, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("converted %d/%d adapters → %s (%d info, %d review, %d blocker)\n",
		len(results)-blocked, len(results), *out, counts[v1compat.Info], counts[v1compat.Review], counts[v1compat.Blocker])
	for _, f := range findings {
		if f.Level != v1compat.Info {
			fmt.Printf("  %-7s %-24s %-40s %s\n", f.Level, f.Slug, f.Path, f.Message)
		}
	}
	if blocked > 0 && *failOnBlocker {
		return fmt.Errorf("%d adapter(s) not written because of blockers", blocked)
	}
	return nil
}

func adapterValidate(args []string) error {
	fs := flag.NewFlagSet("adapter validate", flag.ContinueOnError)
	strict := fs.Bool("strict", false, "treat warnings as errors")
	format := fs.String("format", "text", "text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	roots := fs.Args()
	if len(roots) == 0 {
		roots = []string{"adapters"}
	}
	var all []adapter.Issue
	n := 0
	for _, root := range roots {
		files, err := loadAny(root)
		if err != nil {
			return err
		}
		n += len(files)
		all = append(all, adapter.ValidateAll(files)...)
	}
	errors, warnings := 0, 0
	for _, is := range all {
		if is.Severity == adapter.SeverityError {
			errors++
		} else {
			warnings++
		}
	}
	switch *format {
	case "json":
		b, _ := json.MarshalIndent(all, "", "  ")
		fmt.Println(string(b))
	default:
		for _, is := range all {
			fmt.Printf("%s: %s: [%s] %s\n", is.File, is.Severity, is.Rule, is.Message)
		}
		fmt.Printf("%d adapters, %d errors, %d warnings\n", n, errors, warnings)
	}
	if errors > 0 || (*strict && warnings > 0) {
		return fmt.Errorf("validation failed")
	}
	return nil
}

func adapterIndex(args []string) error {
	fs := flag.NewFlagSet("adapter index", flag.ContinueOnError)
	root := fs.String("root", "adapters", "adapters root")
	out := fs.String("out", "", "write index JSON here (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files, err := adapter.LoadDir(*root)
	if err != nil {
		return explainMissingRoot(*root, err)
	}
	idx, err := adapter.BuildIndex(files)
	if err != nil {
		return err
	}
	// The index being replaced holds each slug's earlier hashes. Re-sync
	// only moves a connector forward along that history, so it must
	// survive regeneration.
	if *out != "" {
		prev, err := readIndex(*out)
		if err != nil {
			return err
		}
		adapter.CarryHistory(prev, idx)
	}
	b, _ := json.MarshalIndent(idx, "", "  ")
	b = append(b, '\n')
	if *out == "" {
		fmt.Print(string(b))
		return nil
	}
	return os.WriteFile(*out, b, 0o644)
}

// readIndex reads an index file, or returns nil when there is none yet.
func readIndex(path string) (*adapter.Index, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a path the operator named on the command line
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var idx adapter.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &idx, nil
}

// explainMissingRoot answers the question somebody asks when they run
// this inside the released image: the catalogue it serves is compiled
// into the binary, and these commands are for authoring adapters in a
// working tree, so there is nothing on disk to read.
func explainMissingRoot(path string, err error) error {
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fmt.Errorf("%s: no such directory.\n"+
		"The adapter commands read adapter sources from a working tree. The catalogue this\n"+
		"binary serves is compiled in and is not on disk, so there is nothing to read here.\n"+
		"Run this from a checkout of the repository, or name a directory:\n"+
		"  supermcp adapter validate path/to/adapters", path)
}

// loadAny accepts an adapters root, an adapter directory, or a single
// adapter.yaml.
func loadAny(p string) ([]*adapter.File, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, explainMissingRoot(p, err)
	}
	if !st.IsDir() {
		f, err := adapter.LoadFile(p)
		if err != nil {
			return nil, err
		}
		return []*adapter.File{f}, nil
	}
	if _, err := os.Stat(filepath.Join(p, adapter.FileName)); err == nil {
		f, err := adapter.LoadFile(filepath.Join(p, adapter.FileName))
		if err != nil {
			return nil, err
		}
		return []*adapter.File{f}, nil
	}
	return adapter.LoadDir(p)
}
