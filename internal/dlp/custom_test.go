package dlp_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/supermcpco/supermcp/internal/dlp"
)

// contract is a detector for an invented contract id, CN- and six digits.
func contract() dlp.CustomDetector {
	return dlp.CustomDetector{Name: "contract_id", Pattern: `\bCN-\d{6}\b`,
		MustMatch: []string{"CN-123456", "see contract CN-000001."}, MustNotMatch: []string{"CN-12345", "XCN-1234567"}}
}

func TestCustomDetectorValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		edit  func(*dlp.CustomDetector)
		field string // empty: valid
	}{
		{name: "valid", edit: func(*dlp.CustomDetector) {}},
		{name: "case-insensitive flag", edit: func(c *dlp.CustomDetector) {
			c.Pattern, c.Flags, c.MustMatch = `\bcn-\d{6}\b`, "i", []string{"CN-123456", "cn-654321"}
		}},
		{name: "a name with capitals", edit: func(c *dlp.CustomDetector) { c.Name = "Contract" }, field: "name"},
		{name: "a one-character name", edit: func(c *dlp.CustomDetector) { c.Name = "c" }, field: "name"},
		{name: "a name with a colon", edit: func(c *dlp.CustomDetector) { c.Name = "custom:x" }, field: "name"},
		{name: "a two-byte pattern", edit: func(c *dlp.CustomDetector) { c.Pattern, c.MustMatch, c.MustNotMatch = `\d`, nil, nil }, field: "pattern"},
		{name: "a pattern over 512 bytes", edit: func(c *dlp.CustomDetector) {
			c.Pattern, c.MustMatch, c.MustNotMatch = strings.Repeat("a", 513), nil, nil
		}, field: "pattern"},
		{name: "a pattern that does not compile", edit: func(c *dlp.CustomDetector) { c.Pattern = `CN-(\d{6}` }, field: "pattern"},
		{name: "a backreference, which RE2 does not have", edit: func(c *dlp.CustomDetector) { c.Pattern = `(CN)-\1` }, field: "pattern"},
		{name: "a pattern matching the empty string", edit: func(c *dlp.CustomDetector) { c.Pattern = `(?:CN-\d{6})?` }, field: "pattern"},
		{name: "a star after a required part", edit: func(c *dlp.CustomDetector) { c.Pattern = `\bCN-\d{6}\d*\b` }},
		{name: "a starred group", edit: func(c *dlp.CustomDetector) { c.Pattern, c.MustMatch, c.MustNotMatch = `(?:CN)*`, nil, nil }, field: "pattern"},
		{name: "an empty alternative", edit: func(c *dlp.CustomDetector) { c.Pattern = `CN-\d{6}|` }, field: "pattern"},
		{name: "only assertions", edit: func(c *dlp.CustomDetector) { c.Pattern, c.MustMatch, c.MustNotMatch = `^\b$`, nil, nil }, field: "pattern"},
		{name: "a zero-minimum repeat", edit: func(c *dlp.CustomDetector) { c.Pattern, c.MustMatch, c.MustNotMatch = `\d{0,6}`, nil, nil }, field: "pattern"},
		{name: "a program too large to run on every call", edit: func(c *dlp.CustomDetector) {
			c.Pattern, c.MustMatch, c.MustNotMatch = `[a-z]{1000}[0-9]{1000}[A-Z]{500}`, nil, nil
		}, field: "pattern"},
		{name: "an unknown flag", edit: func(c *dlp.CustomDetector) { c.Flags = "m" }, field: "flags"},
		{name: "a mustMatch sample that does not match", edit: func(c *dlp.CustomDetector) {
			c.MustMatch = append(c.MustMatch, "contract 12")
		}, field: "mustMatch[2]"},
		{name: "a mustNotMatch sample that matches", edit: func(c *dlp.CustomDetector) {
			c.MustNotMatch = []string{"fine", "CN-999999"}
		}, field: "mustNotMatch[1]"},
		{name: "case matters without the flag", edit: func(c *dlp.CustomDetector) {
			c.MustMatch = []string{"cn-123456"}
		}, field: "mustMatch[0]"},
		{name: "too many samples", edit: func(c *dlp.CustomDetector) {
			c.MustMatch = make([]string, dlp.MaxSamples+1)
			for i := range c.MustMatch {
				c.MustMatch[i] = "CN-123456"
			}
		}, field: "mustMatch"},
		{name: "a sample over the size cap", edit: func(c *dlp.CustomDetector) {
			c.MustMatch = []string{"CN-123456 " + strings.Repeat("x", dlp.MaxSampleBytes)}
		}, field: "mustMatch[0]"},
		{name: "a description over the cap", edit: func(c *dlp.CustomDetector) {
			c.Description = strings.Repeat("é", 501)
		}, field: "description"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := contract()
			tc.edit(&c)
			err := c.Validate()
			if tc.field == "" {
				if err != nil {
					t.Fatalf("refused a valid detector: %v", err)
				}
				return
			}
			var de *dlp.DetectorError
			if !errors.As(err, &de) || !errors.Is(err, dlp.ErrInvalidDetector) {
				t.Fatalf("err = %v, want a DetectorError", err)
			}
			if de.Field != tc.field {
				t.Errorf("field = %q (%s), want %q", de.Field, de.Reason, tc.field)
			}
			// A refusal names a sample by its position, never by its text.
			for _, s := range append(c.MustMatch, c.MustNotMatch...) {
				if len(s) > 3 && strings.Contains(err.Error(), s) {
					t.Errorf("the error quotes a sample: %v", err)
				}
			}
		})
	}
}

func TestCustomDetectorScans(t *testing.T) {
	t.Parallel()
	d, err := dlp.NewCustom(contract())
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != "custom:contract_id" {
		t.Errorf("name = %q", d.Name())
	}
	value := map[string]any{"note": "renew CN-123456 and CN-654321 today", "other": "CN-12"}
	opt := dlp.Options{Detectors: []dlp.Detector{d}}

	masked, res, err := dlp.Apply(value, dlp.ActionMask, opt)
	if err != nil {
		t.Fatal(err)
	}
	if got := masked.(map[string]any)["note"]; got != "renew <redacted:custom:contract_id> and <redacted:custom:contract_id> today" {
		t.Errorf("masked = %q", got)
	}
	if res.Matches != 2 || res.Findings[0].Detector != "custom:contract_id" || res.Findings[0].Path != "$.note" ||
		res.Findings[0].Start != 6 || res.Findings[0].End != 15 {
		t.Errorf("findings = %+v", res.Findings)
	}

	_, _, err = dlp.Apply(value, dlp.ActionRefuse, opt)
	if !errors.Is(err, dlp.ErrRefused) || !strings.Contains(err.Error(), "custom:contract_id") ||
		strings.Contains(err.Error(), "CN-123456") {
		t.Errorf("refusal = %v, want one naming the detector and not the value", err)
	}

	// The byte budget applies as it does to the built-ins: a match past it
	// is not seen, and the scan says it stopped.
	res = dlp.Scan(map[string]any{"a": strings.Repeat("x", 100) + " CN-123456"}, dlp.Options{Detectors: []dlp.Detector{d}, MaxBytes: 64})
	if res.Matches != 0 || !res.Truncated {
		t.Errorf("past the budget: %+v", res)
	}
}

func TestTestPattern(t *testing.T) {
	t.Parallel()
	got, err := dlp.TestPattern(`CN-\d{6}`, "i", []string{"a cn-123456 and CN-000001", "nothing", strings.Repeat("CN-000000 ", 25)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("results = %+v", got)
	}
	if !got[0].Matched || len(got[0].Matches) != 2 || got[0].Matches[0] != (dlp.Span{Start: 2, End: 11}) {
		t.Errorf("first sample = %+v", got[0])
	}
	if got[1].Matched || len(got[1].Matches) != 0 || got[1].Matches == nil {
		t.Errorf("second sample = %+v", got[1])
	}
	if !got[2].More || len(got[2].Matches) != 20 {
		t.Errorf("third sample = %+v, want 20 offsets and more", got[2])
	}

	var de *dlp.DetectorError
	if _, err := dlp.TestPattern(`x*`, "", nil); !errors.As(err, &de) || de.Field != "pattern" {
		t.Errorf("an empty-matching pattern: %v", err)
	}
}

func TestPolicyNamesCustomDetectors(t *testing.T) {
	t.Parallel()
	base := dlp.ScanPolicy{Name: "p", Scan: dlp.StageBoth, Action: dlp.ActionMask, Enabled: true}
	ok := base
	ok.Detectors = []string{dlp.DetectorEmail, "custom:contract_id"}
	if err := ok.Validate(); err != nil {
		t.Errorf("a custom name: %v", err)
	}
	bad := base
	bad.Detectors = []string{"custom:Not A Slug"}
	if err := bad.Validate(); !errors.Is(err, dlp.ErrInvalid) {
		t.Errorf("a malformed custom name: %v", err)
	}

	d, err := dlp.NewCustom(contract())
	if err != nil {
		t.Fatal(err)
	}
	opt, run := ok.OptionsWith("$", map[string]dlp.Detector{"custom:contract_id": d})
	if !run || len(opt.Detectors) != 2 {
		t.Errorf("options = %+v, run = %v", opt, run)
	}
	// A policy whose only detector is a custom one since disabled scans
	// nothing; it does not fall back to every built-in.
	only := base
	only.Detectors = []string{"custom:contract_id"}
	if _, run := only.OptionsWith("$", nil); run {
		t.Error("a policy naming only a missing custom detector would run")
	}
	// Options is the built-ins alone.
	if got := ok.Options("$"); len(got.Detectors) != 1 {
		t.Errorf("Options = %+v", got)
	}
}
