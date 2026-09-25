package dlp_test

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/dlp"
)

// TestScanCapsDenseMatches is the review's case: fifty detectors that
// match every three bytes, over 256 KiB. Before the cap one Apply built a
// Finding per match and allocated about 3 GB. Now each detector stops at
// the cap, the string stands as one match, and the scan allocates a small
// multiple of the value it masks.
func TestScanCapsDenseMatches(t *testing.T) {
	const size = 256 << 10
	value := map[string]any{"blob": strings.Repeat("x", size)}
	dets := make([]dlp.Detector, 0, 50)
	for i := range 50 {
		d, err := dlp.NewCustom(dlp.CustomDetector{Name: fmt.Sprintf("dots_%02d", i), Pattern: "..."})
		if err != nil {
			t.Fatal(err)
		}
		dets = append(dets, d)
	}
	opt := dlp.Options{Detectors: dets, MaxBytes: size}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	masked, res, err := dlp.Apply(value, dlp.ActionMask, opt)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	// The value itself is 256 KiB; the bound leaves room for the masked
	// copy, the scanner and the regexp machines, and none for a span per
	// match.
	const bound = 16 << 20
	if got := after.TotalAlloc - before.TotalAlloc; got > bound {
		t.Errorf("one Apply allocated %d bytes, want under %d", got, bound)
	}
	if got := masked.(map[string]any)["blob"]; got != "<redacted:custom:dots_00>" {
		t.Errorf("masked to %.60q, want the whole string as one token", got)
	}
	if len(res.Findings) != 50 || res.Matches != 50 {
		t.Fatalf("findings = %d, matches = %d, want one per detector", len(res.Findings), res.Matches)
	}
	f := res.Findings[0]
	if f.Rule != "too_many_matches" || f.Start != 0 || f.End != size {
		t.Errorf("finding %+v, want the whole string", f)
	}

	// Refusing is the same: one match per detector, refused whole.
	if _, _, err := dlp.Apply(value, dlp.ActionRefuse, opt); !errors.Is(err, dlp.ErrRefused) {
		t.Errorf("refuse: %v", err)
	}
	// And under the cap nothing changes: every match is its own span.
	d, _ := dlp.NewCustom(dlp.CustomDetector{Name: "contract_id", Pattern: `\bCN-\d{6}\b`})
	few := strings.Repeat("CN-123456 ", 100)
	res = dlp.Scan(map[string]any{"a": few}, dlp.Options{Detectors: []dlp.Detector{d}})
	if res.Matches != 100 || res.Findings[0].Rule != "pattern" || res.Findings[0].End != 9 {
		t.Errorf("a hundred matches: %d, %+v", res.Matches, res.Findings[0])
	}
}

// TestPatternCostCaps: the pattern the review measured at 750 ms per
// 64 KiB, and the largest of its family, are refused at save.
func TestPatternCostCaps(t *testing.T) {
	t.Parallel()
	for _, p := range []string{`[a-z]{1,650}Q`, `[a-z]{1,145}Q`, `.{1,140}Q`} {
		var de *dlp.DetectorError
		if _, err := dlp.CompilePattern(p, ""); !errors.As(err, &de) || de.Field != "pattern" ||
			!strings.Contains(de.Reason, "instructions") {
			t.Errorf("%s: %v, want refused for its size", p, err)
		}
	}
	// The largest accepted program fits a default policy's budget alone.
	if dlp.MaxProgramInsts*dlp.DefaultMaxBytes > dlp.ScanCostBudget {
		t.Errorf("a single detector at the cap (%d) does not fit the budget at %d bytes", dlp.MaxProgramInsts, dlp.DefaultMaxBytes)
	}
	if n, err := dlp.ProgramSize(`\bCN-\d{6}\b`, ""); err != nil || n > 20 {
		t.Errorf("a contract-id pattern compiles to %d instructions, %v", n, err)
	}
}

// TestScanDeadlineRefuses: a scan that reaches its deadline refuses the
// value whatever the action, rather than letting through what it did not
// finish reading.
func TestScanDeadlineRefuses(t *testing.T) {
	t.Parallel()
	d, _ := dlp.NewCustom(dlp.CustomDetector{Name: "contract_id", Pattern: `\bCN-\d{6}\b`})
	for _, act := range []dlp.Action{dlp.ActionAllow, dlp.ActionMask, dlp.ActionRefuse} {
		got, _, err := dlp.Apply(map[string]any{"a": "nothing sensitive"}, act,
			dlp.Options{Detectors: []dlp.Detector{d}, Deadline: time.Now().Add(-time.Millisecond)})
		if !errors.Is(err, dlp.ErrRefused) || !errors.Is(err, dlp.ErrScanDeadline) || got != nil {
			t.Errorf("%s past the deadline: %v, %v", act, got, err)
		}
	}
	// A deadline not yet reached changes nothing.
	got, _, err := dlp.Apply("renew CN-123456", dlp.ActionMask,
		dlp.Options{Detectors: []dlp.Detector{d}, Deadline: time.Now().Add(time.Minute)})
	if err != nil || got != "renew <redacted:custom:contract_id>" {
		t.Errorf("inside the deadline: %v, %v", got, err)
	}
}
