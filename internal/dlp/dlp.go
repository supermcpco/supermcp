// Package dlp decides what a tool call is allowed to carry. It runs a set
// of detectors over a call's arguments on the way out and over its result
// on the way back, and applies the organisation's policy: record what was
// found, mask it, or refuse the call.
//
// It supersedes the masking floor in internal/audit, which redacts a few
// patterns on the way into the record and nothing at all on the way to an
// upstream. Nothing here removes that floor: an organisation with no
// policy is recorded exactly as before.
//
// The scan is bounded. A result of any size cannot be examined in full on
// the request path, so a scan stops at a byte budget and says so, rather
// than reading a prefix and reporting a clean bill of health.
package dlp

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultMaxBytes is how much of one value a scan reads when a policy
// names no limit. It matches what the audit stream keeps of a result, so
// the two agree about what they have seen.
const DefaultMaxBytes = 64 << 10

// maxFindings caps what one scan reports. The mask still covers every
// match; this bounds the size of the record, not the redaction.
const maxFindings = 100

// ErrRefused is returned when a policy's action is refuse and the scan
// found something. The message names the kinds, never the values.
var ErrRefused = errors.New("blocked by a data-loss prevention policy")

// ErrScanDeadline is why a scan that ran out of time is refused, whatever
// the policy's action: a value nobody finished reading may carry exactly
// what the policy is for. It is always wrapped with ErrRefused.
var ErrScanDeadline = errors.New("the data-loss scan did not finish in time")

// ruleTooMany names the finding that stands for a string in which one
// detector matched more than maxFindings times. The whole string is
// treated as the match: a value that dense with matches is the thing
// itself, and collecting a span per match is what would cost the memory.
const ruleTooMany = "too_many_matches"

// Confidence is how much the detector is claiming. It is advisory: a
// policy acts on detectors, not on confidence, but a finding at low
// confidence is the first thing to look at when a rule is too noisy.
type Confidence string

// The three levels a detector may report.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Action is what a policy does with what was found.
type Action string

// The three actions. Allow records and passes the value through
// unchanged; mask replaces each match; refuse stops the call.
const (
	ActionAllow  Action = "allow"
	ActionMask   Action = "mask"
	ActionRefuse Action = "refuse"
)

// Match is one hit inside one string, in byte offsets.
type Match struct {
	Start      int
	End        int
	Confidence Confidence
	// Rule names which of a detector's patterns matched, for a detector
	// that has more than one.
	Rule string
}

// Detector looks for one class of sensitive value. Implementations are
// stateless and safe for concurrent use: one instance serves every request.
type Detector interface {
	Name() string
	Kind() Kind
	// Find returns every match in s. It returns all of them, not a sample:
	// masking a prefix of the matches would leak the rest.
	Find(s string) []Match
}

// Finding says what was found, where, and how sure the detector is. It
// deliberately carries no part of the value: an excerpt would put the
// thing being protected into whatever stores the finding.
type Finding struct {
	Detector   string     `json:"detector"`
	Rule       string     `json:"rule,omitempty"`
	Kind       Kind       `json:"kind"`
	Confidence Confidence `json:"confidence"`
	// Path is where in the value the match sits, as $.customer.card or
	// $.items[0]. A field name is metadata; the value it held is not here.
	Path  string `json:"path"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// Options configure one scan.
type Options struct {
	// Detectors to run. Empty means every built-in.
	Detectors []Detector
	// MaxBytes caps the text examined across the whole value. Zero means
	// DefaultMaxBytes; a negative value means no limit, which belongs in a
	// test or an offline job and not on the request path.
	MaxBytes int
	// Root prefixes every path. Empty means "$".
	Root string
	// Deadline, when set, is when the scan must have finished. It is
	// checked before each detector runs over each string; a scan that
	// reaches it stops and Apply refuses the value with ErrScanDeadline.
	Deadline time.Time
}

// Result is what one scan saw.
type Result struct {
	Findings []Finding `json:"findings" nullable:"false"`
	// Matches counts every match, including those past the findings cap.
	Matches int `json:"matches"`
	// Bytes is how much text was examined.
	Bytes int `json:"bytes"`
	// Truncated says the budget ran out before the value did. A truncated
	// scan with no findings is not a clean one.
	Truncated bool `json:"truncated"`
}

// scanner carries one walk's budget and its findings.
type scanner struct {
	detectors []Detector
	secretKey bool
	mask      bool
	budget    int
	deadline  time.Time
	timedOut  bool
	res       Result
}

// Scan reports what the detectors find in v without changing it.
func Scan(v any, opt Options) Result {
	_, res, _ := Apply(v, ActionAllow, opt)
	return res
}

// Apply runs the detectors over v and returns what the action allows
// through: v itself for allow, a masked copy for mask, and nil with
// ErrRefused for refuse when anything was found.
//
// The copy is shallow where it can be: a container with nothing to mask
// inside it is returned as it came in.
func Apply(v any, act Action, opt Options) (any, Result, error) {
	s := newScanner(opt, act == ActionMask)
	out, _ := s.walk(v, s.root(opt))
	if s.timedOut {
		return nil, s.res, fmt.Errorf("%w: %w", ErrRefused, ErrScanDeadline)
	}
	if act == ActionRefuse && s.res.Matches > 0 {
		return nil, s.res, fmt.Errorf("%w: %s", ErrRefused, strings.Join(s.res.Kinds(), ", "))
	}
	return out, s.res, nil
}

// Clean reports that the value carried nothing sensitive and that the
// whole of it was read. A truncated scan is never clean, because the part
// nobody looked at is exactly where the answer would have been.
func (r Result) Clean() bool { return r.Matches == 0 && !r.Truncated }

// Kinds lists the distinct kinds found, sorted, for a log line or an audit
// event.
func (r Result) Kinds() []string {
	seen := make(map[Kind]bool, len(r.Findings))
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !seen[f.Kind] {
			seen[f.Kind] = true
			out = append(out, string(f.Kind))
		}
	}
	sort.Strings(out)
	return out
}

func newScanner(opt Options, mask bool) *scanner {
	dets := opt.Detectors
	if len(dets) == 0 {
		dets = builtins
	}
	s := &scanner{mask: mask, budget: opt.MaxBytes, deadline: opt.Deadline}
	switch {
	case s.budget == 0:
		s.budget = DefaultMaxBytes
	case s.budget < 0:
		s.budget = math.MaxInt
	}
	s.detectors = make([]Detector, 0, len(dets))
	for _, d := range dets {
		if d.Name() == DetectorSecretKey {
			s.secretKey = true
			continue
		}
		s.detectors = append(s.detectors, d)
	}
	return s
}

func (s *scanner) root(opt Options) string {
	if opt.Root == "" {
		return "$"
	}
	return opt.Root
}

// walk descends the value and returns it, together with whether masking
// rewrote anything inside it. A container nothing was taken out of is
// handed back as it came in rather than copied.
//
// Numbers are not scanned: a card number that survived a JSON round trip
// as a number has already lost digits to the float it was parsed into, and
// reading it back would report a value the caller never sent.
func (s *scanner) walk(v any, path string) (any, bool) {
	switch x := v.(type) {
	case nil:
		return nil, false
	case string:
		out := s.text(x, path)
		return out, out != x
	case map[string]any:
		return s.object(x, path)
	case []any:
		return s.array(x, path)
	}
	return v, false
}

func (s *scanner) object(m map[string]any, path string) (any, bool) {
	var out map[string]any
	for _, k := range sortedKeys(m) {
		child := path + "." + k
		// A field that says what it holds is redacted whatever is in it,
		// including a whole object, and is not descended into.
		if s.secretKey && looksSecret(k) {
			s.record(Finding{Detector: DetectorSecretKey, Rule: "field_name", Kind: KindCredential,
				Confidence: ConfidenceHigh, Path: child})
			if !s.mask {
				continue
			}
			out = copyOnWrite(out, m)
			out[k] = redaction(KindCredential)
			continue
		}
		got, changed := s.walk(m[k], child)
		if changed {
			out = copyOnWrite(out, m)
			out[k] = got
		}
	}
	if out != nil {
		return out, true
	}
	return m, false
}

func (s *scanner) array(a []any, path string) (any, bool) {
	var out []any
	for i, e := range a {
		got, changed := s.walk(e, fmt.Sprintf("%s[%d]", path, i))
		if changed {
			if out == nil {
				out = slices.Clone(a)
			}
			out[i] = got
		}
	}
	if out != nil {
		return out, true
	}
	return a, false
}

// text scans one string within the remaining budget and returns it, masked
// if that is the action.
func (s *scanner) text(in, path string) string {
	if in == "" || s.timedOut {
		return in
	}
	if s.budget <= 0 {
		s.res.Truncated = true
		return in
	}
	part := in
	if len(part) > s.budget {
		// Cut on a rune boundary: half a rune at the end of the window is
		// not text any detector should be asked about.
		part = in[:runeBoundary(in, s.budget)]
		s.res.Truncated = true
	}
	s.budget -= len(part)
	s.res.Bytes += len(part)

	var hits []Finding
	for _, d := range s.detectors {
		if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
			s.timedOut = true
			return in
		}
		ms := d.Find(part)
		if len(ms) > maxFindings {
			// Detectors stop at maxFindings+1 (see findCap), so this is
			// the overflow: the whole string stands as one match, masked
			// or refused whole, and no span per match is ever collected.
			hits = append(hits, Finding{Detector: d.Name(), Rule: ruleTooMany, Kind: d.Kind(),
				Confidence: ms[0].Confidence, Path: path, Start: 0, End: len(in)})
			continue
		}
		for _, m := range ms {
			hits = append(hits, Finding{Detector: d.Name(), Rule: m.Rule, Kind: d.Kind(),
				Confidence: m.Confidence, Path: path, Start: m.Start, End: m.End})
		}
	}
	if len(hits) == 0 {
		return in
	}
	slices.SortFunc(hits, func(a, b Finding) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return a.End - b.End
	})
	for _, f := range hits {
		s.record(f)
	}
	if !s.mask {
		return in
	}
	return maskSpans(in, hits)
}

func (s *scanner) record(f Finding) {
	s.res.Matches++
	if len(s.res.Findings) < maxFindings {
		s.res.Findings = append(s.res.Findings, f)
	}
}

// --- helpers ---------------------------------------------------------------

// maskSpans replaces each match with a token naming what was taken out.
// Overlapping matches — a number two detectors both claim — are merged, so
// the output never contains a token nested inside another one.
func maskSpans(in string, hits []Finding) string {
	var b strings.Builder
	b.Grow(len(in))
	last := 0
	for i := 0; i < len(hits); {
		start, end, kind := hits[i].Start, hits[i].End, hits[i].Kind
		j := i + 1
		for ; j < len(hits) && hits[j].Start < end; j++ {
			if hits[j].End > end {
				end = hits[j].End
			}
		}
		if start < last {
			i = j
			continue
		}
		b.WriteString(in[last:start])
		b.WriteString(redaction(kind))
		last = end
		i = j
	}
	b.WriteString(in[last:])
	return b.String()
}

// redaction is the token a masked match leaves behind. It names the kind
// so a reader can tell a removed card from a removed address without
// either of them being there.
func redaction(k Kind) string { return "<redacted:" + string(k) + ">" }

// sortedKeys gives the walk a stable order, so two scans of the same value
// produce findings in the same order and a test can say what it expects.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// copyOnWrite makes the copy the first redaction in an object needs, and
// returns the one already made for every redaction after it.
func copyOnWrite(out, src map[string]any) map[string]any {
	if out != nil {
		return out
	}
	out = make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func runeBoundary(s string, n int) int {
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}
