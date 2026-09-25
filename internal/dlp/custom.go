package dlp

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"time"
)

// A workspace's own detectors. The built-ins know card numbers and bank
// accounts; they cannot know a company's customer numbers or contract
// ids. A custom detector is one regular expression an administrator
// writes, stored per organisation (00031_dlp_detectors.sql), and a policy
// picks it the way it picks a built-in: by name, spelled
// "custom:<name>".
//
// The expression is RE2, Go's regexp: its cost is linear in the text it
// reads, so a pattern cannot backtrack its way into a denial of service,
// and it runs inside the same byte budget as the built-ins (Options
// MaxBytes). What is left to bound is the size of the pattern and of the
// program it compiles to, which is what CompilePattern checks.

// CustomPrefix is how a policy names a workspace's own detector:
// "custom:customer_number". Built-in names never contain a colon.
const CustomPrefix = "custom:"

// Limits on a custom detector. They are part of the API: a pattern that
// passes them today must pass them tomorrow.
const (
	// MaxPatternBytes caps the pattern's source.
	MaxPatternBytes = 512
	// MinPatternBytes is the shortest pattern accepted. A two-byte
	// pattern is a character or a class, and matches everywhere.
	MinPatternBytes = 3
	// MaxSamples caps each of mustMatch and mustNotMatch. A test request
	// may send twice as many, so an editor can try both lists at once.
	MaxSamples = 20
	// MaxSampleBytes caps one sample.
	MaxSampleBytes = 1024
	// MaxCustomDetectors is how many detectors one organisation may hold.
	// Every enabled detector a policy names runs over every value that
	// policy screens, so the number is a cost on the tool-call path.
	MaxCustomDetectors = 50
	// maxDescriptionChars matches the column's check.
	maxDescriptionChars = 500
	// maxProgramInsts bounds the compiled program. RE2 runs in time
	// proportional to text times program, so a 512-byte pattern such as
	// \w{1000} that compiles to a thousand instructions would cost a
	// thousand times what its length suggests on every call.
	maxProgramInsts = 2000
	// maxTestMatches caps the offsets one tested sample reports.
	maxTestMatches = 20
)

// FlagCaseInsensitive is the one flag a detector may carry.
const FlagCaseInsensitive = "i"

// Errors about custom detectors. The HTTP layer maps each one to a status.
var (
	// ErrDetectorNotFound is returned for a detector that does not exist,
	// or belongs to another organisation.
	ErrDetectorNotFound = errors.New("dlp detector not found")
	// ErrInvalidDetector marks a detector the caller could fix. The error
	// returned is a *DetectorError naming the field.
	ErrInvalidDetector = errors.New("the detector is not valid")
	// ErrDetectorNameTaken means the organisation has a detector of that
	// name already.
	ErrDetectorNameTaken = errors.New("a detector with this name already exists")
	// ErrDetectorInUse means policies name the detector. The error
	// returned is an *InUseError listing them.
	ErrDetectorInUse = errors.New("data-loss policies use this detector; remove it from them first, or delete with force")
	// ErrVersionConflict means the detector changed since the caller read
	// it. The error returned is a *VersionConflictError.
	ErrVersionConflict = errors.New("the detector was changed by someone else; reload it and try again")
)

// DetectorError is a detector refused for one reason, at one place in the
// request. Field is a JSON path into the request body, such as "pattern"
// or "mustMatch[2]". It never quotes a sample: the reason names it by its
// position.
type DetectorError struct {
	Field  string
	Reason string
}

func (e *DetectorError) Error() string { return e.Field + ": " + e.Reason }

// Is makes errors.Is(err, ErrInvalidDetector) hold.
func (e *DetectorError) Is(target error) bool { return target == ErrInvalidDetector }

func invalid(field, format string, args ...any) error {
	return &DetectorError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// PolicyRef names a policy, for a refusal that lists them.
type PolicyRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// InUseError is a delete refused because policies name the detector.
type InUseError struct {
	Policies []PolicyRef
}

func (e *InUseError) Error() string {
	names := make([]string, 0, len(e.Policies))
	for _, p := range e.Policies {
		names = append(names, p.Name)
	}
	return ErrDetectorInUse.Error() + ": " + strings.Join(names, ", ")
}

// Is makes errors.Is(err, ErrDetectorInUse) hold.
func (e *InUseError) Is(target error) bool { return target == ErrDetectorInUse }

// VersionConflictError is a write made against a version other than the
// one stored. Current is the version stored now.
type VersionConflictError struct {
	Current int64
}

func (e *VersionConflictError) Error() string { return ErrVersionConflict.Error() }

// Is makes errors.Is(err, ErrVersionConflict) hold.
func (e *VersionConflictError) Is(target error) bool { return target == ErrVersionConflict }

// CustomDetector is one workspace's own detector, as stored.
type CustomDetector struct {
	ID    string `json:"id"`
	OrgID string `json:"-"`
	// Name is the slug a policy refers to, after CustomPrefix. It never
	// changes once the detector exists.
	Name string `json:"name"`
	// Detector is the name a policy uses: CustomPrefix + Name.
	Detector    string `json:"detector"`
	Description string `json:"description"`
	// Pattern is RE2 source.
	Pattern string `json:"pattern"`
	// Flags is "" or "i" (case-insensitive).
	Flags string `json:"flags" enum:",i"`
	// MustMatch and MustNotMatch are samples the pattern is tested
	// against on every save: each of the first must contain a match, none
	// of the second may.
	MustMatch    []string  `json:"mustMatch" nullable:"false"`
	MustNotMatch []string  `json:"mustNotMatch" nullable:"false"`
	Enabled      bool      `json:"enabled"`
	Version      int64     `json:"version" doc:"Send back as expectedVersion when updating"`
	CreatedBy    string    `json:"createdBy,omitempty"`
	UpdatedBy    string    `json:"updatedBy,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// Ref is the name a policy uses for the detector.
func (c CustomDetector) Ref() string { return CustomPrefix + c.Name }

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)

// ValidSlug reports whether s can be a custom detector's name.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// IsCustom reports whether a policy's detector name refers to a custom
// detector, and returns the slug.
func IsCustom(name string) (string, bool) {
	return strings.CutPrefix(name, CustomPrefix)
}

// Validate checks everything about a detector that does not need the
// database: its name, the pattern, and the samples.
func (c CustomDetector) Validate() error {
	if !ValidSlug(c.Name) {
		return invalid("name", "a name is 2 to 63 characters of lower-case letters, digits, - and _, starting with a letter or digit")
	}
	if n := len([]rune(c.Description)); n > maxDescriptionChars {
		return invalid("description", "the description is %d characters long; the limit is %d", n, maxDescriptionChars)
	}
	re, err := CompilePattern(c.Pattern, c.Flags)
	if err != nil {
		return err
	}
	if err := checkSamples("mustMatch", c.MustMatch, MaxSamples); err != nil {
		return err
	}
	if err := checkSamples("mustNotMatch", c.MustNotMatch, MaxSamples); err != nil {
		return err
	}
	for i, s := range c.MustMatch {
		if !re.MatchString(s) {
			return invalid(fmt.Sprintf("mustMatch[%d]", i), "sample %d of mustMatch does not match the pattern", i+1)
		}
	}
	for i, s := range c.MustNotMatch {
		if re.MatchString(s) {
			return invalid(fmt.Sprintf("mustNotMatch[%d]", i), "sample %d of mustNotMatch matches the pattern", i+1)
		}
	}
	return nil
}

func checkSamples(field string, samples []string, limit int) error {
	if len(samples) > limit {
		return invalid(field, "at most %d samples", limit)
	}
	for i, s := range samples {
		if len(s) > MaxSampleBytes {
			return invalid(fmt.Sprintf("%s[%d]", field, i), "a sample is at most %d bytes", MaxSampleBytes)
		}
	}
	return nil
}

// CompilePattern checks a pattern and compiles it. It refuses a pattern
// that is too short or too long, carries an unknown flag, does not
// compile, compiles to a program too large to run on every call, or can
// match the empty string: a detector that matches nothing at every
// position of every value would report a finding per byte, and a mask
// would insert a token between every character.
func CompilePattern(pattern, flags string) (*regexp.Regexp, error) {
	if len(pattern) < MinPatternBytes {
		return nil, invalid("pattern", "a pattern is at least %d bytes", MinPatternBytes)
	}
	if len(pattern) > MaxPatternBytes {
		return nil, invalid("pattern", "a pattern is at most %d bytes", MaxPatternBytes)
	}
	src := pattern
	switch flags {
	case "":
	case FlagCaseInsensitive:
		src = "(?i)" + pattern
	default:
		return nil, invalid("flags", "the only flag is i (case-insensitive)")
	}
	parsed, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil, invalid("pattern", "the pattern does not compile: %s", describeSyntax(err))
	}
	parsed = parsed.Simplify()
	if nullable(parsed) {
		return nil, invalid("pattern", "the pattern can match an empty string; make at least one part of it required")
	}
	prog, err := syntax.Compile(parsed)
	if err != nil {
		return nil, invalid("pattern", "the pattern does not compile: %s", describeSyntax(err))
	}
	if len(prog.Inst) > maxProgramInsts {
		return nil, invalid("pattern", "the pattern is too complex to run on every tool call; use smaller repetition counts")
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, invalid("pattern", "the pattern does not compile: %s", describeSyntax(err))
	}
	return re, nil
}

// describeSyntax keeps the parser's reason and drops its "error parsing
// regexp:" preamble, which says nothing an administrator needs.
func describeSyntax(err error) string {
	var se *syntax.Error
	if errors.As(err, &se) {
		return se.Code.String() + ": " + se.Expr
	}
	return err.Error()
}

// nullable reports whether re can match an empty span. Empty-width
// assertions (^, $, \b and their kind) count as empty: whether they hold
// depends on the text around them, and a pattern made only of them is a
// pattern that matches nothing but a position. It errs towards refusing,
// which is the right side for a rule that is checked once at save.
func nullable(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	case syntax.OpLiteral:
		return len(re.Rune) == 0
	case syntax.OpCapture, syntax.OpPlus:
		return nullable(re.Sub[0])
	case syntax.OpStar, syntax.OpQuest:
		return true
	case syntax.OpRepeat:
		return re.Min == 0 || nullable(re.Sub[0])
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if !nullable(s) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if nullable(s) {
				return true
			}
		}
		return false
	}
	// OpNoMatch, OpCharClass, OpAnyChar, OpAnyCharNotNL each consume a
	// character or never match.
	return false
}

// Span is where a match sits in a sample, in byte offsets.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// SampleResult is what a pattern found in one tested sample: whether it
// matched, and where. It never carries the text.
type SampleResult struct {
	Index   int    `json:"index" doc:"Position of the sample in the request, from zero"`
	Matched bool   `json:"matched"`
	Matches []Span `json:"matches" nullable:"false" doc:"Byte offsets of each match, at most 20"`
	// More says there were more matches than listed.
	More bool `json:"more,omitempty"`
}

// TestPattern compiles a pattern under the same rules a save applies and
// reports, per sample, where it matches.
func TestPattern(pattern, flags string, samples []string) ([]SampleResult, error) {
	re, err := CompilePattern(pattern, flags)
	if err != nil {
		return nil, err
	}
	if err := checkSamples("samples", samples, 2*MaxSamples); err != nil {
		return nil, err
	}
	out := make([]SampleResult, 0, len(samples))
	for i, s := range samples {
		locs := re.FindAllStringIndex(s, maxTestMatches+1)
		r := SampleResult{Index: i, Matched: len(locs) > 0, Matches: make([]Span, 0, min(len(locs), maxTestMatches))}
		for j, loc := range locs {
			if j == maxTestMatches {
				r.More = true
				break
			}
			r.Matches = append(r.Matches, Span{Start: loc[0], End: loc[1]})
		}
		out = append(out, r)
	}
	return out, nil
}

// customDetector runs one workspace pattern. Its kind is its name, so the
// mask token and a refusal say which of the workspace's detectors took a
// value out: <redacted:custom:contract_id>.
type customDetector struct {
	name string
	re   *regexp.Regexp
}

// NewCustom builds the detector a policy runs for c. It compiles the
// pattern under the rules a save applies.
func NewCustom(c CustomDetector) (Detector, error) {
	re, err := CompilePattern(c.Pattern, c.Flags)
	if err != nil {
		return nil, err
	}
	return customDetector{name: c.Ref(), re: re}, nil
}

func (d customDetector) Name() string { return d.name }

func (d customDetector) Kind() Kind { return Kind(d.name) }

// Find reports every match. CompilePattern refused every pattern that can
// match an empty span, so each one covers at least one byte.
func (d customDetector) Find(s string) []Match {
	locs := d.re.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]Match, 0, len(locs))
	for _, loc := range locs {
		out = append(out, Match{Start: loc[0], End: loc[1], Confidence: ConfidenceHigh, Rule: "pattern"})
	}
	return out
}
