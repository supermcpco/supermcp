package dlp

import (
	"regexp"
	"slices"
	"strings"
)

// Kind names the class of thing a detector looks for. A policy is written
// in terms of detector names; a kind is what a reader of a finding sees,
// and what the mask token says was taken out.
type Kind string

// The kinds the built-in detectors report.
const (
	KindPaymentCard Kind = "payment_card"
	KindIBAN        Kind = "iban"
	KindEmail       Kind = "email"
	KindPhone       Kind = "phone"
	KindUSSSN       Kind = "us_ssn"
	KindDETaxID     Kind = "de_tax_id"
	KindCredential  Kind = "credential"
)

// The built-in detector names. A policy stores these strings, so they are
// part of the API: a name may be added, never renamed.
const (
	DetectorPaymentCard = "payment_card"
	DetectorIBAN        = "iban"
	DetectorEmail       = "email"
	DetectorPhone       = "phone"
	DetectorUSSSN       = "us_ssn"
	DetectorDETaxID     = "de_tax_id"
	DetectorCredential  = "credential" //nolint:gosec // a detector's name, not a credential
	DetectorSecretKey   = "secret_key"
)

// DetectorInfo is a detector as an interface offers it. Excludes is the
// part an administrator actually needs: a detector is chosen by what it
// lets through as much as by what it catches.
type DetectorInfo struct {
	Name     string `json:"name"`
	Kind     Kind   `json:"kind"`
	Summary  string `json:"summary"`
	Excludes string `json:"excludes"`
}

// rule is one regular expression and the test that decides whether what it
// found is really the thing. The expression is the cheap half: it narrows
// a body of text to a handful of candidates, and check throws away the
// ones that only look right.
//
// pre is cheaper still. Running a regular expression over a large result
// costs tens of nanoseconds a byte; looking for a literal the pattern
// cannot match without costs a fraction of one, and most results contain
// none of these literals at all.
type rule struct {
	name  string
	re    *regexp.Regexp
	conf  Confidence
	pre   func(string) bool
	check func(candidate string) (Confidence, bool)
}

// patternDetector is every built-in except secret_key: a set of rules over
// the text of one string.
//
// window, when set, says where in the text the rules can possibly match:
// inside a run of digits, or near a character or a shape the pattern
// cannot match without. Finding those places is one tight pass, and
// running the expressions over them instead of over all of the text is
// what keeps a large result off the critical path.
type patternDetector struct {
	name   string
	kind   Kind
	window func(string) []span
	rules  []rule
}

// fieldDetector matches the name of a field rather than its contents, so
// that a value nothing would recognise — a password, an opaque session
// token — is still caught when the field it sits in says what it is. Find
// returns nothing because there is nothing in the text to find; the walk
// in dlp.go applies it as it descends into an object.
type fieldDetector struct {
	name string
	kind Kind
}

// Builtin returns the detectors an empty policy uses.
func Builtin() []Detector { return slices.Clone(builtins) }

// DetectorNames lists the built-in names in catalogue order.
func DetectorNames() []string {
	out := make([]string, 0, len(builtins))
	for _, d := range builtins {
		out = append(out, d.Name())
	}
	return out
}

// Lookup returns a built-in detector by name.
func Lookup(name string) (Detector, bool) {
	d, ok := byName[name]
	return d, ok
}

// Catalogue describes the built-ins in the order an interface should show
// them.
func Catalogue() []DetectorInfo { return slices.Clone(catalogue) }

func (d patternDetector) Name() string { return d.name }

func (d patternDetector) Kind() Kind { return d.kind }

func (d patternDetector) Find(s string) []Match {
	if d.window == nil {
		return d.find(s, 0, nil)
	}
	var out []Match
	for _, w := range d.window(s) {
		out = d.find(s[w.start:w.end], w.start, out)
	}
	return out
}

// find runs the rules over one window and reports offsets in the original
// string, which is what a finding has to carry: the window is an
// implementation detail of the search, not of the result.
func (d patternDetector) find(s string, offset int, out []Match) []Match {
	for _, r := range d.rules {
		if r.pre != nil && !r.pre(s) {
			continue
		}
		for _, loc := range r.re.FindAllStringIndex(s, -1) {
			conf := r.conf
			if r.check != nil {
				c, ok := r.check(s[loc[0]:loc[1]])
				if !ok {
					continue
				}
				if c != "" {
					conf = c
				}
			}
			out = append(out, Match{Start: offset + loc[0], End: offset + loc[1], Confidence: conf, Rule: r.name})
		}
	}
	return out
}

func (d fieldDetector) Name() string { return d.name }

func (d fieldDetector) Kind() Kind { return d.kind }

func (d fieldDetector) Find(string) []Match { return nil }

// --- payment card ----------------------------------------------------------

// A card number is 13 to 19 digits, optionally written in groups of four.
// The expression admits the shape and the Luhn check does the deciding:
// roughly nine in ten sixteen-digit numbers that are not cards fail it.
//
// Deliberately not matched: any digit run that fails Luhn (an order
// number, an invoice reference, a timestamp in milliseconds), a run of
// identical digits that passes Luhn by accident, and a card number sitting
// inside a longer run of digits — the word boundaries at both ends mean a
// twenty-digit identifier yields nothing at all rather than a card-shaped
// prefix of itself.
var cardRe = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)

func checkCard(s string) (Confidence, bool) {
	digits := onlyDigits(s)
	if len(digits) < 13 || len(digits) > 19 || uniform(digits) || !luhn(digits) {
		return "", false
	}
	if cardScheme(digits) {
		return ConfidenceHigh, true
	}
	// Luhn alone is one digit of evidence out of ten, which is worth
	// reporting and not worth refusing a payment system's traffic over.
	return ConfidenceMedium, true
}

func luhn(d string) bool {
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// cardScheme reports whether the number opens with an issuer range that is
// actually in use. It raises confidence; it never rejects, because ranges
// are assigned over time and a detector that has to be redeployed to see a
// new one is a detector that misses.
func cardScheme(d string) bool {
	n := len(d)
	p2 := prefix(d, 2)
	p4 := prefix(d, 4)
	switch {
	case d[0] == '4' && (n == 13 || n == 16 || n == 19): // Visa
		return true
	case p2 >= 51 && p2 <= 55 && n == 16: // Mastercard
		return true
	case p4 >= 2221 && p4 <= 2720 && n == 16: // Mastercard, 2-series
		return true
	case (p2 == 34 || p2 == 37) && n == 15: // American Express
		return true
	case (p4 == 6011 || p2 == 65) && n >= 16: // Discover
		return true
	case p4 >= 3528 && p4 <= 3589 && n >= 16: // JCB
		return true
	case (p2 == 36 || p2 == 38 || (p4/10 >= 300 && p4/10 <= 305)) && n >= 14: // Diners Club
		return true
	}
	return false
}

// --- IBAN ------------------------------------------------------------------

// An IBAN is two letters, two check digits and up to thirty more
// characters, written either compactly or in groups of four.
//
// Deliberately not matched: anything failing the ISO 7064 mod-97 check, an
// identifier whose length disagrees with its country's registered length
// (DE is 22 characters and nothing else), and a VAT number such as
// DE123456789, which is too short to reach the minimum length at all.
var ibanRe = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b`)

// ibanLengths is the registered length per country. A country that is not
// listed still has to pass mod-97, and is reported one confidence lower.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24,
	"DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27,
	"HR": 21, "HU": 28, "IE": 22, "IS": 26, "IT": 27, "LI": 21, "LT": 20, "LU": 20,
	"LV": 21, "MC": 27, "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24,
	"SE": 24, "SI": 19, "SK": 24, "SM": 27, "TR": 26,
}

func checkIBAN(s string) (Confidence, bool) {
	c := strings.ReplaceAll(s, " ", "")
	if len(c) < 15 || len(c) > 34 || !mod97(c) {
		return "", false
	}
	want, known := ibanLengths[c[:2]]
	switch {
	case known && len(c) != want:
		return "", false
	case known:
		return ConfidenceHigh, true
	}
	return ConfidenceMedium, true
}

// mod97 runs the ISO 7064 check: move the country and check digits to the
// end, read letters as two-digit numbers, and divide by 97.
func mod97(c string) bool {
	rem := 0
	for i := range len(c) {
		ch := c[(i+4)%len(c)]
		switch {
		case ch >= '0' && ch <= '9':
			rem = rem*10 + int(ch-'0')
		case ch >= 'A' && ch <= 'Z':
			rem = rem*100 + int(ch-'A') + 10
		default:
			return false
		}
		rem %= 97
	}
	return rem == 1
}

// --- email address ---------------------------------------------------------

// Deliberately not matched: an address with no dotted top-level domain
// (root@localhost), a mention (@channel, @here), a bare domain name, and a
// package specifier such as left-pad@1.2.3, whose last label has no
// letters in it.
var emailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}\b`)

// --- telephone number ------------------------------------------------------

// The weakest family here, and the one most able to drown a record, so
// every rule insists on either a country prefix or separators between the
// groups, and the national forms are reported at low confidence.
//
// Deliberately not matched: a bare run of digits with no plus sign and no
// separators, which is indistinguishable from an order number, a row id or
// a timestamp; a date (2024-01-15); a version (1.2.3.4); and a numeric run
// longer than fifteen digits, which no telephone number is.
var (
	phoneE164Re = regexp.MustCompile(`\+\d(?:[ .()\-]?\d){7,14}\b`)
	phoneUSRe   = regexp.MustCompile(`(?:\b\d{3}[ .\-]|\(\d{3}\)[ .\-]?)\d{3}[ .\-]\d{4}\b`)
	phoneDERe   = regexp.MustCompile(`\b0\d{2,4}[ /\-]\d{3,9}\b`)
)

func checkE164(s string) (Confidence, bool) {
	d := onlyDigits(s)
	return ConfidenceMedium, len(d) >= 8 && len(d) <= 15 && !uniform(d)
}

func checkNationalPhone(s string) (Confidence, bool) {
	d := onlyDigits(s)
	return ConfidenceLow, len(d) >= 10 && len(d) <= 13 && !uniform(d)
}

// --- United States: social security number ---------------------------------

// Deliberately not matched: nine consecutive digits with no separator. An
// unseparated SSN cannot be told apart from an order number or a bank
// routing number, and a detector that claimed it could would report one on
// every invoice in the estate.
var ssnRe = regexp.MustCompile(`\b(\d{3})[ \-](\d{2})[ \-](\d{4})\b`)

// checkSSN rejects the ranges the Social Security Administration has never
// issued, which removes most numbers invented for test fixtures.
func checkSSN(s string) (Confidence, bool) {
	d := onlyDigits(s)
	area, group, serial := d[0:3], d[3:5], d[5:9]
	if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
		return "", false
	}
	return ConfidenceHigh, true
}

// --- Germany: steuerliche Identifikationsnummer ----------------------------

// Eleven digits with a check digit and a rule about how often each digit
// may repeat, which together reject the great majority of eleven-digit
// numbers.
//
// Deliberately not matched: an eleven-digit run failing either test — a
// telephone number written without separators, an order number, an EAN-13
// prefix — and anything starting with a zero, which no tax number does.
// The Sozialversicherungsnummer has its own shape and is not covered here.
var deTaxRe = regexp.MustCompile(`\b\d{11}\b`)

func checkDETaxID(s string) (Confidence, bool) {
	if s[0] == '0' {
		return "", false
	}
	// Exactly one of the first ten digits appears twice or three times and
	// no other appears more than once. This is the part of the
	// specification that makes the number hard to imitate by accident.
	var counts [10]int
	for i := range 10 {
		d := s[i] - '0'
		if d > 9 {
			return "", false
		}
		counts[d]++
	}
	repeats := 0
	for _, n := range counts {
		switch {
		case n == 2 || n == 3:
			repeats++
		case n > 3:
			return "", false
		}
	}
	if repeats != 1 {
		return "", false
	}
	// ISO 7064 MOD 11,10 over the first ten digits.
	product := 10
	for i := range 10 {
		sum := (int(s[i]-'0') + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (2 * sum) % 11
	}
	if (11-product)%10 != int(s[10]-'0') {
		return "", false
	}
	return ConfidenceHigh, true
}

// --- credentials -----------------------------------------------------------

// The token formats that leak most often, each recognised by the prefix
// its issuer put there for exactly this purpose.
//
// Deliberately not matched: high entropy on its own. A random thirty-two
// character string is a session id, a content hash, a UUID or a build
// fingerprint far more often than it is a credential, and a detector that
// fired on all of them would be turned off within a day. If a secret has
// no recognisable shape, the field it sits in usually names it, and
// secret_key catches that.
var leakRules = []rule{
	{name: "github", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`), conf: ConfidenceHigh,
		pre: literals("ghp_", "gho_", "ghu_", "ghs_", "ghr_")},
	{name: "slack", re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), conf: ConfidenceHigh,
		pre: literals("xox")},
	{name: "stripe", re: regexp.MustCompile(`\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}`), conf: ConfidenceHigh,
		pre: literals("sk_live_", "sk_test_", "rk_live_", "rk_test_")},
	{name: "aws_access_key", re: regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AGPA|ANPA|AROA)[A-Z0-9]{16}\b`), conf: ConfidenceHigh,
		pre: literals("AKIA", "ASIA", "AIDA", "AGPA", "ANPA", "AROA")},
	{name: "google_api_key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), conf: ConfidenceHigh,
		pre: literals("AIza")},
	{name: "openai", re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}`), conf: ConfidenceHigh,
		pre: literals("sk-")},
	{name: "private_key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), conf: ConfidenceHigh,
		pre: literals("PRIVATE KEY")},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}`), conf: ConfidenceHigh,
		pre: literals("eyJ")},
	// The one case-insensitive rule, prefiltered on the part of the word
	// whose case does not vary in practice: Bearer, bearer, BEARER.
	{name: "bearer", re: regexp.MustCompile(`(?i)\bbearer [A-Za-z0-9\-._~+/]{20,}={0,2}`), conf: ConfidenceMedium,
		pre: literals("earer ", "EARER ")},
}

// --- registry --------------------------------------------------------------

var builtins = []Detector{
	patternDetector{name: DetectorPaymentCard, kind: KindPaymentCard, window: digitWindows(13), rules: []rule{
		{name: "luhn", re: cardRe, check: checkCard},
	}},
	patternDetector{name: DetectorIBAN, kind: KindIBAN, window: ibanWindows, rules: []rule{
		{name: "mod97", re: ibanRe, check: checkIBAN},
	}},
	// An address is at most 64 octets of local part and 253 of domain, so
	// the window around each @ holds every address there is; the prefilter
	// on top means a result with no @ in it costs one vectorised pass.
	patternDetector{name: DetectorEmail, kind: KindEmail, window: anchorWindows('@', 72, 260), rules: []rule{
		{name: "address", re: emailRe, conf: ConfidenceHigh, pre: hasAt},
	}},
	patternDetector{name: DetectorPhone, kind: KindPhone, window: digitWindows(8), rules: []rule{
		{name: "e164", re: phoneE164Re, check: checkE164},
		{name: "us", re: phoneUSRe, check: checkNationalPhone},
		{name: "de", re: phoneDERe, check: checkNationalPhone},
	}},
	patternDetector{name: DetectorUSSSN, kind: KindUSSSN, window: digitWindows(9), rules: []rule{
		{name: "ssn", re: ssnRe, check: checkSSN},
	}},
	patternDetector{name: DetectorDETaxID, kind: KindDETaxID, window: digitWindows(11), rules: []rule{
		{name: "steuer_id", re: deTaxRe, check: checkDETaxID},
	}},
	patternDetector{name: DetectorCredential, kind: KindCredential, rules: leakRules},
	fieldDetector{name: DetectorSecretKey, kind: KindCredential},
}

var byName = func() map[string]Detector {
	m := make(map[string]Detector, len(builtins))
	for _, d := range builtins {
		m[d.Name()] = d
	}
	return m
}()

var catalogue = []DetectorInfo{
	{DetectorPaymentCard, KindPaymentCard, "Payment card numbers of 13 to 19 digits, checked with Luhn and against the issuer ranges",
		"A digit run that fails the Luhn check: an order number, an invoice reference, a timestamp. A card number embedded in a longer run of digits."},
	{DetectorIBAN, KindIBAN, "International bank account numbers, checked with ISO 7064 mod-97 and the registered length of the country",
		"An identifier failing mod-97, one whose length disagrees with its country, and a VAT number such as DE123456789."},
	{DetectorEmail, KindEmail, "Email addresses with a dotted top-level domain",
		"An address with no dotted domain (root@localhost), a mention (@channel), a bare domain name, and a package specifier such as left-pad@1.2.3."},
	{DetectorPhone, KindPhone, "Telephone numbers in E.164 form, and United States and German national forms written with separators",
		"A bare run of digits with no plus sign and no separators, a date, a version string, and any numeric run longer than fifteen digits."},
	{DetectorUSSSN, KindUSSSN, "United States social security numbers written with a separator, excluding the ranges never issued",
		"Nine consecutive digits with no separator, which cannot be told from an order or routing number."},
	{DetectorDETaxID, KindDETaxID, "German steuerliche Identifikationsnummer, checked with ISO 7064 MOD 11,10 and the repeated-digit rule",
		"Any other eleven-digit number, including telephone numbers written without separators. The Sozialversicherungsnummer is not covered."},
	{DetectorCredential, KindCredential, "Token formats that carry their issuer's prefix: GitHub, Slack, Stripe, AWS, Google, OpenAI, JWTs, PEM private keys and bearer headers",
		"High entropy on its own. A random string, a UUID, a content hash and a session id are not credentials."},
	{DetectorSecretKey, KindCredential, "A field whose name says it holds a secret: password, token, secret, credential, authorization",
		"Nothing in the text. It reads field names only, so a secret in a field called data is invisible to it."},
}

// secretNames is the vocabulary internal/audit masks on, kept identical so
// that a field redacted in the record is the same field redacted on the
// wire.
var secretNames = []string{"password", "secret", "token", "apikey", "api_key", "authorization", "credential", "passwd", "pwd"}

func looksSecret(key string) bool {
	k := strings.ToLower(key)
	for _, name := range secretNames {
		if strings.Contains(k, name) {
			return true
		}
	}
	return false
}

// --- helpers ---------------------------------------------------------------

// literals builds a prefilter that passes only when one of the given
// strings is present. strings.Contains is a vectorised scan and costs a
// fraction of a nanosecond a byte, against tens for an expression with no
// literal prefix to anchor on.
func literals(want ...string) func(string) bool {
	return func(s string) bool {
		for _, w := range want {
			if strings.Contains(s, w) {
				return true
			}
		}
		return false
	}
}

func hasAt(s string) bool { return strings.IndexByte(s, '@') >= 0 }

// span is a window of the text worth running an expression over.
type span struct{ start, end int }

// digitSeps are the characters a number may be written with. A character
// outside this set and outside the digits ends the run.
var digitSeps = [256]bool{' ': true, '-': true, '.': true, '(': true, ')': true, '/': true}

// spanContext widens each run by two bytes at each end so that a word
// boundary at the edge of a window is judged against the text around it.
// Without it \b would match at the start of the window and report a card
// number inside an identifier such as ref4111111111111111.
const spanContext = 2

// digitSpans returns the runs of digits and separators holding at least
// min digits. It is the reason a numeric detector costs one pass over the
// text plus an expression over the few parts of it that are numbers, and
// not an expression over all of it.
func digitWindows(min int) func(string) []span {
	return func(s string) []span { return digitSpans(s, min) }
}

func anchorWindows(c byte, before, after int) func(string) []span {
	return func(s string) []span { return anchorSpans(s, c, before, after) }
}

// ibanWindows looks for the only shape an IBAN can start with: two
// capitals and two digits. It has no literal to search for and no run of
// digits to sit in, so this stands in for both.
func ibanWindows(s string) []span {
	var out []span
	for i := 0; i+3 < len(s); i++ {
		if !isUpper(s[i]) || !isUpper(s[i+1]) || !isDigit(s[i+2]) || !isDigit(s[i+3]) {
			continue
		}
		// Thirty-four characters is the longest IBAN there is, plus the
		// spaces a printed one is written with.
		w := span{start: max(i-spanContext, 0), end: min2(i+45, len(s))}
		if n := len(out); n > 0 && w.start <= out[n-1].end {
			out[n-1].end = w.end
		} else {
			out = append(out, w)
		}
	}
	return out
}

func digitSpans(s string, min int) []span {
	var out []span
	for i := 0; i < len(s); {
		if !isDigit(s[i]) {
			i++
			continue
		}
		start, digits, last := i, 0, i
	run:
		for i < len(s) {
			switch c := s[i]; {
			case isDigit(c):
				digits, last = digits+1, i
				i++
			case digitSeps[c]:
				i++
			default:
				break run
			}
		}
		if digits >= min {
			out = append(out, span{start: max(start-spanContext, 0), end: min2(last+1+spanContext, len(s))})
		}
	}
	return out
}

// anchorSpans returns the windows within reach of each occurrence of c,
// merged where they overlap. Merging is what keeps a text full of
// addresses from costing more than scanning it whole would have.
func anchorSpans(s string, c byte, before, after int) []span {
	var out []span
	for i := 0; i < len(s); {
		at := strings.IndexByte(s[i:], c)
		if at < 0 {
			break
		}
		at += i
		w := span{start: max(at-before, 0), end: min2(at+after, len(s))}
		if n := len(out); n > 0 && w.start <= out[n-1].end {
			out[n-1].end = w.end
		} else {
			out = append(out, w)
		}
		i = at + 1
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

// min2 is spelled out because min is taken by the parameter above.
func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func onlyDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// uniform reports a run of one repeated digit, which passes Luhn once in
// ten times and is never anybody's card or telephone number.
func uniform(d string) bool {
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}

func prefix(d string, n int) int {
	if len(d) < n {
		return -1
	}
	v := 0
	for i := range n {
		v = v*10 + int(d[i]-'0')
	}
	return v
}
