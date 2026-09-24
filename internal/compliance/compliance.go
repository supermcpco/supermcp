// Package compliance answers the questions an assessor asks, from the
// database rather than from a document: who can do what, what is
// encrypted and what is not, what this instance is configured to do, and
// everything one person's record holds.
//
// Three rules shape every report here.
//
// It says what is missing as plainly as what is present. A report that
// lists nine controls and stays quiet about the tenth reads as a clean
// bill of health, and an assessor who later finds the tenth has reason to
// doubt the other nine.
//
// It is for a person to read and for a machine to diff. Each report has a
// text form for the first and a JSON form for the second, and both are
// ordered deterministically, so two runs a quarter apart differ only
// where the instance did.
//
// It never fills a gap with a guess. Where the data cannot support a
// conclusion — a rotation the audit window no longer covers, a data key
// this process holds no master key for — the report says that, in place
// of the conclusion.
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// Deps is what every report reads through. Reports are tenant-scoped
// wherever the data is, and reach for DB.Bypass only where the question
// itself spans tenants — listing the workspaces, reading the instance's
// keys, rewriting one person's name everywhere it appears.
type Deps struct {
	DB *tenant.DB
	// Now fixes the moment a report describes. Zero means time.Now. It
	// exists so a test can age an instance, and so a report generated in
	// two formats for the same review carries one timestamp.
	Now time.Time
}

func (d Deps) now() time.Time {
	if d.Now.IsZero() {
		return time.Now().UTC()
	}
	return d.Now.UTC()
}

// Digest is how a value appears when the value itself must not. Two
// different values give two different digests, so a reader can compare
// two instances, or confirm that a key was replaced, without being handed
// either secret.
//
// A digest is not a safe way to publish a value drawn from a short list:
// anyone can digest the whole list and look the answer up. It is used
// here only for key material, passwords inside connection strings and
// values an operator supplied as secret, never for a setting whose
// possible values could be enumerated.
func Digest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// RedactURL keeps everything about a connection string that decides
// behaviour — the scheme, the host, the database, the parameters, and in
// particular whether the connection is encrypted — and replaces only the
// password with a digest. An assessor needs to see `sslmode=disable`; the
// password tells them nothing they should have.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		// A string that does not parse may still be a credential, so it is
		// digested whole rather than printed in the hope that it is not.
		if err != nil {
			return Digest(raw)
		}
		return raw
	}
	if pw, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), Digest(pw))
	}
	// url.URL re-escapes the digest's colon, which makes two instances with
	// the same password look different depending on the encoder. Undo it.
	return strings.ReplaceAll(u.String(), "sha256%3A", "sha256:")
}

// looksSecret reports whether a setting's name says its value must not be
// printed. It errs towards redaction: a setting wrongly digested costs a
// reader one question, and a secret wrongly printed costs a rotation.
func looksSecret(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"secret", "password", "passwd", "token", "_key", "key_", "kek", "credential", "salt", "pepper"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// writeJSON is the machine-readable form of every report: indented, so a
// diff between two runs points at a line rather than at a column of one
// very long one, and newline-terminated so it concatenates cleanly.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ago renders an interval the way a reviewer reads one. An absent time is
// "never", which is a finding in most of the places this is called from
// and so is never rendered as a blank.
func ago(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := now.Sub(*t)
	switch {
	case d < 0:
		return "in " + days(-d)
	case d < 36*time.Hour:
		return "today"
	default:
		return days(d) + " ago"
	}
}

func days(d time.Duration) string {
	n := int(d.Hours() / 24)
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// ts renders a time in UTC. Every timestamp in every report goes through
// it: a report generated in one time zone and read in another has to say
// the same thing, and a column that sometimes carries an offset does not
// sort.
func ts(t time.Time) string { return t.UTC().Format(timeLayout) }

// stamp renders a time for a report, or a word saying there is not one.
func stamp(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// sortedStrings copies and sorts, so a report's ordering never depends on
// the order the database happened to return rows in.
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// timeLayout is the one timestamp format every report uses. RFC 3339 in
// UTC sorts lexically, which is what makes a report diffable and a CSV
// column sortable in a spreadsheet that knows nothing about time zones.
const timeLayout = time.RFC3339

// printer writes a text report and remembers the first error, so a
// hundred writes do not become a hundred error checks. A report is written
// to a file or a terminal; the first failure is the only informative one.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

// wrap breaks a long line at word boundaries and indents the continuation,
// so a finding's explanation stays readable in an 80-column terminal
// without the caller counting characters.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	// A width at or below the indent would put one word on every line. It
	// is a caller's arithmetic mistake and it makes a report unreadable,
	// so it is corrected here rather than printed.
	if width <= len(indent)+8 {
		width = len(indent) + 40
	}
	var b strings.Builder
	line := 0
	for i, word := range words {
		switch {
		case i == 0:
			b.WriteString(word)
			line = len(word)
		case line+1+len(word) > width:
			b.WriteString("\n" + indent + word)
			line = len(indent) + len(word)
		default:
			b.WriteString(" " + word)
			line += 1 + len(word)
		}
	}
	return b.String()
}
