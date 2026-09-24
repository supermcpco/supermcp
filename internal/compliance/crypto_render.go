package compliance

import (
	"io"
	"strings"
)

// WriteJSON writes the cryptography report as JSON.
func (c *Crypto) WriteJSON(w io.Writer) error { return writeJSON(w, c) }

// WriteText writes the cryptography report for a person to read. The
// section that says what is not encrypted comes last and is not
// abbreviated: it is the half of this report an assessor is owed and the
// half a vendor is tempted to shorten.
func (c *Crypto) WriteText(w io.Writer) error {
	p := &printer{w: w}
	p.printf("Cryptography report\ngenerated %s\n", ts(c.GeneratedAt))

	p.printf("\n%s\nMaster keys\n", strings.Repeat("=", 72))
	if c.MasterKeys.Active != "" {
		p.printf("  active         %s\n", c.MasterKeys.Active)
	}
	for _, ref := range c.MasterKeys.DecryptOnly {
		p.printf("  decrypt only   %s\n", ref)
	}
	p.printf("  %s\n", wrap(c.MasterKeys.Note, 70, "  "))

	p.printf("\n%s\nData keys (%d)\n", strings.Repeat("=", 72), len(c.DataKeys))
	p.printf("  A data key seals rows. The master key above wraps the data keys and nothing else,\n")
	p.printf("  so replacing it re-wraps this list and touches no ciphertext.\n")
	if len(c.DataKeys) == 0 {
		p.printf("\n  There are no data keys. Nothing has been sealed on this instance yet.\n")
	}
	for _, k := range c.DataKeys {
		p.printf("\n  %s\n", k.ID)
		p.printf("    scope        %s\n", k.Scope)
		p.printf("    status       %s\n", k.Status)
		p.printf("    wrapped by   %s\n", k.KEKRef)
		p.printf("    created      %s (%d days ago)\n", ts(k.CreatedAt), k.AgeDays)
		switch {
		case k.Opens == nil:
			p.printf("    opens        not checked: this run held no master key\n")
		case *k.Opens:
			p.printf("    opens        yes\n")
		default:
			p.printf("    opens        NO — %s\n", k.Error)
		}
	}

	p.printf("\n%s\nSigning keys (%d)\n", strings.Repeat("=", 72), len(c.SigningKeys))
	p.printf("  These sign MCP access tokens and the audit stream's checkpoints.\n")
	p.printf("  %s\n", wrap(signingRotation, 70, "  "))
	if len(c.SigningKeys) == 0 {
		p.printf("\n  There are no signing keys. One is created on the gateway's first boot.\n")
	}
	for _, k := range c.SigningKeys {
		p.printf("\n  %s (%s)\n", k.KID, k.Alg)
		p.printf("    status       %s, %d days in it\n", k.Status, k.AgeDays)
		p.printf("    created      %s\n", ts(k.CreatedAt))
		p.printf("    activated    %s\n", stamp(k.ActivatedAt))
		if k.RetireAt != nil {
			p.printf("    retires      %s\n", stamp(k.RetireAt))
		}
	}

	p.printf("\n%s\nSealed columns (%d)\n", strings.Repeat("=", 72), len(c.Sealed))
	p.printf("  Found in the schema, not listed in the report's source: a column sealed by a\n")
	p.printf("  feature added after this report was written still appears here.\n")
	for _, s := range c.Sealed {
		p.printf("\n  %s.%s\n", s.Table, s.Column)
		switch s.Scope {
		case "workspace", "instance":
			p.printf("    sealed by    the %s data key\n", s.Scope)
		default:
			// A column the schema has and this report has not been told
			// about. Saying so is the point: the alternative is a report
			// that keeps claiming six columns are sealed while seven are.
			p.printf("    sealed by    a data key this report cannot name\n")
		}
		p.printf("    rows sealed  %d\n", s.Rows)
		if s.Holds == "" {
			p.printf("    holds        %s\n", wrap(
				"this report has no description for this column. It is sealed; what it holds is not stated here, "+
					"and a reader who needs to know has to ask.", 60, "                 "))
		} else {
			p.printf("    holds        %s\n", wrap(s.Holds, 60, "                 "))
		}
	}

	p.printf("\n%s\nWhat is NOT encrypted\n", strings.Repeat("=", 72))
	for _, s := range c.Clear {
		p.printf("\n  %s", s.Subject)
		if s.Rows > 0 {
			p.printf(" (%d rows)", s.Rows)
		}
		p.printf("\n    %s\n", wrap(s.Detail, 70, "    "))
	}

	p.printf("\n%s\nWhat this report cannot see\n", strings.Repeat("=", 72))
	for _, l := range c.Limits {
		p.printf("  - %s\n", wrap(l, 72, "    "))
	}
	return p.err
}

// signingRotation states the schedule the keyring keeps, which is a
// property of the code rather than of any row, so no query can report it.
const signingRotation = "A key older than 90 days publishes a successor; the successor is promoted 24 hours later, " +
	"which is the gap that lets a verifier holding a cached key set catch up; the outgoing key retires 30 days after that. " +
	"The schedule runs from the gateway's hourly sweep, so an instance whose gateway is not running does not rotate. " +
	"Nothing rotates a data key, and the master key rotates only when an operator runs `supermcp keys rotate-kek`."

// Failures reports the data keys that did not open. A deployment check
// wants the count, not the prose.
func (c *Crypto) Failures() []DataKeyState {
	var out []DataKeyState
	for _, k := range c.DataKeys {
		if k.Opens != nil && !*k.Opens {
			out = append(out, k)
		}
	}
	return out
}
