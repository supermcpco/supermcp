package compliance

import (
	"io"
	"strings"
)

// WriteJSON writes the erasure report as JSON.
func (e *Erasure) WriteJSON(w io.Writer) error { return writeJSON(w, e) }

// WriteText writes the erasure report for a person to read. The two
// halves are given equal weight on purpose: what was rewritten, and what
// was not and why. A report that printed only the first would let an
// operator tell a subject their record was erased when a diff two tables
// away still names them.
func (e *Erasure) WriteText(w io.Writer) error {
	p := &printer{w: w}
	p.printf("Erasure\nrun %s\n", ts(e.ErasedAt))
	p.printf("\naccount        %s\n", e.UserID)
	p.printf("now known as   %s\n", e.Pseudonym)
	p.printf("new address    %s\n", e.NewAddress)
	if len(e.Workspaces) == 0 {
		p.printf("workspaces     none; this account belonged to no workspace\n")
	} else {
		p.printf("workspaces     %s\n", strings.Join(e.Workspaces, ", "))
	}

	p.printf("\n%s\nRewritten\n", strings.Repeat("=", 72))
	var total int64
	for _, c := range e.Changed {
		total += c.Rows
		p.printf("\n  %s (%s)\n", c.Table, strings.Join(c.Columns, ", "))
		p.printf("    rows       %d\n", c.Rows)
		p.printf("    why        %s\n", wrap(c.Why, 62, "               "))
	}
	p.printf("\n  %d rows in total\n", total)

	p.printf("\n%s\nLeft as it was, and why\n", strings.Repeat("=", 72))
	for _, u := range e.Untouched {
		p.printf("\n  %s\n", u.Where)
		if u.Rows >= 0 {
			p.printf("    rows       %d\n", u.Rows)
		}
		p.printf("    why        %s\n", wrap(u.Why, 62, "               "))
	}

	p.printf("\n%s\nThe audit chain\n", strings.Repeat("=", 72))
	p.printf("  %s\n", wrap("Only "+strings.Join(ChainSafeColumns(), " and ")+" were rewritten in audit_events. "+
		"The chain hash covers the event id, its write time, the workspace, the category, the action, the outcome, "+
		"the actor kind and id, the target kind and id, and a digest of the diff, payload and metadata. None of those "+
		"changed, so `supermcp audit verify` still passes. Run it: a report that says the chain is intact is worth less "+
		"than the command that proves it.", 70, "  "))
	return p.err
}
