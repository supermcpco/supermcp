package compliance

import (
	"io"
	"strings"
)

// WriteJSON writes the snapshot as JSON.
func (s *Snapshot) WriteJSON(w io.Writer) error { return writeJSON(w, s) }

// WriteText writes the snapshot for a person to read.
func (s *Snapshot) WriteText(w io.Writer) error {
	p := &printer{w: w}
	p.printf("Configuration snapshot\ngenerated %s\n", ts(s.GeneratedAt))
	p.printf("\ninstance       %s\n", s.Instance.ID)
	p.printf("created        %s\n", ts(s.Instance.CreatedAt))
	p.printf("schema         %d\n", s.Instance.SchemaVersion)
	p.printf("binary         %s\n", s.Instance.BinaryVersion)

	section(p, "Effective settings", "what this process will act on, after defaults")
	writeSettings(p, s.Effective)

	section(p, "Environment", "what an operator set")
	if len(s.Environment) == 0 {
		p.printf("\n  Nothing this binary reads is set in the environment.\n")
	}
	writeSettings(p, s.Environment)

	section(p, "Site settings", "rows of site_settings, which apply to the whole instance")
	if len(s.Site) == 0 {
		p.printf("\n  none\n")
	}
	writeSettings(p, s.Site)

	section(p, "Workspace settings", "rows of org_settings, per workspace")
	for _, ws := range s.Workspaces {
		p.printf("\n  %s (%s)\n", ws.Slug, ws.OrgID)
		if len(ws.Settings) == 0 {
			p.printf("    none; this workspace runs on the built-in defaults\n")
			continue
		}
		for _, st := range ws.Settings {
			p.printf("    %-28s %s%s\n", st.Name, st.Value, redactedMark(st))
		}
	}

	section(p, "Populations", "the other half of an instance's shape")
	for _, c := range s.Counts {
		p.printf("  %-30s %d\n", c.Of, c.N)
	}

	section(p, "What this snapshot cannot say", "")
	for _, l := range s.Limits {
		p.printf("  - %s\n", wrap(l, 72, "    "))
	}
	return p.err
}

func section(p *printer, title, sub string) {
	p.printf("\n%s\n%s\n", strings.Repeat("=", 72), title)
	if sub != "" {
		p.printf("%s\n", sub)
	}
}

func writeSettings(p *printer, settings []Setting) {
	for _, st := range settings {
		p.printf("  %-30s %s%s\n", st.Name, st.Value, redactedMark(st))
		if st.Note != "" {
			p.printf("      note: %s\n", wrap(st.Note, 64, "            "))
		}
	}
}

func redactedMark(st Setting) string {
	if st.Redacted {
		return "   [redacted to a digest]"
	}
	return ""
}
