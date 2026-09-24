package compliance

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// The text form is written with fixed indentation rather than aligned
// columns. Aligned columns look better and diff worse: one long email
// address changes the width of every line in the block, so a quarter's
// review differs from the last one everywhere instead of where somebody's
// access changed.

// WriteJSON writes the review as JSON.
func (r *Review) WriteJSON(w io.Writer) error { return writeJSON(w, r) }

// WriteText writes the review for a person to read.
func (r *Review) WriteText(w io.Writer) error {
	p := &printer{w: w}
	p.printf("Access review\n")
	p.printf("generated %s; a principal is dormant after %d days without use\n", ts(r.GeneratedAt), r.DormantDays)

	if len(r.Workspaces) == 0 {
		p.printf("\nThis instance has no workspaces.\n")
	}
	for _, ws := range r.Workspaces {
		p.printf("\n%s\nworkspace %s — %q (%s)\n", strings.Repeat("=", 72), ws.Slug, ws.Name, ws.OrgID)
		p.printf("%s\n", countLine(ws))
		if len(ws.Principals) == 0 {
			p.printf("\n  Nobody and nothing holds access to this workspace.\n")
		}
		for _, pr := range ws.Principals {
			writePrincipal(p, pr)
		}
	}

	p.printf("\n%s\nSummary\n", strings.Repeat("=", 72))
	byCode := map[string]int{}
	total := 0
	for _, ws := range r.Workspaces {
		for _, pr := range ws.Principals {
			total++
			for _, f := range pr.Findings {
				byCode[f.Code]++
			}
		}
	}
	p.printf("  %d principals across %d workspaces\n", total, len(r.Workspaces))
	if len(byCode) == 0 {
		p.printf("  no findings\n")
	}
	for _, code := range sortedKeys(byCode) {
		p.printf("  %-42s %d\n", code, byCode[code])
	}

	p.printf("\nWhat this report cannot see\n")
	for _, l := range r.Limits {
		p.printf("  - %s\n", wrap(l, 74, "    "))
	}
	return p.err
}

func countLine(ws Workspace) string {
	counts := map[string]int{}
	findings := 0
	for _, p := range ws.Principals {
		counts[p.Kind]++
		findings += len(p.Findings)
	}
	if len(ws.Principals) == 0 {
		return "  no principals"
	}
	parts := []string{}
	for _, k := range []string{"user", "service_account", "idp_group", "api_key"} {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[k], plural(k, counts[k])))
		}
	}
	return fmt.Sprintf("  %s; %d finding(s)", strings.Join(parts, ", "), findings)
}

func plural(kind string, n int) string {
	name := map[string]string{
		"user": "user", "service_account": "service account", "idp_group": "group", "api_key": "API key",
	}[kind]
	if name == "" {
		name = kind
	}
	if n == 1 {
		return name
	}
	if name == "API key" {
		return "API keys"
	}
	return name + "s"
}

func writePrincipal(p *printer, pr Principal) {
	p.printf("\n  %-16s %s  [%s]\n", pr.Kind, pr.Display, pr.Status)
	p.printf("    id             %s\n", pr.ID)
	p.printf("    since          %s\n", ts(pr.CreatedAt))
	from := ""
	if pr.LastUsedFrom != "" {
		from = " (" + pr.LastUsedFrom + ")"
	}
	p.printf("    last used      %s%s\n", agoOrNever(pr), from)
	if pr.ActsAs != "" {
		p.printf("    acts as        %s\n", strings.Replace(pr.ActsAs, "|", " ", 1))
	}
	if pr.ExpiresAt != nil {
		p.printf("    expires        %s\n", stamp(pr.ExpiresAt))
	} else if pr.Kind == "api_key" {
		p.printf("    expires        never\n")
	}
	if len(pr.Scopes) > 0 {
		p.printf("    scopes         %s\n", strings.Join(pr.Scopes, " "))
	}
	if pr.ServerID != "" {
		p.printf("    bound to       server %s\n", pr.ServerID)
	}
	if pr.Kind == "idp_group" {
		if len(pr.Members) == 0 {
			p.printf("    members        none recorded here\n")
		} else {
			p.printf("    members        %s\n", strings.Join(pr.Members, ", "))
		}
	}

	switch {
	case pr.Kind == "api_key":
		// A credential holds no binding of its own; what it may do comes
		// from the principal it acts as, already narrowed by its scopes.
	case len(pr.Bindings) == 0:
		p.printf("    bindings       none\n")
	default:
		p.printf("    bindings\n")
		for _, b := range pr.Bindings {
			scope := b.ScopeKind
			if b.ScopeID != "" {
				scope += " " + b.ScopeID
			}
			expiry := "no expiry"
			if b.ExpiresAt != nil {
				expiry = "expires " + stamp(b.ExpiresAt)
				if b.Expired {
					expiry = "EXPIRED " + stamp(b.ExpiresAt)
				}
			}
			p.printf("      %s — %s scope, source %s, %s, granted %s\n",
				b.RoleName, scope, b.Source, expiry, ts(b.CreatedAt))
			if len(b.Privileged) > 0 {
				p.printf("        privileged: %s\n", strings.Join(b.Privileged, " "))
			}
		}
	}

	if len(pr.Effective) == 0 {
		p.printf("    effective      none\n")
	} else {
		p.printf("    effective (%d) %s\n", len(pr.Effective), wrap(strings.Join(pr.Effective, " "), 60, "                   "))
	}
	for _, f := range pr.Findings {
		p.printf("    ! %s\n      %s\n", f.Code, wrap(f.Detail, 70, "      "))
	}
}

func agoOrNever(pr Principal) string {
	if pr.LastUsed == nil {
		return "never"
	}
	return stamp(pr.LastUsed)
}

// csvHeader is fixed and ordered so a spreadsheet built on one run still
// opens the next one. Columns are added at the end, never in the middle.
var csvHeader = []string{
	"workspace_slug", "workspace_id",
	"principal_kind", "principal_id", "principal_display", "status",
	"since", "last_used", "last_used_from", "acts_as", "scopes", "server_id", "credential_expires",
	"role_id", "role_name", "scope_kind", "scope_id", "source",
	"binding_granted", "binding_granted_by", "binding_expires", "binding_expired",
	"privileged_permissions", "effective_permissions", "findings",
}

// WriteCSV writes one row per principal and binding, which is the shape a
// reviewer signs: one line to look at, one decision to record beside it. A
// principal holding no binding still gets a row, because "this person has
// no access" is a thing a review has to state rather than omit.
func (r *Review) WriteCSV(w io.Writer) error {
	c := csv.NewWriter(w)
	if err := c.Write(csvHeader); err != nil {
		return err
	}
	for _, ws := range r.Workspaces {
		for _, pr := range ws.Principals {
			codes := make([]string, 0, len(pr.Findings))
			for _, f := range pr.Findings {
				codes = append(codes, f.Code)
			}
			base := []string{
				ws.Slug, ws.OrgID,
				pr.Kind, pr.ID, pr.Display, pr.Status,
				ts(pr.CreatedAt), stamp(pr.LastUsed), pr.LastUsedFrom,
				strings.Replace(pr.ActsAs, "|", " ", 1), strings.Join(pr.Scopes, " "), pr.ServerID, stamp(pr.ExpiresAt),
			}
			tail := []string{strings.Join(pr.Effective, " "), strings.Join(codes, " ")}
			if len(pr.Bindings) == 0 {
				row := append(append(append([]string{}, base...),
					"", "", "", "", "", "", "", "", "", ""), tail...)
				if err := c.Write(row); err != nil {
					return err
				}
				continue
			}
			for _, b := range pr.Bindings {
				row := append(append(append([]string{}, base...),
					b.RoleID, b.RoleName, b.ScopeKind, b.ScopeID, b.Source,
					ts(b.CreatedAt), b.CreatedBy, stamp(b.ExpiresAt), strconv.FormatBool(b.Expired),
					strings.Join(b.Privileged, " ")), tail...)
				if err := c.Write(row); err != nil {
					return err
				}
			}
		}
	}
	c.Flush()
	return c.Error()
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
