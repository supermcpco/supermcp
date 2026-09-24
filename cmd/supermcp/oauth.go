package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/mcpauth"
)

const oauthUsage = `Usage: supermcp oauth clients <subcommand> [flags]

Subcommands:
  list      list registered clients (-status pending|approved|rejected)
  approve   let a client start sign-ins:      approve <client_id>
  reject    refuse a client and end its tokens: reject <client_id>

With SUPERMCP_DCR_MODE=approval, a client that registers itself waits as
pending until an operator approves it here. Clients belong to the
instance rather than to a workspace, which is why this is an operator
command and not a screen. Every decision is written to the audit trail.
`

func oauthCmd(args []string) error {
	if len(args) < 2 || args[0] != "clients" {
		fmt.Fprint(os.Stderr, oauthUsage)
		return fmt.Errorf("want: oauth clients list|approve|reject")
	}
	switch args[1] {
	case "list":
		return oauthClientsList(args[2:])
	case "approve":
		return oauthClientsDecide(args[2:], true)
	case "reject":
		return oauthClientsDecide(args[2:], false)
	default:
		fmt.Fprint(os.Stderr, oauthUsage)
		return fmt.Errorf("unknown subcommand %q", args[1])
	}
}

func oauthClientsList(args []string) error {
	fs := flag.NewFlagSet("oauth clients list", flag.ContinueOnError)
	status := fs.String("status", "", "only clients in this state: pending | approved | rejected")
	format := fs.String("format", "text", "text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *status != "" {
		if err := checkFormat(*status, "pending", "approved", "rejected"); err != nil {
			return fmt.Errorf("-status: %w", err)
		}
	}
	if err := checkFormat(*format, "text", "json"); err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	d, err := complianceSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	o := &mcpauth.OAuth{DB: d.Deps.DB}
	clients, err := o.ListClients(ctx, *status)
	if err != nil {
		return err
	}
	return writeClients(os.Stdout, clients, *format)
}

// writeClients prints the list as a table for a person or as JSON for a
// script.
func writeClients(w io.Writer, clients []mcpauth.ClientInfo, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(clients)
	}
	if len(clients) == 0 {
		_, err := fmt.Fprintln(w, "no clients")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CLIENT ID\tNAME\tSTATUS\tREGISTERED\tFROM\tREDIRECTS")
	for _, c := range clients {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", c.ClientID, c.Name, c.Status,
			c.CreatedAt.Format("2006-01-02 15:04"), c.RegistrationIP, strings.Join(c.RedirectURIs, " "))
	}
	return tw.Flush() // the writes above only buffer; a write error surfaces here
}

func oauthClientsDecide(args []string, approve bool) error {
	verb := "reject"
	if approve {
		verb = "approve"
	}
	fs := flag.NewFlagSet("oauth clients "+verb, flag.ContinueOnError)
	by := fs.String("by", os.Getenv("USER"), "who is deciding, for the audit trail")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: supermcp oauth clients %s [-by name] <client_id>", verb)
	}
	clientID := fs.Arg(0)

	ctx, stop := signalContext()
	defer stop()
	d, err := complianceSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	// Blocking on the audit write is deliberate: a decision about who may
	// sign in that left no record is one nobody can account for.
	writer := audit.NewWriter(d.Deps.DB, d.Log, //nolint:contextcheck // the writer owns its lifetime
		audit.Options{OnUnavailable: audit.UnavailableBlock})
	defer writer.Close()

	o := &mcpauth.OAuth{DB: d.Deps.DB}
	before, revoked, err := o.DecideClient(ctx, clientID, approve, *by)
	if errors.Is(err, mcpauth.ErrClientNotFound) {
		return fmt.Errorf("%w: %s", err, clientID)
	}
	if err != nil {
		return err
	}
	after := "rejected"
	if approve {
		after = "approved"
	}
	if err := writer.EmitSync(ctx, audit.Event{
		Category: audit.CategoryAdmin, Action: "oauth.client." + verb, Outcome: audit.Success,
		ActorKind: "system", ActorDisplay: "supermcp oauth clients " + verb,
		TargetKind: "oauth_client", TargetID: clientID, TargetDisplay: before.Name,
		Diff: audit.Changes(map[string]any{"status": before.Status}, map[string]any{"status": after}),
		Meta: map[string]any{"by": *by, "refresh_tokens_revoked": revoked},
	}); err != nil {
		return fmt.Errorf("the client is %s, but the audit event was not written: %w", after, err)
	}

	fmt.Printf("%s (%s): %s -> %s\n", clientID, before.Name, before.Status, after)
	if revoked > 0 {
		fmt.Printf("revoked %d refresh tokens\n", revoked)
	}
	return nil
}
