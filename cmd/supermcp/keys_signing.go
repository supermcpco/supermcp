package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/secrets"
)

const rotateSigningUsage = `Usage: supermcp keys rotate-signing [flags]

  -revoke      retire every published key now and make a new one active
  -by <name>   who is rotating, for the audit trail (default $USER)
  -format      text | json

Without -revoke it publishes the next signing key, as the scheduled
rotation does. The job promotes it once it has been published for a day,
and the old key keeps verifying for thirty days after that.

With -revoke, for an incident, the new key signs at once. Every access
token signed so far is refused within a minute, and clients have to use
their refresh tokens, or sign in again, to get new ones.
`

// signingRotation is the command's report, as text and as JSON.
type signingRotation struct {
	Revoked bool   `json:"revoked"`
	Changed bool   `json:"changed"`
	KID     string `json:"kid"`
	Status  string `json:"status"`
	// Since is when KID entered the key set, and ActiveFrom the earliest
	// the scheduled job promotes it. ActiveFrom is empty for an active key.
	Since      time.Time  `json:"published_at"`
	ActiveFrom *time.Time `json:"active_from,omitempty"`
	Replaced   string     `json:"replaced,omitempty"`
	Retired    []string   `json:"retired,omitempty"`
}

func newSigningRotation(rep mcpauth.Replacement, revoke bool) signingRotation {
	out := signingRotation{
		Revoked: revoke, Changed: rep.Minted, KID: rep.KID, Status: "next",
		Since: rep.PublishedAt, Replaced: rep.Replaced, Retired: rep.Retired,
	}
	if rep.Active {
		out.Status = "active"
	} else {
		from := rep.PublishedAt.Add(mcpauth.PrePublish)
		out.ActiveFrom = &from
	}
	return out
}

// keysRotateSigning replaces the key that signs OAuth access tokens and
// audit checkpoints, outside the schedule.
func keysRotateSigning(args []string) error {
	fs := flag.NewFlagSet("keys rotate-signing", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, rotateSigningUsage) }
	revoke := fs.Bool("revoke", false, "retire every published key now and make a new one active")
	by := fs.String("by", os.Getenv("USER"), "who is rotating, for the audit trail")
	format := fs.String("format", "text", "text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fmt.Fprint(os.Stderr, rotateSigningUsage)
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := checkFormat(*format, "text", "json"); err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()
	d, err := keysSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	// The new key is sealed under the instance data key, so the master key
	// has to open what it wraps before a key only it can open is the one
	// that signs.
	if prover, ok := d.Set.Active.(keyProver); ok {
		if err := prover.Verify(ctx); err != nil {
			return fmt.Errorf("master key %s is not usable: %w", d.Set.Active.Ref(), err)
		}
	}

	// Blocking on the audit write, as oauth clients does: a change of
	// signing key that left no record looks like a bug when tokens are
	// investigated.
	writer := audit.NewWriter(d.DB, d.Log, //nolint:contextcheck // the writer owns its lifetime
		audit.Options{OnUnavailable: audit.UnavailableBlock})
	defer writer.Close()

	keyring := mcpauth.NewKeyring(d.DB, secrets.New(d.Set.Active, d.Keys, d.Set.Previous...), nil)
	keyring.Log = d.Log
	rep, err := keyring.Replace(ctx, *revoke)
	if err != nil {
		return err
	}
	out := newSigningRotation(rep, *revoke)
	if out.Changed {
		if err := writer.EmitSync(ctx, audit.Event{
			Category: audit.CategoryAdmin, Action: "signing_key.rotate", Outcome: audit.Success,
			ActorKind: "system", ActorDisplay: "supermcp keys rotate-signing",
			TargetKind: "signing_key", TargetID: rep.KID,
			Meta: map[string]any{"by": *by, "revoked": *revoke, "status": out.Status,
				"replaced": rep.Replaced, "retired": rep.Retired},
		}); err != nil {
			return fmt.Errorf("signing key %s is %s, but the audit event was not written: %w", rep.KID, out.Status, err)
		}
	}
	return writeSigningRotation(os.Stdout, out, *format)
}

func writeSigningRotation(w io.Writer, r signingRotation, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	const stamp = "2006-01-02 15:04 MST"
	var err error
	switch {
	case r.Status == "active" && len(r.Retired) > 0:
		_, err = fmt.Fprintf(w, "signing key %s is active\nretired %s: tokens they signed are refused, by every replica within a minute\n",
			r.KID, strings.Join(r.Retired, ", "))
	case r.Status == "active":
		_, err = fmt.Fprintf(w, "signing key %s is active; there was no key before it\n", r.KID)
	case !r.Changed:
		_, err = fmt.Fprintf(w, "signing key %s has been published since %s and becomes active at the first scheduled run after %s; nothing changed\n",
			r.KID, r.Since.UTC().Format(stamp), r.ActiveFrom.UTC().Format(stamp))
	default:
		_, err = fmt.Fprintf(w, "published signing key %s; it becomes active at the first scheduled run after %s\n%s keeps signing until then and verifying for thirty days after\n",
			r.KID, r.ActiveFrom.UTC().Format(stamp), r.Replaced)
	}
	return err
}
