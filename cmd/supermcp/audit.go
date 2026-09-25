package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/telemetry"
	"github.com/supermcpco/supermcp/internal/tenant"
)

const auditUsage = `Usage: supermcp audit <subcommand> [flags]

Subcommands:
  verify   walk the hash chain and report whether the record is intact
`

func auditCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, auditUsage)
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "verify":
		return auditVerify(args[1:])
	default:
		fmt.Fprint(os.Stderr, auditUsage)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// auditVerify checks the whole instance chain, not one organisation's
// events: the sequence is shared, so a tenant's rows can only be trusted
// as far as the rows around them are.
func auditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	from := fs.Int64("from", 0, "first sequence to check (0 = the start of the chain)")
	to := fs.Int64("to", 0, "last sequence to check (0 = the head of the chain)")
	format := fs.String("format", "text", "text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unknown format %q, want text or json", *format)
	}
	if *to != 0 && *from > *to {
		return fmt.Errorf("-from %d is above -to %d", *from, *to)
	}

	cfg, err := config.LoadOffline(version)
	if err != nil {
		return err
	}
	log := telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.Version)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Verification reads across every tenant, which is the maintenance
	// pool's job, so the app role is not needed here.
	st, err := store.Open(ctx, cfg.DatabaseURL, cfg.MaintDatabaseURL, log, store.Options{})
	if err != nil {
		return err
	}
	defer st.Close()

	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
	// The checkpoints are checked against the public halves of the signing
	// keys, so no master key is needed and none is unsealed.
	keyring := mcpauth.NewKeyring(db, nil, nil)
	reader := &audit.Reader{DB: db, VerifyAnchor: keyring.VerifyDigest}
	res, err := reader.Verify(ctx, *from, *to)
	if err != nil {
		return err
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else {
		// A run that breaks on its first row has verified no range, so it
		// has none to report.
		if res.Checked == 0 {
			fmt.Println("checked 0 events")
		} else {
			fmt.Printf("checked %d events (sequence %d to %d)\n", res.Checked, res.FirstSeq, res.LastSeq)
		}
		// Retention removes the oldest events, row by row or a month at a
		// time with its partition, and anchors where it stopped.
		if res.RetentionCut > 0 {
			fmt.Printf("starts after the retention cut at sequence %d\n", res.RetentionCut)
		}
		if res.Anchors > 0 {
			fmt.Printf("matched %d checkpoints", res.Anchors)
			if res.Unsigned > 0 {
				fmt.Printf(" (%d written without a signing key)", res.Unsigned)
			}
			fmt.Println()
		}
		if res.Valid {
			fmt.Println("the chain is intact")
		} else {
			fmt.Printf("the chain is broken at sequence %d: %s\n", res.BrokenAt, res.Explained)
		}
	}
	// A broken chain leaves by the error path so a cron job notices.
	if !res.Valid {
		return fmt.Errorf("the audit chain is broken at sequence %d", res.BrokenAt)
	}
	return nil
}
