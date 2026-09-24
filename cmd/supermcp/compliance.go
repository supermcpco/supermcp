package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/supermcpco/supermcp/internal/compliance"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/telemetry"
	"github.com/supermcpco/supermcp/internal/tenant"
)

const complianceUsage = `Usage: supermcp compliance <subcommand> [flags]

Subcommands:
  access-review    every principal, the roles they hold, where each binding
                   applies, when it expires, and what it adds up to
  crypto-report    every key, what it seals, whether it opens, and what this
                   instance does not encrypt at all
  config-snapshot  the settings that decide behaviour, with secrets reduced to
                   digests, so an instance can be described without being handed over

Each reads the same database and master keys as the gateway. None of them
writes anything.
`

func complianceCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, complianceUsage)
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "access-review":
		return complianceAccessReview(args[1:])
	case "crypto-report":
		return complianceCryptoReport(args[1:])
	case "config-snapshot":
		return complianceConfigSnapshot(args[1:])
	default:
		fmt.Fprint(os.Stderr, complianceUsage)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// complianceAccessReview reports who can do what.
//
// It defaults to every workspace. A reviewer asked to attest to access
// has to be shown all of it; a report that covered one workspace by
// default would be a report that quietly omitted the others.
func complianceAccessReview(args []string) error {
	fs := flag.NewFlagSet("compliance access-review", flag.ContinueOnError)
	org := fs.String("org", "", "limit the review to one workspace, by id or slug (default: every workspace)")
	dormant := fs.Int("dormant-days", compliance.DefaultDormantDays, "how long a principal may go unused before the review says so")
	format := fs.String("format", "text", "text | json | csv")
	out := fs.String("out", "", "write to this file instead of standard output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := checkFormat(*format, "text", "json", "csv"); err != nil {
		return err
	}
	if *dormant <= 0 {
		return fmt.Errorf("-dormant-days must be a positive number of days, got %d", *dormant)
	}

	ctx, stop := signalContext()
	defer stop()
	d, err := complianceSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	rev, err := compliance.AccessReview(ctx, d.Deps, compliance.AccessOptions{OrgID: *org, DormantDays: *dormant})
	if err != nil {
		return err
	}
	w, closeOut, err := openOut(*out)
	if err != nil {
		return err
	}
	defer closeOut()
	switch *format {
	case "json":
		return rev.WriteJSON(w)
	case "csv":
		return rev.WriteCSV(w)
	default:
		return rev.WriteText(w)
	}
}

// complianceCryptoReport reports the key hierarchy and what is in the
// clear. It does not leave by the error path when a data key fails to
// open: that is what `supermcp keys verify` is for, and a report an
// operator cannot read because the command exited first is no use to them.
func complianceCryptoReport(args []string) error {
	fs := flag.NewFlagSet("compliance crypto-report", flag.ContinueOnError)
	format := fs.String("format", "text", "text | json")
	out := fs.String("out", "", "write to this file instead of standard output")
	if err := fs.Parse(args); err != nil {
		return err
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

	// The master keys are optional here. Without them the report still
	// lists every data key and says it did not check that they open, which
	// is a weaker claim honestly made rather than a command that refuses.
	var set *secrets.KEKSet
	if set, err = secrets.KEKFromEnv(ctx, os.Getenv); err != nil {
		fmt.Fprintf(os.Stderr, "no master key for this run (%v); the report will say the data keys were not checked\n", err)
		set = nil
	}

	rep, err := compliance.CryptoReport(ctx, d.Deps, compliance.CryptoOptions{Keys: set})
	if err != nil {
		return err
	}
	w, closeOut, err := openOut(*out)
	if err != nil {
		return err
	}
	defer closeOut()
	if *format == "json" {
		return rep.WriteJSON(w)
	}
	return rep.WriteText(w)
}

func complianceConfigSnapshot(args []string) error {
	fs := flag.NewFlagSet("compliance config-snapshot", flag.ContinueOnError)
	format := fs.String("format", "text", "text | json")
	out := fs.String("out", "", "write to this file instead of standard output")
	if err := fs.Parse(args); err != nil {
		return err
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

	snap, err := compliance.ConfigSnapshot(ctx, d.Deps, compliance.SnapshotOptions{Cfg: d.Cfg})
	if err != nil {
		return err
	}
	w, closeOut, err := openOut(*out)
	if err != nil {
		return err
	}
	defer closeOut()
	if *format == "json" {
		return snap.WriteJSON(w)
	}
	return snap.WriteText(w)
}

// ---------------------------------------------------------------------------
// shared setup

// complianceDeps is what every compliance and subject-access command
// needs: the configuration, a logger, and both pools.
type complianceDeps struct {
	Cfg  *config.Config
	Log  *slog.Logger
	Deps compliance.Deps

	store *store.Store
}

func (d complianceDeps) Close() {
	if d.store != nil {
		d.store.Close()
	}
}

// complianceSetup opens both pools with the app role set, so that the
// parts of a report that are tenant-scoped run under row-level security
// exactly as a request would. A report that read everything through the
// maintenance pool would be easier to write and would stop being evidence
// that the tenant policies do anything.
func complianceSetup(ctx context.Context) (complianceDeps, error) {
	cfg, err := config.LoadOffline(version)
	if err != nil {
		return complianceDeps{}, err
	}
	log := telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.Version)
	st, err := store.Open(ctx, cfg.DatabaseURL, cfg.MaintDatabaseURL, log, store.Options{AppRole: true})
	if err != nil {
		return complianceDeps{}, err
	}
	return complianceDeps{
		Cfg:   cfg,
		Log:   log,
		Deps:  compliance.Deps{DB: &tenant.DB{App: st.App, Maint: st.Maint, Log: log}},
		store: st,
	}, nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func checkFormat(got string, allowed ...string) error {
	for _, a := range allowed {
		if got == a {
			return nil
		}
	}
	return fmt.Errorf("unknown format %q, want one of %v", got, allowed)
}

// openOut returns where a report is written. An empty path is standard
// output, which is not closed: closing it would break a second command in
// the same pipeline.
func openOut(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}
