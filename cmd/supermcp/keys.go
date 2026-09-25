package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/secrets/rotatepg"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/telemetry"
	"github.com/supermcpco/supermcp/internal/tenant"
)

const keysUsage = `Usage: supermcp keys <subcommand> [flags]

Subcommands:
  rotate-kek       re-wrap every data key under the configured master key
  rotate-dek       re-seal a workspace's rows under a new data key
  verify           check that every data key opens with the keys this process holds
  rotate-signing   replace the key that signs access tokens (-revoke for an incident)

All of them read the master keys from the same settings as the gateway:
SUPERMCP_KEK_PROVIDER (local|awskms), and SUPERMCP_KEK_PREVIOUS for keys
that may only decrypt: a local key's base64, <reference>|<base64>, or
awskms:<key id, alias or ARN>[@<region>][#<deployment>].

Reach for rotate-kek when the master key is suspect or is moving; it
rewrites no ciphertext. Reach for rotate-dek when the sealed values
themselves are suspect; it rewrites every affected row. Neither is a
substitute for the other.
`

const rotateDEKUsage = `Usage: supermcp keys rotate-dek [flags]

  -org <id>    rotate one workspace's data key
  -instance    rotate the instance data key (signing keys)
  -all         rotate every scope that has an active data key
  -batch N     rows per transaction (default 500)
  -dry-run     report what would move and change nothing
  -format      text | json

Exactly one of -org, -instance and -all is required.
`

func keysCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, keysUsage)
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "rotate-kek":
		return keysRotateKEK(args[1:])
	case "rotate-dek":
		return keysRotateDEK(args[1:])
	case "verify":
		return keysVerify(args[1:])
	case "rotate-signing":
		return keysRotateSigning(args[1:])
	default:
		fmt.Fprint(os.Stderr, keysUsage)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// keyProver is implemented by master keys that can prove themselves
// before any key material depends on them. Declared here because this is
// the only caller that cares; AWSKMS satisfies it, the local key has
// nothing to prove.
type keyProver interface {
	Verify(ctx context.Context) error
}

// keysRotateKEK moves every data key onto the configured master key. It
// changes no ciphertext at all: the data keys are the only thing the
// master key protects, so a million sealed rows are untouched and the run
// costs one wrap per tenant. Running it twice is harmless — a key already
// under the target is skipped — which is also how an interrupted run is
// finished.
func keysRotateKEK(args []string) error {
	fs := flag.NewFlagSet("keys rotate-kek", flag.ContinueOnError)
	format := fs.String("format", "text", "text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unknown format %q, want text or json", *format)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	d, err := keysSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	// Prove the target key round-trips before touching a single row. The
	// rotation verifies each re-wrap too, but a key that can encrypt and
	// not decrypt — an IAM policy granting kms:Encrypt only, a key pending
	// deletion — is a property of the configuration, and finding it out
	// here costs one probe instead of one failed tenant.
	if prover, ok := d.Set.Active.(keyProver); ok {
		if err := prover.Verify(ctx); err != nil {
			return fmt.Errorf("master key %s is not usable: %w", d.Set.Active.Ref(), err)
		}
	}

	rep, rotErr := secrets.RotateKEK(ctx, secrets.KEKRotation{
		Store: d.Keys,
		To:    d.Set.Active,
		From:  d.Set.Previous,
		Log:   d.Log,
	})
	// The report is printed either way: a run that stops half way has
	// still moved the keys it counted, and the operator needs to know how
	// far it got before deciding what to do next.
	if *format == "json" {
		if err := printJSON(struct {
			Target    string `json:"target"`
			Examined  int    `json:"examined"`
			Skipped   int    `json:"skipped"`
			ReWrapped int    `json:"rewrapped"`
		}{d.Set.Active.Ref(), rep.Examined, rep.Skipped, rep.ReWrapped}); err != nil {
			return err
		}
	} else {
		fmt.Printf("examined %d data keys: %d already under %s, %d re-wrapped\n",
			rep.Examined, rep.Skipped, d.Set.Active.Ref(), rep.ReWrapped)
	}
	return rotErr
}

// ---------------------------------------------------------------------------
// Data key rotation

// dekLockClass is the advisory lock class data key rotation contends for.
// It is a constant rather than a hash of a name so the value is greppable
// in pg_locks when someone is wondering who holds it, and it is not the
// background sweeps' lock: a rotation can take an hour and must not stop
// audit deliveries for the length of it.
//
// The lock is taken per scope, on a session rather than a transaction,
// which is where this departs from the sweeps in jobs.go. A sweep is one
// transaction and an xact lock frees itself when that transaction ends; a
// rotation is hundreds of transactions with the decision to mint a key
// taken before the first of them, so the lock has to outlive each one. A
// session lock still frees itself when the connection goes, so a replica
// that dies mid-rotation blocks nobody.
const dekLockClass int32 = 0x5DA17DE4

// dekReport is one scope's rotation, as text and as JSON.
type dekReport struct {
	Scope    string           `json:"scope"`
	OldKeyID string           `json:"old_key_id,omitempty"`
	NewKeyID string           `json:"new_key_id,omitempty"`
	Resumed  bool             `json:"resumed"`
	Tables   []dekTableReport `json:"tables"`
	Retired  []string         `json:"retired_keys,omitempty"`
	Held     map[string]int   `json:"keys_still_referenced,omitempty"`
}

// dekTableReport is one sealed column's share of one scope's rotation.
// Pending is what a dry run reports and the others are what a real run
// did, so a report carries either shape and never both.
type dekTableReport struct {
	Table    string `json:"table"`
	Pending  int    `json:"pending,omitempty"`
	Scanned  int    `json:"scanned,omitempty"`
	ReSealed int    `json:"resealed,omitempty"`
	Empty    int    `json:"empty,omitempty"`
	Vanished int    `json:"vanished,omitempty"`
}

// keysRotateDEK mints a new data key for a scope and re-seals that
// scope's rows under it.
//
// Unlike rotate-kek this rewrites every affected row, so it is the
// expensive one and the one with something to lose: the row being written
// holds the only copy of its ciphertext. Every value is opened again
// before it is written, every statement is checked to have matched exactly
// the row it named, and the key being replaced is left decrypt_only until
// a census says nothing references it.
//
// An interrupted run is finished by running the command again. It works
// out for itself that a rotation was left unfinished — a decrypt-only key
// with rows still on it — and carries on onto the key that run minted
// rather than minting a third.
func keysRotateDEK(args []string) error {
	fs := flag.NewFlagSet("keys rotate-dek", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, rotateDEKUsage) }
	org := fs.String("org", "", "the workspace whose data key to rotate")
	instance := fs.Bool("instance", false, "rotate the instance data key")
	all := fs.Bool("all", false, "rotate every scope with an active data key")
	batch := fs.Int("batch", 0, "rows per transaction (default 500)")
	dryRun := fs.Bool("dry-run", false, "report what would move and change nothing")
	format := fs.String("format", "text", "text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unknown format %q, want text or json", *format)
	}
	chosen := 0
	for _, set := range []bool{*org != "", *instance, *all} {
		if set {
			chosen++
		}
	}
	if chosen != 1 {
		fmt.Fprint(os.Stderr, rotateDEKUsage)
		return fmt.Errorf("choose exactly one of -org, -instance and -all")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	d, err := keysSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	// The master key has to be able to open what it wrapped before a single
	// row is rewritten, for the same reason rotate-kek probes it: a key
	// that encrypts and cannot decrypt turns the first batch into a
	// tableful of values nothing can read.
	if prover, ok := d.Set.Active.(keyProver); ok {
		if err := prover.Verify(ctx); err != nil {
			return fmt.Errorf("master key %s is not usable: %w", d.Set.Active.Ref(), err)
		}
	}
	// And the catalogue has to still describe the schema. A sealed column
	// nothing names is the failure this command exists to avoid: the run
	// would report success having left it on the old key, and the key
	// would then look retirable. The checked list is what the rotation
	// then walks, so there is no way to reach the rows without having
	// asked the schema first.
	deployed, err := rotatepg.Check(ctx, d.DB)
	if err != nil {
		return err
	}

	scopes, err := dekScopes(ctx, d, *org, *instance, *all)
	if err != nil {
		return err
	}

	sealer := secrets.New(d.Set.Active, d.Keys, d.Set.Previous...)
	reports := make([]dekReport, 0, len(scopes))
	var runErr error
	for _, scope := range scopes {
		rep, err := rotateOneScope(ctx, d, sealer, deployed, scope, *batch, *dryRun)
		reports = append(reports, rep)
		if err != nil {
			// Stop at the first scope that fails rather than grinding on.
			// The usual cause — a master key that cannot open what it
			// wrapped, a table the catalogue has wrong — is the same for
			// every scope, and a second failure tells the operator nothing
			// the first did not.
			runErr = fmt.Errorf("scope %s: %w", scope, err)
			break
		}
	}
	// The report prints either way: a run that stopped half way has still
	// moved the rows it counted, and what to do next depends on how far it
	// got.
	if err := printDEKReport(*format, *dryRun, reports); err != nil {
		return err
	}
	return runErr
}

// dekScopes resolves the flags to the scopes to work on.
func dekScopes(ctx context.Context, d keysDeps, org string, instance, all bool) ([]string, error) {
	switch {
	case all:
		scopes, err := rotatepg.Scopes(ctx, d.DB)
		if err != nil {
			return nil, err
		}
		if len(scopes) == 0 {
			return nil, fmt.Errorf("no scope has an active data key; nothing has been sealed yet")
		}
		return scopes, nil
	case instance:
		return []string{secrets.ScopeInstance}, nil
	default:
		// An organisation with no active data key has sealed nothing. Say
		// so rather than minting a key for it: rotating a scope into
		// existence would be a confusing way to learn the id was a typo.
		scope := secrets.ScopeOrg(org)
		if _, ok, err := d.Keys.Active(ctx, scope); err != nil {
			return nil, err
		} else if !ok {
			return nil, fmt.Errorf("workspace %q has no active data key; it has sealed nothing to rotate", org)
		}
		return []string{scope}, nil
	}
}

// rotateOneScope rotates a single scope, or reports what it would do.
func rotateOneScope(ctx context.Context, d keysDeps, sealer *secrets.Sealer, deployed []rotatepg.Target, scope string, batch int, dryRun bool) (dekReport, error) {
	rep := dekReport{Scope: scope}
	rows, err := rotatepg.NewStore(d.DB, scope)
	if err != nil {
		return rep, err
	}
	targets := rotatepg.ScopeTargets(deployed, scope)

	active, ok, err := d.Keys.Active(ctx, scope)
	if err != nil {
		return rep, err
	}
	if !ok {
		return rep, fmt.Errorf("no active data key")
	}
	rep.OldKeyID = shortKey(active.ID)

	if dryRun {
		// A dry run takes no lock. It reads what a rotation would read and
		// is allowed to be slightly out of date; taking the lock would let
		// a report block the work it is a report about.
		census, err := scopeCensus(ctx, rows, targets)
		if err != nil {
			return rep, err
		}
		resume, err := unfinishedRotation(ctx, d, census, scope)
		if err != nil {
			return rep, err
		}
		rep.Resumed = resume
		return dekPlan(rep, census, active.ID, resume), nil
	}

	// Serialise against other replicas and other operators, per scope, so
	// two workspaces can rotate at once but one workspace cannot be
	// rotated twice. Without this, two runs would each demote the active
	// key and mint their own replacement, and every row either of them had
	// already moved would be stranded on a key the other was about to
	// retire.
	unlock, err := lockScope(ctx, d.maint, scope)
	if err != nil {
		return rep, err
	}
	defer unlock()

	// Decide between starting a rotation and finishing one. A decrypt-only
	// key that rows still name means the last run stopped part way: a run
	// that finished would have retired that key, because retirement is
	// exactly the census finding nothing left on it. Carrying on is then
	// the only safe reading — minting a third key would leave two
	// half-used ones behind and make the next run's arithmetic worse.
	//
	// The census is taken inside the lock, so nothing can start a rotation
	// between the question and the answer.
	census, err := scopeCensus(ctx, rows, targets)
	if err != nil {
		return rep, err
	}
	resume, err := unfinishedRotation(ctx, d, census, scope)
	if err != nil {
		return rep, err
	}
	rep.Resumed = resume

	rot, err := secrets.RotateDataKey(ctx, secrets.DataKeyRotation{
		Store: d.Keys, Sealer: sealer, Rows: rows, Scope: scope,
		Targets: targets, Batch: batch, ReSealOnly: resume, Log: d.Log,
	})
	rep.OldKeyID, rep.NewKeyID = shortKey(rot.OldKeyID), shortKey(rot.NewKeyID)
	for _, t := range rot.Targets {
		rep.Tables = append(rep.Tables, dekTableReport{
			Table: t.Target, Scanned: t.Scanned, ReSealed: t.ReSealed,
			Empty: t.Empty, Vanished: t.Vanished,
		})
	}
	if err != nil {
		return rep, err
	}

	// Only now, with every target walked to the end, is it safe to ask
	// whether the superseded key can be let go.
	ret, err := secrets.RetireSuperseded(ctx, secrets.Retirement{
		Store: d.Keys, Census: rows, Scope: scope, Targets: targets, Log: d.Log,
	})
	rep.Retired, rep.Held = ret.Retired, ret.Held
	return rep, err
}

// tableCensus is one target's rows counted by the key each one names.
type tableCensus struct {
	target string
	counts map[[16]byte]int
}

// scopeCensus counts every target's rows by data key, in one pass. Both
// the resume decision and the dry run's arithmetic come out of it, and
// they have to agree: asking twice would let a row move between the two
// questions and make the report contradict the plan.
func scopeCensus(ctx context.Context, rows *rotatepg.Store, targets []secrets.ReSealTarget) ([]tableCensus, error) {
	out := make([]tableCensus, 0, len(targets))
	for _, t := range targets {
		counts, err := rows.KeyCensus(ctx, t)
		if err != nil {
			return nil, err
		}
		out = append(out, tableCensus{target: t.String(), counts: counts})
	}
	return out, nil
}

// dekPlan fills in what a rotation would have to move, without moving it.
//
// What counts as pending depends on which rotation is about to happen. A
// fresh one mints a key, so every sealed row moves, including the ones on
// the key that is active right now. A resumed one seals onto the key that
// is already active, so only what is not yet on it moves. Reporting the
// second number for the first case is how a dry run comes back saying
// there is nothing to do just before rewriting the table.
func dekPlan(rep dekReport, census []tableCensus, active [16]byte, resume bool) dekReport {
	for _, c := range census {
		pending := 0
		for id, n := range c.counts {
			if !resume || id != active {
				pending += n
			}
		}
		rep.Tables = append(rep.Tables, dekTableReport{Table: c.target, Pending: pending})
	}
	return rep
}

// unfinishedRotation reports whether a decrypt-only key of this scope
// still has rows on it, which is what an interrupted run leaves behind.
func unfinishedRotation(ctx context.Context, d keysDeps, census []tableCensus, scope string) (bool, error) {
	all, err := d.Keys.ListDataKeys(ctx)
	if err != nil {
		return false, fmt.Errorf("list data keys: %w", err)
	}
	superseded := map[[16]byte]bool{}
	for _, dk := range all {
		if dk.Scope == scope && dk.Status == "decrypt_only" {
			superseded[dk.ID] = true
		}
	}
	if len(superseded) == 0 {
		return false, nil
	}
	for _, c := range census {
		for id, n := range c.counts {
			if n > 0 && superseded[id] {
				return true, nil
			}
		}
	}
	return false, nil
}

// lockScope takes the scope's advisory lock on a connection of its own and
// returns the release. A replica that cannot take it leaves rather than
// waits: whoever holds it is doing the same work, and two rotations of one
// scope are worse than one late one.
func lockScope(ctx context.Context, pool *pgxpool.Pool, scope string) (func(), error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("take the rotation lock: %w", err)
	}
	// The object id is derived here rather than with Postgres's hashtext,
	// which is an internal whose value is not promised across versions. A
	// lock id that changed under an upgrade would let two rotations run.
	h := fnv.New32a()
	_, _ = h.Write([]byte(scope))
	obj := int32(h.Sum32()) //nolint:gosec // the wrap is the point: an advisory lock id is any 32 bits.
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", dekLockClass, obj).Scan(&got); err != nil {
		conn.Release()
		return nil, fmt.Errorf("take the rotation lock: %w", err)
	}
	if !got {
		conn.Release()
		return nil, fmt.Errorf("another rotation of %s is already running (advisory lock %d/%d)", scope, dekLockClass, obj)
	}
	return func() {
		// Released on a context of its own: the usual reason to be here is
		// that the run's context was cancelled, and an unlock that
		// inherited that cancellation would never be sent. Ending the
		// session would free the lock anyway, but not before this process
		// has finished its remaining scopes.
		rel, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(rel, "SELECT pg_advisory_unlock($1, $2)", dekLockClass, obj); err != nil {
			// An unlock that did not land must not hand the connection
			// back to the pool still holding the lock, where it would sit
			// out the process's lifetime blocking the next rotation.
			// Closing it ends the session, which is what frees the lock;
			// the pool discards a closed connection on release.
			_ = conn.Conn().Close(rel)
		}
		conn.Release()
	}, nil
}

func shortKey(id [16]byte) string {
	if id == ([16]byte{}) {
		return ""
	}
	return fmt.Sprintf("%x", id[:4])
}

func printDEKReport(format string, dryRun bool, reports []dekReport) error {
	if format == "json" {
		return printJSON(struct {
			DryRun bool        `json:"dry_run"`
			Scopes []dekReport `json:"scopes"`
		}{dryRun, reports})
	}
	for _, r := range reports {
		switch {
		case dryRun:
			fmt.Printf("%s is on data key %s\n", r.Scope, r.OldKeyID)
		case r.NewKeyID == "":
			fmt.Printf("%s: nothing was moved\n", r.Scope)
		case r.Resumed:
			fmt.Printf("%s: finished an unfinished rotation onto data key %s\n", r.Scope, r.NewKeyID)
		default:
			fmt.Printf("%s: data key %s replaced by %s\n", r.Scope, r.OldKeyID, r.NewKeyID)
		}
		for _, t := range r.Tables {
			if dryRun {
				fmt.Printf("  %-28s %d rows to re-seal\n", t.Table, t.Pending)
				continue
			}
			line := fmt.Sprintf("  %-28s %d of %d rows re-sealed", t.Table, t.ReSealed, t.Scanned)
			if t.Empty > 0 {
				line += fmt.Sprintf(", %d hold nothing", t.Empty)
			}
			if t.Vanished > 0 {
				line += fmt.Sprintf(", %d went away mid-run", t.Vanished)
			}
			fmt.Println(line)
		}
		for _, k := range r.Retired {
			fmt.Printf("  data key %s retired: nothing references it\n", k)
		}
		for k, n := range r.Held {
			fmt.Printf("  data key %s kept decrypt-only: %d rows still reference it\n", k, n)
		}
		if r.Resumed {
			fmt.Printf("  run again to move %s onto a key of its own\n", r.Scope)
		}
	}
	return nil
}

// keyCheck is one data key's result in a verification.
type keyCheck struct {
	KeyID  string `json:"key_id"`
	Scope  string `json:"scope"`
	KEKRef string `json:"kek_ref"`
	Status string `json:"status"`
	// Active is whether the key is recorded under the active master key,
	// which is what says a previous key can be let go.
	Active bool `json:"active"`
	// HeldBy names the configured key that opened it: active, previous,
	// or replica (a multi-Region key opening its replica's data key).
	HeldBy string `json:"held_by,omitempty"`
	Error  string `json:"error,omitempty"`
}

// verifyReport is what keys verify prints, as text or JSON.
type verifyReport struct {
	Checked     int        `json:"checked"`
	Active      string     `json:"active"`
	Previous    []string   `json:"previous"`
	UnderActive int        `json:"under_active"`
	Keys        []keyCheck `json:"keys"`
	Failed      []keyCheck `json:"failed"`
}

// keysVerify opens every data key with the keys this process holds and
// leaves by the error path if any of them cannot be opened, so it works
// as a deployment check. Run before a rotation it says whether the new
// configuration can read what is already there; run after, it says
// whether anything was left behind. It also says which master key each
// scope's data keys are recorded under, because "every key opens" is true
// half way through a move too, and what an operator needs before taking a
// previous key out of the configuration is that nothing is under it.
func keysVerify(args []string) error {
	fs := flag.NewFlagSet("keys verify", flag.ContinueOnError)
	format := fs.String("format", "text", "text | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unknown format %q, want text or json", *format)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	d, err := keysSetup(ctx)
	if err != nil {
		return err
	}
	defer d.Close()

	all, err := d.Keys.ListDataKeys(ctx)
	if err != nil {
		return fmt.Errorf("list data keys: %w", err)
	}
	checks, err := d.Set.Check(ctx, all)
	if err != nil {
		return fmt.Errorf("verification stopped: %w", err)
	}
	rep := buildVerifyReport(d.Set, checks)
	if *format == "json" {
		if err := printJSON(rep); err != nil {
			return err
		}
	} else {
		printVerifyReport(rep)
	}
	if len(rep.Failed) > 0 {
		return fmt.Errorf("%d of %d data keys cannot be opened by this process", len(rep.Failed), rep.Checked)
	}
	return nil
}

func buildVerifyReport(set *secrets.KEKSet, checks []secrets.DataKeyCheck) verifyReport {
	rep := verifyReport{
		Checked: len(checks), Active: set.Active.Ref(),
		Previous: make([]string, 0, len(set.Previous)),
		Keys:     make([]keyCheck, 0, len(checks)), Failed: make([]keyCheck, 0),
	}
	for _, k := range set.Previous {
		rep.Previous = append(rep.Previous, k.Ref())
	}
	for _, c := range checks {
		res := keyCheck{
			KeyID: shortKey(c.Key.ID), Scope: c.Key.Scope, KEKRef: c.Key.KEKRef,
			Status: c.Key.Status, Active: c.Active, HeldBy: c.HeldBy,
		}
		if c.Active {
			rep.UnderActive++
		}
		if c.Err != nil {
			res.Error = c.Err.Error()
			rep.Failed = append(rep.Failed, res)
		}
		rep.Keys = append(rep.Keys, res)
	}
	return rep
}

func printVerifyReport(rep verifyReport) {
	fmt.Printf("checked %d data keys against %s\n", rep.Checked, rep.Active)
	for _, p := range rep.Previous {
		fmt.Printf("previous key %s may decrypt\n", p)
	}
	for _, k := range rep.Keys {
		under := "under the active key"
		if !k.Active {
			under = "under " + k.KEKRef
			if k.HeldBy != "" {
				under += " (" + k.HeldBy + ")"
			}
		}
		fmt.Printf("  %-44s %s %-12s %s\n", k.Scope, k.KeyID, k.Status, under)
	}
	for _, f := range rep.Failed {
		fmt.Printf("  %s (%s, %s) wrapped by %s: %s\n", f.KeyID, f.Scope, f.Status, f.KEKRef, f.Error)
	}
	if len(rep.Failed) == 0 {
		fmt.Println("every data key opens")
	}
	fmt.Printf("%d of %d data keys are under the active key\n", rep.UnderActive, rep.Checked)
	// Advice only when it is the next step. A key that does not open is a
	// configuration to fix first, and rotate-kek would stop on it.
	switch {
	case len(rep.Failed) > 0:
	case rep.UnderActive < rep.Checked:
		fmt.Println("run keys rotate-kek before removing a key from SUPERMCP_KEK_PREVIOUS")
	case len(rep.Previous) > 0:
		fmt.Println("the database no longer needs SUPERMCP_KEK_PREVIOUS; backups taken before the rotation still do")
	}
}

// keysDeps is what both subcommands need: the configured master keys and
// a key store that reads across every tenant.
type keysDeps struct {
	Log  *slog.Logger
	Set  *secrets.KEKSet
	Keys *store.KeyStore
	// DB is what the row walk uses. Data key rotation reads and writes
	// other packages' tables, which the key store has no business
	// knowing about.
	DB *tenant.DB

	store *store.Store
	// maint is the pool the scope lock is held on. A session lock needs a
	// connection of its own for as long as the rotation runs, which is
	// not something a transaction helper can hand out.
	maint *pgxpool.Pool
}

// Close releases the pools the command opened.
func (d keysDeps) Close() {
	if d.store != nil {
		d.store.Close()
	}
}

// keysSetup loads the configuration, resolves the master keys and opens
// the database. Key work spans every tenant, which is the maintenance
// pool's job, so the app role and its row policies are not involved.
//
// The master keys are resolved before the database is opened so a
// misconfigured provider fails immediately and leaves no connection
// behind.
func keysSetup(ctx context.Context) (keysDeps, error) {
	cfg, err := config.LoadOffline(version)
	if err != nil {
		return keysDeps{}, err
	}
	log := telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.Version)
	set, err := secrets.KEKFromEnv(ctx, os.Getenv)
	if err != nil {
		return keysDeps{}, err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL, cfg.MaintDatabaseURL, log, store.Options{})
	if err != nil {
		return keysDeps{}, err
	}
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
	return keysDeps{
		Log:   log,
		Set:   set,
		Keys:  &store.KeyStore{DB: db},
		DB:    db,
		store: st,
		maint: st.Maint,
	}, nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
