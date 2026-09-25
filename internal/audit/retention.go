package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// How long an organisation keeps its stream is its own decision, but not
// without limits. Below the floor the stream stops answering the questions
// it exists to answer — who had access last quarter, when did that key
// change — so a shorter window is raised to the floor rather than obeyed.

// retentionSetting is the org_settings key holding the window in days.
const retentionSetting = "audit.retention_days"

// Retention window bounds, in days.
const (
	DefaultRetentionDays = 365
	MinRetentionDays     = 90
	// MaxRetentionDays keeps the window inside what a time.Duration can
	// hold: a wrapped duration would put the cutoff in the future and
	// delete the whole stream.
	MaxRetentionDays = 36500
)

// Retention trims each organisation's events to its window.
type Retention struct {
	DB  *tenant.DB
	Log *slog.Logger
}

// RetentionSetting is one organisation's window: the number of days the
// sweep applies, and whether the organisation chose it or is on the
// default.
type RetentionSetting struct {
	Days       int
	Configured bool
}

// RetentionRangeError refuses a window outside the bounds. The sweep would
// clamp such a value anyway; refusing it at the door means what is stored
// is what is applied, and the person setting it is told why.
type RetentionRangeError struct {
	Days int
}

func (e *RetentionRangeError) Error() string {
	if e.Days < MinRetentionDays {
		return fmt.Sprintf("the audit trail must be kept for at least %d days, not %d: a shorter window "+
			"cannot answer who had access last quarter", MinRetentionDays, e.Days)
	}
	return fmt.Sprintf("the audit trail can be kept for at most %d days, not %d", MaxRetentionDays, e.Days)
}

// NewRetention builds the sweep.
func NewRetention(db *tenant.DB, log *slog.Logger) *Retention {
	return &Retention{DB: db, Log: log}
}

// Run applies retention in two steps, because one sequence is shared by
// every tenant and a hole in it cannot be bridged.
//
// First each organisation's own window is honoured by scrubbing: the
// events stay in the chain, their content does not. Then the whole stream
// is cut at the longest window any organisation still asks for, which is
// the only point where deleting rows leaves the chain verifiable. Rows
// under legal hold stop the cut where they sit.
//
// An instance-level event (one with no organisation) is never scrubbed,
// since no tenant owns a window for it; it is removed by the cut like
// everything else at that age.
func (r *Retention) Run(ctx context.Context) error {
	if r == nil || r.DB == nil {
		return nil
	}
	windows, err := r.windows(ctx)
	if err != nil {
		return err
	}
	reader := &Reader{DB: r.DB}
	var errs []error
	longest := time.Duration(0)
	now := time.Now()
	for _, w := range windows {
		if ctx.Err() != nil {
			return errors.Join(append(errs, ctx.Err())...)
		}
		if w.window > longest {
			longest = w.window
		}
		scrubbed, err := reader.Scrub(ctx, w.orgID, now.Add(-w.window))
		if err != nil {
			errs = append(errs, fmt.Errorf("scrub %s: %w", w.orgID, err))
			continue
		}
		if scrubbed > 0 {
			r.logger().Info("audit retention scrubbed event content",
				"org", w.orgID, "events", scrubbed, "days", int64(w.window/(24*time.Hour)))
		}
	}
	// Nothing is deleted until every organisation has given up on it.
	if longest > 0 {
		deleted, err := reader.Cut(ctx, now.Add(-longest))
		if err != nil {
			errs = append(errs, fmt.Errorf("cut: %w", err))
		} else if deleted > 0 {
			r.logger().Info("audit retention cut the stream",
				"deleted", deleted, "days", int64(longest/(24*time.Hour)))
		}
	}
	return errors.Join(errs...)
}

// Setting reads one organisation's window as the sweep would apply it.
func (r *Retention) Setting(ctx context.Context, orgID string) (RetentionSetting, error) {
	var raw []byte
	err := r.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value FROM org_settings WHERE organization_id = $1 AND key = $2`,
			orgID, retentionSetting).Scan(&raw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RetentionSetting{Days: DefaultRetentionDays}, nil
	}
	if err != nil {
		return RetentionSetting{}, fmt.Errorf("read retention for %s: %w", orgID, err)
	}
	return RetentionSetting{Days: windowDays(retentionWindow(raw)), Configured: true}, nil
}

// SetDays stores an organisation's window. A value outside the bounds is
// refused with a *RetentionRangeError rather than clamped.
func (r *Retention) SetDays(ctx context.Context, orgID string, days int) error {
	if days < MinRetentionDays || days > MaxRetentionDays {
		return &RetentionRangeError{Days: days}
	}
	value, err := json.Marshal(days)
	if err != nil {
		return fmt.Errorf("encode retention: %w", err)
	}
	err = r.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO org_settings (organization_id, key, value) VALUES ($1,$2,$3)
			ON CONFLICT (organization_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			orgID, retentionSetting, value)
		return err
	})
	if err != nil {
		return fmt.Errorf("store retention for %s: %w", orgID, err)
	}
	return nil
}

// InstanceCutDays is the age, in days, past which the sweep deletes rows:
// the longest window any organisation asks for. Events younger than that
// but outside an organisation's own window are scrubbed, not deleted. A
// legal hold keeps rows past it; this does not account for holds.
func (r *Retention) InstanceCutDays(ctx context.Context) (int, error) {
	windows, err := r.windows(ctx)
	if err != nil {
		return 0, fmt.Errorf("read retention windows: %w", err)
	}
	longest := time.Duration(0)
	for _, w := range windows {
		longest = max(longest, w.window)
	}
	return windowDays(longest), nil
}

type orgWindow struct {
	orgID  string
	window time.Duration
}

// windows reads every organisation and its window in one pass. The sweep
// visits every tenant anyway, so a settings lookup per organisation would
// be a query per row for nothing.
func (r *Retention) windows(ctx context.Context) ([]orgWindow, error) {
	var out []orgWindow
	err := r.DB.Bypass(ctx, "audit-retention", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT o.id, s.value
			FROM organizations o
			LEFT JOIN org_settings s ON s.organization_id = o.id AND s.key = $1
			ORDER BY o.id`, retentionSetting)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var raw []byte
			if err := rows.Scan(&id, &raw); err != nil {
				return err
			}
			out = append(out, orgWindow{orgID: id, window: retentionWindow(raw)})
		}
		return rows.Err()
	})
	return out, err
}

// retentionWindow reads the stored day count. A missing or malformed
// setting keeps more rather than less: too much history costs storage,
// too little costs an investigation that can no longer be run.
func retentionWindow(raw []byte) time.Duration {
	days := float64(DefaultRetentionDays)
	if len(raw) > 0 {
		var n float64
		if err := json.Unmarshal(raw, &n); err == nil {
			days = n
		}
	}
	switch {
	case days < MinRetentionDays:
		days = MinRetentionDays
	case days > MaxRetentionDays:
		days = MaxRetentionDays
	}
	return time.Duration(days) * 24 * time.Hour
}

func windowDays(d time.Duration) int {
	return int(d / (24 * time.Hour))
}

func (r *Retention) logger() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}
