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

func (r *Retention) logger() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}
