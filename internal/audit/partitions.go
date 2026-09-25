package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// audit_events is partitioned by UTC calendar month on ts (migration
// 00033). An event whose month has no partition is not refused: it lands in
// audit_events_default, and creating the month's partition later moves it
// there. But retention can only drop a month that has a partition of its
// own, and the default partition is scanned every time a month is added,
// so the months are created ahead of the clock.

// PartitionsAhead is how many months after the current one Maintain keeps
// partitioned.
const PartitionsAhead = 3

const (
	// maintainTimeout bounds one maintenance run. Creating a month is
	// quick; moving rows out of the default partition is what could take
	// longer, and there should be none.
	maintainTimeout = time.Minute
	// maintainLockTimeout bounds each wait for a lock. Attaching a month
	// takes SHARE UPDATE EXCLUSIVE on audit_events, which appends and reads
	// do not conflict with, but also ACCESS EXCLUSIVE on
	// audit_events_default while it checks that table holds nothing for
	// the month; a query that cannot rule the default partition out (a
	// read not bounded by time) queues behind that for as long as the
	// attach waits. Analyzing takes SHARE UPDATE EXCLUSIVE too. The next
	// run is an hour away, so waiting long is never worth it.
	maintainLockTimeout = "3s"
	// analyzeEvery is how often Maintain analyzes audit_events. Analyzing
	// it samples every partition and computes the search index's
	// expression for each sampled row, which took 25 seconds over a
	// million events in 17 months; hourly would be most of the job's work
	// for statistics that move slowly.
	analyzeEvery = 24 * time.Hour
	// analyzeTimeout bounds one analyze, which grows with the months kept.
	analyzeTimeout = 10 * time.Minute
)

// Partitions keeps audit_events partitioned ahead of the clock.
type Partitions struct {
	DB *tenant.DB
	// Now is the clock the months are counted from; time.Now when nil.
	Now func() time.Time
}

// NewPartitions builds the maintenance job.
func NewPartitions(db *tenant.DB) *Partitions {
	return &Partitions{DB: db}
}

func (p *Partitions) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

// Maintain creates the partitions for the current month and the
// PartitionsAhead months after it that do not exist yet, and reports how
// many it created. Running it again creates nothing.
//
// It then analyzes audit_events if that was last done more than
// analyzeEvery ago. Autovacuum analyzes each partition but never the
// partitioned table itself, and the planner reads the parent's statistics
// for anything that spans months. When it was last done is Postgres's own
// record, so it holds whichever replica runs the job.
func (p *Partitions) Maintain(ctx context.Context) (int, error) {
	month := monthOf(p.now())
	created, err := p.ensure(ctx, month, month.AddDate(0, PartitionsAhead, 0))
	if err != nil {
		return 0, err
	}
	return created, p.analyze(ctx)
}

// analyze refreshes the statistics of audit_events and its partitions
// when they are older than analyzeEvery.
func (p *Partitions) analyze(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, analyzeTimeout)
	defer cancel()
	err := p.DB.Bypass(ctx, "audit-partition-analyze", func(tx pgx.Tx) error {
		var due bool
		if err := tx.QueryRow(ctx, `SELECT COALESCE(
				pg_stat_get_last_analyze_time('public.audit_events'::regclass) < now() - $1::interval, true)`,
			analyzeEvery.String()).Scan(&due); err != nil {
			return err
		}
		if !due {
			return nil
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, maintainLockTimeout); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `ANALYZE audit_events`)
		return err
	})
	if err != nil {
		return fmt.Errorf("analyze audit_events: %w", err)
	}
	return nil
}

// ensure creates the partitions for every month from the one holding from
// through the one holding through that do not exist yet, and reports how
// many it created. Events already in the default partition for those
// months are moved into them.
func (p *Partitions) ensure(ctx context.Context, from, through time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, maintainTimeout)
	defer cancel()
	var created int
	err := p.DB.Bypass(ctx, "audit-partition-maint", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, maintainLockTimeout); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT audit_partition_ensure('public.audit_events'::regclass, $1, $2)`,
			from, through).Scan(&created)
	})
	if err != nil {
		return 0, fmt.Errorf("create audit partitions: %w", err)
	}
	return created, nil
}

// partitionBound is one monthly partition of audit_events.
type partitionBound struct {
	Name     string
	From, To time.Time
}

// bounds lists the monthly partitions of audit_events, oldest first. The
// default partition is not among them.
func (p *Partitions) bounds(ctx context.Context) ([]partitionBound, error) {
	var out []partitionBound
	err := p.DB.Bypass(ctx, "audit-partition-bounds", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT partition::text, lower_bound, upper_bound
			FROM audit_partition_bounds('public.audit_events'::regclass)
			WHERE lower_bound IS NOT NULL ORDER BY lower_bound`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b partitionBound
			if err := rows.Scan(&b.Name, &b.From, &b.To); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list audit partitions: %w", err)
	}
	return out, nil
}

// MonthsAhead reports how many whole months after the current one
// audit_events has partitions for without a gap: PartitionsAhead after
// Maintain, 0 when only the current month has one, and -1 when not even
// the current month has.
func (p *Partitions) MonthsAhead(ctx context.Context) (int, error) {
	bounds, err := p.bounds(ctx)
	if err != nil {
		return 0, err
	}
	return monthsAhead(p.now(), bounds), nil
}

// monthsAhead walks bounds, oldest first, from the start of now's month
// for as long as each partition starts where the last one ended.
func monthsAhead(now time.Time, bounds []partitionBound) int {
	at := monthOf(now)
	covered := -1
	for _, b := range bounds {
		switch {
		case !b.To.After(at):
			continue
		case b.From.Equal(at):
			covered++
			at = b.To
		default:
			return covered
		}
	}
	return covered
}

// monthOf is the start of t's UTC calendar month.
func monthOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}
