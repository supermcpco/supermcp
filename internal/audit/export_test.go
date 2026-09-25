package audit

import (
	"context"
	"time"
)

// WithRetry sets how a refused batch is retried, so a test does not wait
// out the production back-off.
func WithRetry(o Options, attempts int, base time.Duration) Options {
	o.retryAttempts = attempts
	o.retryBase = base
	return o
}

// ListSearchSQL is the statement List sends for a search, for the test
// that checks how Postgres runs it under the application role.
const ListSearchSQL = listSearchSQL

// PartitionBound is one monthly partition of audit_events.
type PartitionBound = partitionBound

// Ensure creates the monthly partitions from the month holding from
// through the one holding through, so a test can give an aged stream a
// month of its own.
func (p *Partitions) Ensure(ctx context.Context, from, through time.Time) (int, error) {
	return p.ensure(ctx, from, through)
}

// Bounds lists the monthly partitions, oldest first.
func (p *Partitions) Bounds(ctx context.Context) ([]PartitionBound, error) {
	return p.bounds(ctx)
}

// MonthsAheadOf is the arithmetic behind MonthsAhead.
func MonthsAheadOf(now time.Time, bounds []PartitionBound) int { return monthsAhead(now, bounds) }
