package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Lag reports, for each destination kind with an enabled exporter, how
// long the oldest event any of them has yet to accept has been waiting:
// zero when every destination of that kind is caught up. It is the
// number an operator is actually asking about when a SIEM goes quiet,
// and it covers every reason at once — a receiver refusing, an exporter
// in back-off, a configuration that no longer opens, and a sweep that
// never got to run.
//
// It reads shared state, the cursors and the events after them, so every
// replica computes the same answer whichever of them ran the last sweep.
// The per-exporter lookup is the same one the sweep makes to find its
// next batch, cut to the first row, and the whole thing is one statement.
//
// The category filter is applied in SQL. A filter the sweep cannot parse
// is read by the sweep as "everything"; here a malformed one matches
// nothing and so reads as caught up. Both are the result of writing the
// row by hand, which the API does not allow.
func (e *Exporters) Lag(ctx context.Context) (map[string]time.Duration, error) {
	if e == nil || e.DB == nil {
		return nil, nil
	}
	out := make(map[string]time.Duration, len(Kinds))
	err := e.DB.Bypass(ctx, "audit-export-lag", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT x.kind, COALESCE(max(GREATEST(EXTRACT(EPOCH FROM now() - e.ts), 0)), 0)::float8
			FROM audit_exporters x
			LEFT JOIN LATERAL (
				SELECT ev.ts FROM audit_events ev
				WHERE ev.organization_id = x.organization_id AND ev.seq > x.cursor_seq
				  AND CASE WHEN jsonb_typeof(x.filter->'categories') = 'array' THEN
				        CASE WHEN jsonb_array_length(x.filter->'categories') > 0
				             THEN ev.category IN (SELECT jsonb_array_elements_text(x.filter->'categories'))
				             ELSE true END
				      ELSE true END
				ORDER BY ev.seq LIMIT 1
			) e ON true
			WHERE x.enabled AND x.kind = ANY($1)
			GROUP BY x.kind`, Kinds)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var kind string
			var seconds float64
			if err := rows.Scan(&kind, &seconds); err != nil {
				return err
			}
			out[kind] = time.Duration(seconds * float64(time.Second))
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("measure audit export lag: %w", err)
	}
	return out, nil
}
