package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// --- analytics -------------------------------------------------------------

// Usage over time, read from tool_invocations: the row every call writes,
// which is the only record that knows the organisation. The Prometheus
// series carry no organisation label and cannot answer per workspace.
//
// A call counts as an error when its status is anything but success:
// error, timeout, or denied.

const (
	// usageMaxWindow bounds what one request may aggregate.
	usageMaxWindow = 90 * 24 * time.Hour
	// usageDefaultWindow is the window when from is left out.
	usageDefaultWindow = 7 * 24 * time.Hour
	// usageHourlyUpTo is the widest window hourly buckets are chosen for
	// when the caller does not pick a bucket.
	usageHourlyUpTo = 48 * time.Hour
	// usageQueryTimeout bounds the two aggregate queries together.
	usageQueryTimeout = 15 * time.Second
)

type usageInput struct {
	From   time.Time `query:"from" doc:"Start of the window (RFC 3339, inclusive). Defaults to seven days before to"`
	To     time.Time `query:"to" doc:"End of the window (RFC 3339, exclusive). Defaults to now"`
	Bucket string    `query:"bucket" enum:"hour,day" doc:"Width of one point in the series, in UTC. Defaults to hour for a window of two days or less, day otherwise"`
	By     string    `query:"by" enum:"tool,connector,server" default:"tool" doc:"What the top list is broken down by"`
	Limit  int       `query:"limit" default:"10" minimum:"1" maximum:"50" doc:"How many entries the top list holds"`
}

// UsageStats is what is known about a set of calls. The percentiles are
// absent when there were no calls, and the upstream ones also when no
// call in the set reported an upstream time.
//
// It is exported only because huma merges the fields of an embedded
// struct into the OpenAPI schema when its type is exported, and skips
// them otherwise; the JSON is the same either way.
type UsageStats struct {
	Calls         int64    `json:"calls"`
	Errors        int64    `json:"errors" doc:"Calls whose status was not success: error, timeout or denied"`
	P50MS         *float64 `json:"p50Ms,omitempty" doc:"Median duration of a call, in milliseconds"`
	P95MS         *float64 `json:"p95Ms,omitempty" doc:"95th percentile duration of a call, in milliseconds"`
	UpstreamP50MS *float64 `json:"upstreamP50Ms,omitempty" doc:"Median time spent waiting on the upstream, in milliseconds"`
	UpstreamP95MS *float64 `json:"upstreamP95Ms,omitempty" doc:"95th percentile time spent waiting on the upstream, in milliseconds"`
}

// usagePoint is one bucket of the series. Buckets without calls are
// present with zero counts, so a chart needs no gap filling.
type usagePoint struct {
	Start time.Time `json:"start" doc:"Start of the bucket, in UTC"`
	UsageStats
}

// usageGroup is one entry of the top list.
type usageGroup struct {
	ID   string `json:"id" doc:"The tool, connector or server id; empty for calls that went through no server"`
	Name string `json:"name" doc:"Its current name, or its name at the time of the call if it is gone; empty if unknown"`
	UsageStats
}

type usageReport struct {
	From   time.Time    `json:"from"`
	To     time.Time    `json:"to"`
	Bucket string       `json:"bucket" enum:"hour,day"`
	By     string       `json:"by" enum:"tool,connector,server"`
	Totals UsageStats   `json:"totals" doc:"The whole window"`
	Series []usagePoint `json:"series" nullable:"false"`
	Top    []usageGroup `json:"top" nullable:"false" doc:"The busiest entries by call count over the whole window"`
}

type usageOutput struct {
	Body usageReport
}

func (d Deps) analyticsRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "analytics-usage", Method: http.MethodGet,
		Path: "/api/v1/analytics/usage", Summary: "Tool call volume, errors and latency over time",
		Description: "Aggregates this workspace's tool calls into a series of buckets and a top list. " +
			"The window is at most 90 days; a wider or reversed one is refused with 422.",
		Tags: []string{"observability"}, Security: sessionSecurity},
		func(ctx context.Context, in *usageInput) (*usageOutput, error) {
			// The same permission the tool-call list asks for: this is
			// that list, counted.
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			w, err := usageWindowFor(time.Now(), in.From, in.To, in.Bucket)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(err.Error())
			}
			by := in.By
			if by == "" {
				by = "tool"
			}
			limit := in.Limit
			if limit <= 0 {
				limit = 10
			}
			rep, err := usage(ctx, d.DB, p.OrgID, w, by, limit)
			if err != nil {
				return nil, err
			}
			return &usageOutput{Body: rep}, nil
		})
}

// usageWindow is a validated request window.
type usageWindow struct {
	From, To time.Time
	Bucket   string
}

// step is the width of one bucket. Buckets are cut in UTC, where a day
// is always 24 hours.
func (w usageWindow) step() time.Duration {
	if w.Bucket == "hour" {
		return time.Hour
	}
	return 24 * time.Hour
}

// usageWindowFor applies the defaults and bounds to what the caller
// asked for. A zero time means the caller left it out.
func usageWindowFor(now, from, to time.Time, bucket string) (usageWindow, error) {
	if to.IsZero() {
		to = now
	}
	if from.IsZero() {
		from = to.Add(-usageDefaultWindow)
	}
	from, to = from.UTC(), to.UTC()
	if !from.Before(to) {
		return usageWindow{}, fmt.Errorf("from (%s) must be before to (%s)", from.Format(time.RFC3339), to.Format(time.RFC3339))
	}
	if to.Sub(from) > usageMaxWindow {
		return usageWindow{}, fmt.Errorf("the window is %s long; it can be at most 90 days", roundWindow(to.Sub(from)))
	}
	if bucket == "" {
		bucket = "day"
		if to.Sub(from) <= usageHourlyUpTo {
			bucket = "hour"
		}
	}
	return usageWindow{From: from, To: to, Bucket: bucket}, nil
}

func roundWindow(d time.Duration) string {
	days := d.Hours() / 24
	if days == float64(int64(days)) {
		return fmt.Sprintf("%d days", int64(days))
	}
	return fmt.Sprintf("%.1f days", days)
}

// usageSeriesSQL is the series and the window's totals in one pass: the
// empty grouping set is the totals row, told apart by GROUPING().
const usageSeriesSQL = `
SELECT GROUPING(bucket) = 1 AS total, bucket,
       count(*) AS calls,
       count(*) FILTER (WHERE status <> 'success') AS errors,
       percentile_cont(0.5)  WITHIN GROUP (ORDER BY duration_ms) AS p50,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95,
       percentile_cont(0.5)  WITHIN GROUP (ORDER BY upstream_ms) AS up50,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY upstream_ms) AS up95
FROM (
    SELECT date_trunc($4::text, created_at, 'UTC') AS bucket, status, duration_ms, upstream_ms
    FROM tool_invocations
    WHERE organization_id = $1 AND created_at >= $2 AND created_at < $3
) calls
GROUP BY GROUPING SETS ((bucket), ())`

// usageTopSQL is the top list for one dimension. The names are looked up
// after the aggregate, so the join touches at most $5 rows. A tool is
// keyed by its id and falls back to the name it was called by, which is
// also its label once the tool has been deleted.
const usageTopSQL = `
WITH agg AS (
    SELECT CASE $4::text
               WHEN 'tool' THEN COALESCE(NULLIF(tool_id, ''), tool_name)
               WHEN 'connector' THEN connector_id
               ELSE server_id
           END AS key,
           max(tool_name) AS tool_name,
           count(*) AS calls,
           count(*) FILTER (WHERE status <> 'success') AS errors,
           percentile_cont(0.5)  WITHIN GROUP (ORDER BY duration_ms) AS p50,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95,
           percentile_cont(0.5)  WITHIN GROUP (ORDER BY upstream_ms) AS up50,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY upstream_ms) AS up95
    FROM tool_invocations
    WHERE organization_id = $1 AND created_at >= $2 AND created_at < $3
    GROUP BY 1
    ORDER BY calls DESC, key
    LIMIT $5
)
SELECT COALESCE(a.key, ''),
       COALESCE(CASE $4::text
                    WHEN 'tool' THEN COALESCE(t.name, a.tool_name)
                    WHEN 'connector' THEN c.name
                    ELSE s.name
                END, ''),
       a.calls, a.errors, a.p50, a.p95, a.up50, a.up95
FROM agg a
LEFT JOIN tools t ON $4::text = 'tool' AND t.id = a.key
LEFT JOIN connectors c ON $4::text = 'connector' AND c.id = a.key
LEFT JOIN mcp_servers s ON $4::text = 'server' AND s.id = a.key
ORDER BY a.calls DESC, a.key`

// usage reads the report for one organisation under its row-level
// security role. by and w.Bucket must already be validated: they are
// passed as parameters, but an unknown bucket is a query error.
func usage(ctx context.Context, db *tenant.DB, orgID string, w usageWindow, by string, limit int) (usageReport, error) {
	rep := usageReport{From: w.From, To: w.To, Bucket: w.Bucket, By: by, Series: []usagePoint{}, Top: []usageGroup{}}
	ctx, cancel := context.WithTimeout(ctx, usageQueryTimeout)
	defer cancel()
	byStart := map[int64]UsageStats{}
	err := db.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, usageSeriesSQL, orgID, w.From, w.To, w.Bucket)
		if err != nil {
			return fmt.Errorf("usage series: %w", err)
		}
		for rows.Next() {
			var total bool
			var start *time.Time
			var s UsageStats
			if err := rows.Scan(&total, &start, &s.Calls, &s.Errors, &s.P50MS, &s.P95MS, &s.UpstreamP50MS, &s.UpstreamP95MS); err != nil {
				rows.Close()
				return fmt.Errorf("usage series: %w", err)
			}
			if total {
				rep.Totals = s
			} else if start != nil {
				byStart[start.Unix()] = s
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("usage series: %w", err)
		}

		rows, err = tx.Query(ctx, usageTopSQL, orgID, w.From, w.To, by, limit)
		if err != nil {
			return fmt.Errorf("usage top: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var g usageGroup
			if err := rows.Scan(&g.ID, &g.Name, &g.Calls, &g.Errors, &g.P50MS, &g.P95MS, &g.UpstreamP50MS, &g.UpstreamP95MS); err != nil {
				return fmt.Errorf("usage top: %w", err)
			}
			rep.Top = append(rep.Top, g)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("usage top: %w", err)
		}
		return nil
	})
	if err != nil {
		return usageReport{}, err
	}
	rep.Series = fillSeries(w, byStart)
	return rep, nil
}

// fillSeries lays the buckets that had calls onto every bucket of the
// window, keyed by Unix second, so the series has no gaps. The first bucket starts at from cut
// down to the bucket width and may be partial, as may the last.
func fillSeries(w usageWindow, byStart map[int64]UsageStats) []usagePoint {
	step := w.step()
	first := w.From.Truncate(step)
	out := make([]usagePoint, 0, int(w.To.Sub(first)/step)+1)
	for t := first; t.Before(w.To); t = t.Add(step) {
		out = append(out, usagePoint{Start: t, UsageStats: byStart[t.Unix()]})
	}
	return out
}
