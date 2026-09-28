package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// --- tool calls ------------------------------------------------------------

// The tool-call list and its summary read tool_invocations, the row every
// call writes, under the workspace's row-level security role.

const (
	// toolCallsDefaultLimit is the page size when limit is left out.
	toolCallsDefaultLimit = 50
	// toolCallsMaxLimit is the largest page.
	toolCallsMaxLimit = 500
	// toolCallsQueryTimeout bounds a filtered list or a summary. A filter
	// that matches little of a large workspace (a tool name that is
	// nowhere, a status that is rare) walks the workspace's calls until
	// the page is full, and this is where that walk stops.
	toolCallsQueryTimeout = 10 * time.Second
	// pgQueryCanceled is the SQLSTATE of a statement stopped by
	// statement_timeout.
	pgQueryCanceled = "57014"
)

type toolCallsInput struct {
	Limit       int       `query:"limit" default:"50" maximum:"500" doc:"How many calls to return, newest first"`
	Since       time.Time `query:"since" doc:"Only calls made at or after this time (RFC 3339)"`
	Until       time.Time `query:"until" doc:"Only calls made before this time (RFC 3339)"`
	ConnectorID string    `query:"connectorId" maxLength:"128" doc:"Only calls to this connector"`
	ServerID    string    `query:"serverId" maxLength:"128" doc:"Only calls made through this MCP server. Needs servers:read"`
	Status      string    `query:"status" enum:"success,error,timeout,denied" doc:"Only calls with this outcome"`
	Q           string    `query:"q" maxLength:"200" doc:"Only calls whose tool name contains this text, ignoring case"`
}

// invocationDTO is one call. Its arguments and result are never part of
// it: they are what the data-loss policy governs, and a list is no place
// to show them.
type invocationDTO struct {
	ID            string    `json:"id"`
	ToolName      string    `json:"toolName" doc:"The tool's name at the time of the call"`
	ToolID        string    `json:"toolId,omitempty" doc:"The tool called; absent if the call recorded none"`
	ConnectorID   string    `json:"connectorId,omitempty" doc:"The connector the tool belongs to"`
	ServerID      string    `json:"serverId,omitempty" doc:"The MCP server the call came through; absent for a call through none, and when the caller lacks servers:read"`
	PrincipalKind string    `json:"principalKind" doc:"How the caller signed in: user, api_key, service_account or anonymous"`
	PrincipalID   string    `json:"principalId,omitempty" doc:"The user id for user and for api_key (the user who owns the key), the service account id for service_account. Absent for anonymous, and when the caller lacks org:read"`
	Status        string    `json:"status" enum:"success,error,timeout,denied"`
	DurationMS    int       `json:"durationMs"`
	Error         string    `json:"error,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}

type toolCallsSummaryInput struct {
	Since time.Time `query:"since" doc:"Start of the window (RFC 3339, inclusive). Defaults to seven days before until"`
	Until time.Time `query:"until" doc:"End of the window (RFC 3339, exclusive). Defaults to now"`
}

// toolCallStatusCounts has every status, so a client reads a zero rather
// than a missing key.
type toolCallStatusCounts struct {
	Success int64 `json:"success"`
	Error   int64 `json:"error"`
	Timeout int64 `json:"timeout"`
	Denied  int64 `json:"denied"`
}

type toolCallsSummary struct {
	Since    time.Time            `json:"since"`
	Until    time.Time            `json:"until"`
	Total    int64                `json:"total"`
	Failed   int64                `json:"failed" doc:"Calls whose status was not success: error, timeout or denied"`
	ByStatus toolCallStatusCounts `json:"byStatus"`
}

func (d Deps) invocationRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "invocations-list", Method: http.MethodGet, Path: "/api/v1/tool-calls",
		Summary: "List recent tool calls",
		Description: "Newest first. Every filter is optional and they combine. since and until are RFC 3339; " +
			"a since that is not before until is refused with 422. serverId needs servers:read, and without it the rows carry no serverId; " +
			"without org:read they carry no principalId. A filtered list draws on the analytics rate-limit budget and its per-workspace " +
			"limit of two running queries (a third is refused with 429), and one that runs longer than ten seconds is answered with 503.",
		Tags: []string{"observability"}, Security: sessionSecurity},
		func(ctx context.Context, in *toolCallsInput) (*struct {
			Body []invocationDTO `json:"body"`
		}, error) {
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if !in.Since.IsZero() && !in.Until.IsZero() && !in.Since.Before(in.Until) {
				return nil, huma.Error422UnprocessableEntity(fmt.Sprintf("since (%s) must be before until (%s)",
					in.Since.UTC().Format(time.RFC3339), in.Until.UTC().Format(time.RFC3339)))
			}
			// Filtering by server names a server, which the server list
			// shows only to servers:read, as the analytics' by=server does.
			if in.ServerID != "" {
				if _, err := d.require(ctx, authz.ServersRead, authz.Resource{}); err != nil {
					return nil, err
				}
			}
			seeServers, err := d.allowed(ctx, authz.ServersRead)
			if err != nil {
				return nil, err
			}
			seePrincipals, err := d.allowed(ctx, authz.OrgRead)
			if err != nil {
				return nil, err
			}
			f := toolCallFilter{
				Limit: in.Limit, Since: in.Since, Until: in.Until,
				ConnectorID: in.ConnectorID, ServerID: in.ServerID, Status: in.Status, Q: in.Q,
			}
			// The unfiltered list is the newest page of an index and costs
			// the same however large the workspace. A filtered one can walk
			// the workspace's calls for ten seconds, so it takes a slot as
			// the analytics do.
			if f.filtered() {
				if !d.analytics.acquire(p.OrgID) {
					return nil, errAnalyticsBusy()
				}
				defer d.analytics.release(p.OrgID)
			}
			list, err := d.listInvocations(ctx, p.OrgID, f)
			if err != nil {
				return nil, toolCallsErr(ctx, err)
			}
			for i := range list {
				if !seeServers {
					list[i].ServerID = ""
				}
				if !seePrincipals {
					list[i].PrincipalID = ""
				}
			}
			return &struct {
				Body []invocationDTO `json:"body"`
			}{Body: list}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "invocations-summary", Method: http.MethodGet, Path: "/api/v1/tool-calls/summary",
		Summary: "Count tool calls by outcome over a window",
		Description: "The window is at most 90 days; a wider or reversed one is refused with 422. " +
			"It draws on the analytics rate-limit budget and its per-workspace limit of two running queries; a third is refused with 429.",
		Tags: []string{"observability"}, Security: sessionSecurity},
		func(ctx context.Context, in *toolCallsSummaryInput) (*struct{ Body toolCallsSummary }, error) {
			p, err := d.require(ctx, authz.ConnectorsRead, authz.Resource{})
			if err != nil {
				return nil, err
			}
			since, until, err := toolCallWindow(time.Now(), in.Since, in.Until)
			if err != nil {
				return nil, huma.Error422UnprocessableEntity(err.Error())
			}
			if !d.analytics.acquire(p.OrgID) {
				return nil, errAnalyticsBusy()
			}
			defer d.analytics.release(p.OrgID)
			sum, err := d.summarizeInvocations(ctx, p.OrgID, since, until)
			if err != nil {
				return nil, toolCallsErr(ctx, err)
			}
			return &struct{ Body toolCallsSummary }{Body: sum}, nil
		})
}

// errAnalyticsBusy refuses a workspace's third aggregate or filtered
// search while two are running on this replica. It is built per request
// because huma may add to the error it is given.
func errAnalyticsBusy() error {
	return huma.Error429TooManyRequests("this workspace already has two searches or analytics queries running; try again when they finish")
}

// allowed reports whether the caller holds perm, without recording a
// refusal: a missing permission here narrows the answer, it does not
// refuse the request. An error is a decision that could not be made.
func (d Deps) allowed(ctx context.Context, perm authz.Permission) (bool, error) {
	err := d.Authz.Require(ctx, perm, authz.Resource{})
	if errors.Is(err, authz.ErrDenied) {
		return false, nil
	}
	return err == nil, err
}

// toolCallsErr answers a query stopped by its own time limit with 503
// and a way forward. Anything else is returned as it is, for a 500. ctx
// is the request's: when it is done, the query was stopped by the caller
// going away (clientGone, which answerClientGone answers) or by the
// router's limit on the whole request, and neither is this query's
// time limit.
func toolCallsErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return err
	}
	var pgErr *pgconn.PgError
	if (errors.As(err, &pgErr) && pgErr.Code == pgQueryCanceled) || errors.Is(err, context.DeadlineExceeded) {
		return huma.Error503ServiceUnavailable("the search took too long; narrow it with since and until, or a connector")
	}
	return err
}

// toolCallWindow applies the summary's defaults and bounds, the same as
// the usage analytics'. A zero time means the caller left it out.
func toolCallWindow(now, since, until time.Time) (time.Time, time.Time, error) {
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-usageDefaultWindow)
	}
	since, until = since.UTC(), until.UTC()
	if !since.Before(until) {
		return time.Time{}, time.Time{}, fmt.Errorf("since (%s) must be before until (%s)", since.Format(time.RFC3339), until.Format(time.RFC3339))
	}
	if until.Sub(since) > usageMaxWindow {
		return time.Time{}, time.Time{}, fmt.Errorf("the window is %s long; it can be at most 90 days", roundWindow(until.Sub(since)))
	}
	return since, until, nil
}

// toolCallFilter narrows the list. Zero fields do not filter.
type toolCallFilter struct {
	Limit        int
	Since, Until time.Time
	ConnectorID  string
	ServerID     string
	Status       string
	Q            string
}

func (f toolCallFilter) filtered() bool {
	return !f.Since.IsZero() || !f.Until.IsZero() || f.ConnectorID != "" || f.ServerID != "" || f.Status != "" || f.Q != ""
}

// toolCallsQuery builds the list's statement with a condition for each
// filter that is set, and none for those that are not. A single statement
// of "$n = ” OR column = $n" conditions would do the same, but once
// Postgres switches a prepared statement to its generic plan it plans for
// every filter at once and loses the connector index. Every value is a
// parameter; only the shape varies.
func toolCallsQuery(orgID string, f toolCallFilter) (string, []any) {
	limit := f.Limit
	if limit <= 0 || limit > toolCallsMaxLimit {
		limit = toolCallsDefaultLimit
	}
	var b strings.Builder
	b.WriteString(`SELECT id, tool_name, COALESCE(tool_id,''), COALESCE(connector_id,''), COALESCE(server_id,''),
			principal_kind, COALESCE(principal_id,''), status, duration_ms, COALESCE(error,''), created_at
		FROM tool_invocations WHERE organization_id = $1`)
	args := []any{orgID}
	cond := func(sql string, v any) {
		args = append(args, v)
		b.WriteString(" AND ")
		b.WriteString(strings.ReplaceAll(sql, "$?", "$"+strconv.Itoa(len(args))))
	}
	if !f.Since.IsZero() {
		cond("created_at >= $?", f.Since)
	}
	if !f.Until.IsZero() {
		cond("created_at < $?", f.Until)
	}
	if f.ConnectorID != "" {
		cond("connector_id = $?", f.ConnectorID)
	}
	if f.ServerID != "" {
		cond("server_id = $?", f.ServerID)
	}
	if f.Status != "" {
		cond("status = $?", f.Status)
	}
	if f.Q != "" {
		cond(`tool_name ILIKE '%' || $? || '%'`, likeEscape(f.Q))
	}
	args = append(args, limit)
	b.WriteString(" ORDER BY created_at DESC LIMIT $" + strconv.Itoa(len(args)))
	return b.String(), args
}

// likeEscape makes s match only itself inside a LIKE pattern, whose
// escape character is a backslash by default.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// listInvocations reads an organisation's tool calls, newest first.
func (d Deps) listInvocations(ctx context.Context, orgID string, f toolCallFilter) ([]invocationDTO, error) {
	sql, args := toolCallsQuery(orgID, f)
	out := []invocationDTO{}
	if f.filtered() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, toolCallsQueryTimeout)
		defer cancel()
	}
	err := d.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if f.filtered() {
			if err := setStatementTimeout(ctx, tx, toolCallsQueryTimeout); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("list tool calls: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var i invocationDTO
			if err := rows.Scan(&i.ID, &i.ToolName, &i.ToolID, &i.ConnectorID, &i.ServerID,
				&i.PrincipalKind, &i.PrincipalID, &i.Status, &i.DurationMS, &i.Error, &i.CreatedAt); err != nil {
				return fmt.Errorf("list tool calls: %w", err)
			}
			out = append(out, i)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("list tool calls: %w", err)
		}
		return nil
	})
	return out, err
}

// summarizeInvocations counts an organisation's calls in [since, until)
// by status. It reads only the (organization_id, created_at) covering
// index, which carries the status.
func (d Deps) summarizeInvocations(ctx context.Context, orgID string, since, until time.Time) (toolCallsSummary, error) {
	sum := toolCallsSummary{Since: since, Until: until}
	ctx, cancel := context.WithTimeout(ctx, toolCallsQueryTimeout)
	defer cancel()
	err := d.DB.Tx(tenant.WithOrg(ctx, orgID), func(tx pgx.Tx) error {
		if err := setStatementTimeout(ctx, tx, toolCallsQueryTimeout); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT status, count(*) FROM tool_invocations
			WHERE organization_id = $1 AND created_at >= $2 AND created_at < $3 GROUP BY status`, orgID, since, until)
		if err != nil {
			return fmt.Errorf("summarise tool calls: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var status string
			var n int64
			if err := rows.Scan(&status, &n); err != nil {
				return fmt.Errorf("summarise tool calls: %w", err)
			}
			switch status {
			case "success":
				sum.ByStatus.Success = n
			case "error":
				sum.ByStatus.Error = n
			case "timeout":
				sum.ByStatus.Timeout = n
			case "denied":
				sum.ByStatus.Denied = n
			}
			sum.Total += n
			if status != "success" {
				sum.Failed += n
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("summarise tool calls: %w", err)
		}
		return nil
	})
	if err != nil {
		return toolCallsSummary{}, err
	}
	return sum, nil
}

// setStatementTimeout makes Postgres stop the transaction's statements
// after d too, rather than finish work nobody will read once the context
// deadline has given up on it.
func setStatementTimeout(ctx context.Context, tx pgx.Tx, d time.Duration) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`, strconv.FormatInt(d.Milliseconds(), 10)); err != nil {
		return fmt.Errorf("statement timeout: %w", err)
	}
	return nil
}
