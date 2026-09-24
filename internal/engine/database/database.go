// Package database executes database-transport tools: parameterised SQL
// over database/sql, JSON find specs over MongoDB, schema introspection,
// and static text. Read-only connectors accept only SELECT/WITH statements
// with no stacked statements and no data-modifying CTEs.
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/supermcpco/supermcp/internal/dbpool"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

const (
	// MaxQueryLength bounds an incoming statement.
	MaxQueryLength = 100_000
	// DefaultMaxRows caps result sets.
	DefaultMaxRows = 1000
)

// Engine is the database engine.
type Engine struct {
	Pools      *dbpool.Registry
	SQLiteRoot string
}

func (*Engine) Type() adapter.TransportType { return adapter.TransportDatabase }

// ErrNotReadOnly is returned for a write statement on a read-only connector.
var ErrNotReadOnly = errors.New("only SELECT queries are allowed (a leading WITH … SELECT CTE is also accepted); INSERT, UPDATE, DELETE, DROP and other write operations are blocked")

var (
	reStringLit = regexp.MustCompile(`'(?:[^']|'')*'|"(?:[^"]|"")*"`)
	reLineCmt   = regexp.MustCompile(`--[^\n]*`)
	reBlockCmt  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reWriteCTE  = regexp.MustCompile(`\(\s*(INSERT|UPDATE|DELETE|MERGE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\b`)
)

// ValidateReadOnly rejects any statement that is not a single read.
func ValidateReadOnly(stmt string) error {
	if len(stmt) > MaxQueryLength {
		return fmt.Errorf("statement exceeds %d characters", MaxQueryLength)
	}
	n := reBlockCmt.ReplaceAllString(stmt, " ")
	n = reLineCmt.ReplaceAllString(n, " ")
	n = reStringLit.ReplaceAllString(n, "''")
	n = strings.ToUpper(strings.TrimSpace(n))
	if !strings.HasPrefix(n, "SELECT") && !strings.HasPrefix(n, "WITH") {
		return ErrNotReadOnly
	}
	body := strings.TrimRight(n, "; \t\r\n")
	if strings.Contains(body, ";") {
		return errors.New("only a single SQL statement is allowed; stacked statements are blocked")
	}
	if m := reWriteCTE.FindStringSubmatch(n); m != nil {
		return fmt.Errorf("blocked SQL keyword in CTE: %s; only read-only queries are allowed", m[1])
	}
	return nil
}

// Execute runs the tool.
func (e *Engine) Execute(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	op := req.Tool.Operation
	c := req.Connector
	dialect := dbpool.Dialect(c.Driver)

	switch op.Kind {
	case "static":
		v, _ := op.Value.Value()
		return &engine.Response{Body: v, MediaType: "text/plain"}, nil
	case "sql", "schema":
	default:
		return nil, fmt.Errorf("database: %w: kind %q", engine.ErrUnsupported, op.Kind)
	}

	dsn, err := tmpl.RenderString(c.DSN, req.Vars, tmpl.Strict)
	if err != nil {
		return nil, fmt.Errorf("dsn: %w", err)
	}
	dsn = withCredentials(dsn, dialect, req.Vars.Auth)

	h, err := e.Pools.Acquire(ctx, dbpool.Spec{ConnectorID: c.ID, Dialect: dialect, DSN: dsn, ReadOnly: c.ReadOnly, SQLiteRoot: e.SQLiteRoot})
	if err != nil {
		return nil, err
	}
	maxRows := req.Limits.MaxRows
	if op.MaxRows > 0 {
		maxRows = op.MaxRows
	}
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}
	start := time.Now()
	var out *engine.Response
	switch {
	case dialect == dbpool.MongoDB && op.Kind == "schema":
		out, err = mongoSchema(ctx, h, dsn)
	case dialect == dbpool.MongoDB:
		out, err = mongoFind(ctx, h, dsn, op.Statement, req.Vars, maxRows)
	case op.Kind == "schema":
		out, err = sqlSchema(ctx, h, dialect)
	default:
		out, err = runSQL(ctx, h, dialect, op.Statement, req.Vars, c.ReadOnly, maxRows)
	}
	if err != nil {
		return nil, err
	}
	out.Meta.UpstreamDurationMS = time.Since(start).Milliseconds()
	return out, nil
}

// DryRun renders the statement and bound arguments.
func (e *Engine) DryRun(_ context.Context, req *engine.Request) (*engine.Preview, error) {
	op := req.Tool.Operation
	if op.Kind != "sql" {
		return &engine.Preview{SQL: op.Kind}, nil
	}
	// MongoDB's statement is a JSON document rather than SQL, and binding
	// its values as $1 would preview a query that is never run.
	if dbpool.Dialect(req.Connector.Driver) == dbpool.MongoDB {
		doc, err := renderMongo(op.Statement, req.Vars)
		if err != nil {
			return nil, err
		}
		return &engine.Preview{SQL: doc}, nil
	}
	stmt, args, err := tmpl.SQL(op.Statement, req.Vars, sqlDialect(dbpool.Dialect(req.Connector.Driver)))
	if err != nil {
		return nil, err
	}
	return &engine.Preview{SQL: stmt, Args: args}, nil
}

func sqlDialect(d dbpool.Dialect) tmpl.Dialect {
	switch d {
	case dbpool.MySQL:
		return tmpl.MySQL
	case dbpool.MSSQL:
		return tmpl.MSSQL
	case dbpool.Oracle:
		return tmpl.Oracle
	case dbpool.SQLite:
		return tmpl.SQLite
	default:
		return tmpl.Postgres
	}
}

// withCredentials splices auth username/password into a URL-style DSN.
func withCredentials(dsn string, dialect dbpool.Dialect, auth map[string]string) string {
	if auth == nil || (auth["username"] == "" && auth["password"] == "") || !strings.Contains(dsn, "://") {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	user := auth["username"]
	if d := auth["domain"]; d != "" && dialect == dbpool.MSSQL {
		user = d + `\` + user
	}
	u.User = url.UserPassword(user, auth["password"])
	return u.String()
}

func runSQL(ctx context.Context, h *dbpool.Handle, dialect dbpool.Dialect, tpl string, vars tmpl.Vars, readOnly bool, maxRows int) (*engine.Response, error) {
	stmt, args, err := tmpl.SQL(tpl, vars, sqlDialect(dialect))
	if err != nil {
		return nil, err
	}
	if readOnly {
		if err := ValidateReadOnly(stmt); err != nil {
			return nil, err
		}
	}
	if !readOnly && !looksLikeQuery(stmt) {
		res, err := h.SQL.ExecContext(ctx, stmt, args...)
		if err != nil {
			return nil, upstreamSQLError(err)
		}
		n, _ := res.RowsAffected()
		return &engine.Response{Body: map[string]any{"rowCount": n}, MediaType: "application/json", Meta: engine.Meta{RowCount: int(n)}}, nil
	}
	rows, err := h.SQL.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, upstreamSQLError(err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, 64)
	truncated := false
	for rows.Next() {
		if len(out) >= maxRows {
			truncated = true
			break
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			row[c] = normalise(vals[i])
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, upstreamSQLError(err)
	}
	body := any(out)
	if truncated {
		body = map[string]any{"rows": out, "_truncated": true, "_limit": maxRows}
	}
	return &engine.Response{Body: body, MediaType: "application/json", Meta: engine.Meta{RowCount: len(out), Truncated: truncated}}, nil
}

func looksLikeQuery(stmt string) bool {
	s := strings.ToUpper(strings.TrimSpace(stmt))
	return strings.HasPrefix(s, "SELECT") || strings.HasPrefix(s, "WITH") || strings.HasPrefix(s, "SHOW") || strings.HasPrefix(s, "EXPLAIN") || strings.HasPrefix(s, "DESCRIBE") || strings.HasPrefix(s, "PRAGMA")
}

func normalise(v any) any {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case time.Time:
		return x.Format(time.RFC3339Nano)
	default:
		return v
	}
}

func upstreamSQLError(err error) error {
	return &engine.UpstreamError{Status: 400, Body: err.Error(), Hint: err.Error()}
}

// sqlSchema lists tables via information_schema where available.
func sqlSchema(ctx context.Context, h *dbpool.Handle, dialect dbpool.Dialect) (*engine.Response, error) {
	var q string
	switch dialect {
	case dbpool.SQLite:
		q = "SELECT name AS table_name, type AS table_type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
	case dbpool.Oracle:
		q = "SELECT owner AS table_schema, table_name FROM all_tables WHERE owner NOT IN ('SYS','SYSTEM') ORDER BY owner, table_name"
	default:
		q = "SELECT table_schema, table_name, table_type FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema','mysql','performance_schema','sys') ORDER BY table_schema, table_name"
	}
	return runSQL(ctx, h, dialect, q, tmpl.Vars{}, false, DefaultMaxRows)
}

// ---------------------------------------------------------------------------
// MongoDB

type mongoSpec struct {
	Collection string         `json:"collection"`
	Filter     map[string]any `json:"filter"`
	Projection map[string]any `json:"projection"`
	Sort       map[string]any `json:"sort"`
	Limit      int            `json:"limit"`
}

// renderMongo substitutes into a JSON document statement. Params are
// JSON-encoded in place so {"collection": {{params.c}}} stays valid JSON.
func renderMongo(tpl string, vars tmpl.Vars) (string, error) {
	refs, err := tmpl.Refs(tpl)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	i := 0
	for _, r := range refs {
		at := strings.Index(tpl[i:], r.String()) + i
		sb.WriteString(tpl[i:at])
		i = at + len(r.String())
		v, ok, err := tmpl.Render(r.String(), vars, tmpl.Value)
		if err != nil {
			return "", err
		}
		if !ok {
			sb.WriteString("null")
			continue
		}
		if s, isStr := v.(string); isStr && strings.Contains(r.String(), "| raw") {
			sb.WriteString(s)
			continue
		}
		b, _ := json.Marshal(v)
		sb.Write(b)
	}
	sb.WriteString(tpl[i:])
	return sb.String(), nil
}

func mongoFind(ctx context.Context, h *dbpool.Handle, dsn, tpl string, vars tmpl.Vars, maxRows int) (*engine.Response, error) {
	doc, err := renderMongo(tpl, vars)
	if err != nil {
		return nil, err
	}

	var spec mongoSpec
	if err := json.Unmarshal([]byte(doc), &spec); err != nil {
		return nil, errors.New("MongoDB query must be a valid JSON object with at least a \"collection\" field")
	}
	if spec.Collection == "" {
		return nil, errors.New("MongoDB query must specify a \"collection\" field")
	}
	limit := spec.Limit
	if limit <= 0 || limit > maxRows {
		limit = maxRows
	}
	dbName, err := mongoDatabase(dsn)
	if err != nil {
		return nil, err
	}
	opts := options.Find().SetLimit(int64(limit))
	if spec.Projection != nil {
		opts.SetProjection(spec.Projection)
	}
	if spec.Sort != nil {
		opts.SetSort(spec.Sort)
	}
	filter := spec.Filter
	if filter == nil {
		filter = map[string]any{}
	}
	cur, err := h.Mongo.Database(dbName).Collection(spec.Collection).Find(ctx, filter, opts)
	if err != nil {
		return nil, upstreamSQLError(err)
	}
	defer func() { _ = cur.Close(ctx) }()
	var docs []map[string]any
	for cur.Next(ctx) {
		var d bson.M
		if err := cur.Decode(&d); err != nil {
			return nil, err
		}
		docs = append(docs, map[string]any(d))
	}
	if docs == nil {
		docs = []map[string]any{}
	}
	return &engine.Response{Body: docs, MediaType: "application/json", Meta: engine.Meta{RowCount: len(docs)}}, nil
}

func mongoSchema(ctx context.Context, h *dbpool.Handle, dsn string) (*engine.Response, error) {
	dbName, err := mongoDatabase(dsn)
	if err != nil {
		return nil, err
	}
	names, err := h.Mongo.Database(dbName).ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return nil, upstreamSQLError(err)
	}
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		var sample bson.M
		fields := []string{}
		if err := h.Mongo.Database(dbName).Collection(n).FindOne(ctx, bson.M{}).Decode(&sample); err == nil {
			for k := range sample {
				fields = append(fields, k)
			}
		}
		out = append(out, map[string]any{"collection": n, "sampleFields": fields})
	}
	return &engine.Response{Body: out, MediaType: "application/json"}, nil
}

func mongoDatabase(dsn string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	name := strings.Trim(u.Path, "/")
	if name == "" {
		return "", errors.New("MongoDB DSN must name a database (mongodb://host/<database>)")
	}
	return name, nil
}

var _ = sql.ErrNoRows
