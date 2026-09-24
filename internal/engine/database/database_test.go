package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/supermcpco/supermcp/internal/dbpool"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

func TestValidateReadOnly(t *testing.T) {
	ok := []string{
		"SELECT 1", "  select * from t;", "WITH q AS (SELECT 1) SELECT * FROM q",
		"SELECT 'a;b' AS s, \"x;y\" FROM t -- INSERT here\n", "SELECT /* DROP */ 1",
		"SELECT * FROM t WHERE created_at > now()",
	}
	bad := []string{
		"INSERT INTO t VALUES (1)", "DELETE FROM t", "SELECT 1; DROP TABLE t",
		"WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x",
		"WITH x AS ( update t set a=1 ) SELECT 1", "UPDATE t SET a=1", "",
	}
	for _, s := range ok {
		if err := ValidateReadOnly(s); err != nil {
			t.Errorf("%q: unexpected %v", s, err)
		}
	}
	for _, s := range bad {
		if err := ValidateReadOnly(s); err == nil {
			t.Errorf("%q: expected rejection", s)
		}
	}
}

func sqliteEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "test.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, active INTEGER); INSERT INTO users VALUES (1,'ann',1),(2,'bob',0),(3,'cy',1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	return &Engine{Pools: dbpool.New(nil, 10), SQLiteRoot: root}, "sqlite://" + path
}

func req(dsn string, readOnly bool, kind, stmt string, params map[string]any) *engine.Request {
	return &engine.Request{
		Connector: &engine.Connector{ID: "c1", Type: adapter.TransportDatabase, Driver: "sqlite", DSN: dsn, ReadOnly: readOnly},
		Tool:      &adapter.Tool{Name: "t", Operation: adapter.Operation{Kind: kind, Statement: stmt}},
		Vars:      tmpl.Vars{Params: params},
	}
}

func TestSQLiteBoundParamsAndReadOnly(t *testing.T) {
	e, dsn := sqliteEngine(t)
	defer e.Pools.Close()
	ctx := context.Background()

	resp, err := e.Execute(ctx, req(dsn, true, "sql", "SELECT id, name FROM users WHERE active = {{params.active}} ORDER BY id", map[string]any{"active": float64(1)}))
	if err != nil {
		t.Fatal(err)
	}
	rows := resp.Body.([]map[string]any)
	if len(rows) != 2 || rows[0]["name"] != "ann" || rows[1]["name"] != "cy" {
		t.Fatalf("rows %#v", rows)
	}

	// Raw statement from the caller is validated when read-only.
	_, err = e.Execute(ctx, req(dsn, true, "sql", "{{params.query | raw}}", map[string]any{"query": "DELETE FROM users"}))
	if !errors.Is(err, ErrNotReadOnly) {
		t.Fatalf("expected read-only rejection, got %v", err)
	}
	// Injection through a bound param stays data.
	resp, err = e.Execute(ctx, req(dsn, true, "sql", "SELECT name FROM users WHERE name = {{params.n}}", map[string]any{"n": "ann' OR 1=1 --"}))
	if err != nil || len(resp.Body.([]map[string]any)) != 0 {
		t.Fatalf("injection not neutralised: %#v %v", resp, err)
	}
	// Row cap.
	r := req(dsn, true, "sql", "SELECT * FROM users", nil)
	r.Limits.MaxRows = 2
	resp, err = e.Execute(ctx, r)
	if err != nil || !resp.Meta.Truncated {
		t.Fatalf("expected truncation: %+v %v", resp, err)
	}
	// Schema introspection.
	resp, err = e.Execute(ctx, req(dsn, true, "schema", "", nil))
	if err != nil || resp.Body.([]map[string]any)[0]["table_name"] != "users" {
		t.Fatalf("schema %#v %v", resp, err)
	}
	// Writes allowed only when the connector is not read-only.
	resp, err = e.Execute(ctx, req(dsn, false, "sql", "UPDATE users SET active = 0 WHERE id = {{params.id}}", map[string]any{"id": float64(1)}))
	if err != nil || resp.Body.(map[string]any)["rowCount"] != int64(1) {
		t.Fatalf("write %#v %v", resp, err)
	}
	// Dry run binds without executing.
	p, err := e.DryRun(ctx, req(dsn, true, "sql", "SELECT * FROM t WHERE a = {{params.a}}", map[string]any{"a": "x"}))
	if err != nil || p.SQL != "SELECT * FROM t WHERE a = ?" || p.Args[0] != "x" {
		t.Fatalf("dry run %+v %v", p, err)
	}
}

func TestSQLiteConfinedToRoot(t *testing.T) {
	e := &Engine{Pools: dbpool.New(nil, 10), SQLiteRoot: t.TempDir()}
	outside := filepath.Join(os.TempDir(), "elsewhere.db")
	if _, err := e.Execute(context.Background(), req("sqlite://"+outside, true, "sql", "SELECT 1", nil)); err == nil {
		t.Fatal("expected path confinement error")
	}
	if _, err := e.Execute(context.Background(), req("sqlite://"+filepath.Join(e.SQLiteRoot, "../x.db"), true, "sql", "SELECT 1", nil)); err == nil {
		t.Fatal("expected traversal rejection")
	}
}
