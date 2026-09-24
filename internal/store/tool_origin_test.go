package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// TestToolOriginBackfill applies the migrations up to 00018, seeds one
// catalog connector and one hand-made connector with a tool each, applies
// 00019, and checks that each tool got the source its connector implies.
func TestToolOriginBackfill(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	target := scratchDatabase(ctx, t, dsn, "tool_origin")

	st := open(ctx, t, target)
	db := stdlib.OpenDBFromPool(st.Maint)
	t.Cleanup(func() { _ = db.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 18); err != nil {
		t.Fatalf("migrate to 18: %v", err)
	}

	conn, err := pgx.Connect(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) }) //nolint:contextcheck // must close after ctx ends
	seed := []string{
		`INSERT INTO organizations (id, name, slug) VALUES ('org_1', 'Org', 'org')`,
		`INSERT INTO connectors (id, organization_id, name, transport, auth, catalog_slug)
		 VALUES ('con_cat', 'org_1', 'Catalog', '{"type":"http"}', '{"type":"none"}', 'bundesbank')`,
		`INSERT INTO connectors (id, organization_id, name, transport, auth)
		 VALUES ('con_imp', 'org_1', 'Imported', '{"type":"http"}', '{"type":"none"}')`,
		`INSERT INTO tools (id, connector_id, organization_id, name, definition)
		 VALUES ('tool_cat', 'con_cat', 'org_1', 'a', '{"name":"a"}'),
		        ('tool_imp', 'con_imp', 'org_1', 'b', '{"name":"b"}')`,
	}
	for _, q := range seed {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}

	if _, err := provider.UpTo(ctx, 19); err != nil {
		t.Fatalf("migrate to 19: %v", err)
	}

	cases := []struct {
		id, want string
	}{
		{"tool_cat", "catalog"},
		{"tool_imp", "import"},
	}
	for _, tc := range cases {
		var source string
		var editedAt *time.Time
		var editedBy *string
		if err := conn.QueryRow(ctx, `SELECT source, edited_at, edited_by FROM tools WHERE id = $1`, tc.id).Scan(&source, &editedAt, &editedBy); err != nil {
			t.Fatal(err)
		}
		if source != tc.want || editedAt != nil || editedBy != nil {
			t.Errorf("%s: source=%q editedAt=%v editedBy=%v, want source %q and no edit", tc.id, source, editedAt, editedBy, tc.want)
		}
	}
	if _, err := conn.Exec(ctx, `UPDATE tools SET source = 'other' WHERE id = 'tool_imp'`); err == nil {
		t.Error("the check constraint accepted an unknown source")
	}

	// Down removes the columns again.
	if _, err := provider.DownTo(ctx, 18); err != nil {
		t.Fatalf("migrate down to 18: %v", err)
	}
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'tools' AND column_name IN ('source', 'edited_at', 'edited_by')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d origin columns left after down", n)
	}
}
