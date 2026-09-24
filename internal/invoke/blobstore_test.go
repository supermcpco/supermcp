package invoke_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/invoke"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// blobDB opens the app and maintenance pools and makes two workspaces for
// the test to store under.
func blobDB(t *testing.T) (*tenant.DB, string, string) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	maint, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	maint.Close()
	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	orgA, orgB := "blob_a_"+suffix, "blob_b_"+suffix
	if err := db.Bypass(ctx, "blob test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1), ($2,$2,$2)`, orgA, orgB)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Bypass(context.WithoutCancel(ctx), "blob test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.WithoutCancel(ctx), `DELETE FROM organizations WHERE id IN ($1,$2)`, orgA, orgB)
			return err
		})
	})
	return db, orgA, orgB
}

// TestPostgresBlobStoreIsShared is the reason the store exists: a link
// written by one replica is collected from another.
func TestPostgresBlobStoreIsShared(t *testing.T) {
	db, orgA, orgB := blobDB(t)
	ctx := t.Context()
	writer := &invoke.PostgresBlobStore{DB: db, BaseURL: "https://mcp.example/"}
	reader := &invoke.PostgresBlobStore{DB: db}

	owner := invoke.BlobOwner{OrgID: orgA, PrincipalID: "u1"}
	data := bytes.Repeat([]byte{0xff, 0x00}, 1<<16)
	ref, err := writer.Put(ctx, invoke.Blob{Owner: owner, MediaType: "image/png", Name: "chart.png", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://mcp.example/api/v1/blobs/" + ref.ID; ref.URL != want {
		t.Fatalf("url %q, want %q", ref.URL, want)
	}

	got, ok, err := reader.Get(ctx, ref.ID, owner)
	if err != nil || !ok {
		t.Fatalf("another replica could not collect the blob: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got.Data, data) || got.MediaType != "image/png" || got.Name != "chart.png" {
		t.Fatalf("the blob came back changed: %d bytes, %q, %q", len(got.Data), got.MediaType, got.Name)
	}

	for name, other := range map[string]invoke.BlobOwner{
		"another person in the workspace":  {OrgID: orgA, PrincipalID: "u2"},
		"the same id in another workspace": {OrgID: orgB, PrincipalID: "u1"},
		"nobody":                           {},
	} {
		if _, ok, err := reader.Get(ctx, ref.ID, other); ok || err != nil {
			t.Errorf("%s collected the blob (ok=%v err=%v)", name, ok, err)
		}
	}
	if _, err := writer.Put(ctx, invoke.Blob{Data: data}); err == nil {
		t.Error("a blob with no owner was stored")
	}
}

func TestPostgresBlobStoreExpiresAndSweeps(t *testing.T) {
	db, orgA, _ := blobDB(t)
	ctx := t.Context()
	now := time.Now()
	s := &invoke.PostgresBlobStore{DB: db, TTL: time.Minute, Now: func() time.Time { return now }}
	owner := invoke.BlobOwner{OrgID: orgA, PrincipalID: "u1"}
	ref, err := s.Put(ctx, invoke.Blob{Owner: owner, MediaType: "application/pdf", Data: []byte("%PDF")})
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Minute)
	if _, ok, _ := s.Get(ctx, ref.ID, owner); ok {
		t.Fatal("an expired blob was still collected")
	}
	if n, err := s.Sweep(ctx); err != nil || n < 1 {
		t.Fatalf("the sweep removed %d rows (%v), want the expired blob", n, err)
	}
}

// failingStore stands in for a Redis that has gone away.
type failingStore struct{}

func (failingStore) Put(context.Context, invoke.Blob) (invoke.BlobRef, error) {
	return invoke.BlobRef{}, errors.New("connection refused")
}

func (failingStore) Get(context.Context, string, invoke.BlobOwner) (invoke.Blob, bool, error) {
	return invoke.Blob{}, false, errors.New("connection refused")
}

func TestFallbackBlobStoreSurvivesItsPrimary(t *testing.T) {
	secondary := invoke.NewMemoryBlobStore(invoke.BlobOptions{})
	s := &invoke.FallbackBlobStore{Primary: failingStore{}, Secondary: secondary}
	owner := invoke.BlobOwner{OrgID: "o", PrincipalID: "p"}

	ref, err := s.Put(t.Context(), invoke.Blob{Owner: owner, MediaType: "image/png", Data: []byte{1}})
	if err != nil {
		t.Fatalf("the fallback did not take the write: %v", err)
	}
	if _, ok, err := s.Get(t.Context(), ref.ID, owner); !ok || err != nil {
		t.Fatalf("a blob written to the fallback was not found through it: ok=%v err=%v", ok, err)
	}
	// A blob that lived only in the unreachable primary is not found, not
	// an error: the route answers it with a 404 rather than a 500.
	if _, ok, err := s.Get(t.Context(), "missing", owner); ok || err != nil {
		t.Fatalf("a blob in neither store: ok=%v err=%v, want a plain not-found", ok, err)
	}
}

func TestRedisBlobStoreIsShared(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	writer, err := invoke.NewRedisBlobStore(url, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := invoke.NewRedisBlobStore(url, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	owner := invoke.BlobOwner{OrgID: "o", PrincipalID: "p"}
	data := bytes.Repeat([]byte{0, 1, 2, 0xff}, 1<<16)
	ref, err := writer.Put(t.Context(), invoke.Blob{Owner: owner, MediaType: "image/png", Name: "x.png", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := reader.Get(t.Context(), ref.ID, owner)
	if err != nil || !ok || !bytes.Equal(got.Data, data) || got.MediaType != "image/png" {
		t.Fatalf("another replica could not collect the blob intact: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := reader.Get(t.Context(), ref.ID, invoke.BlobOwner{OrgID: "o", PrincipalID: "q"}); ok {
		t.Fatal("another person collected the blob")
	}
}
