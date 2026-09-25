// API key rotation is a property of rows in api_keys and of the locks taken
// on them, so it is tested against a live Postgres. Set DATABASE_URL to run
// it.
package mcpauth_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// rotateFixture is a migrated database, one org with one user, and a key
// service whose id generator a test can override.
type rotateFixture struct {
	db     *tenant.DB
	keys   *mcpauth.Keys
	orgID  string
	userID string

	mu       sync.Mutex
	forcedID string // when set, the next id minted is this one
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "t" + hex.EncodeToString(b)
}

func (f *rotateFixture) newID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forcedID != "" {
		id := f.forcedID
		f.forcedID = ""
		return id
	}
	return randomID()
}

func (f *rotateFixture) forceNextID(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forcedID = id
}

func newRotateFixture(t *testing.T) *rotateFixture {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set; API key rotation can only be tested against a live Postgres")
	}
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mst, err := store.Open(ctx, url, url, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := mst.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	mst.Close()
	st, err := store.Open(ctx, url, url, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	f := &rotateFixture{db: &tenant.DB{App: st.App, Maint: st.Maint, Log: log}}
	ids := identity.New(f.db, identity.Config{OpenRegistration: true}, authz.New(f.db), randomID)
	u, o, err := ids.Register(ctx, identity.RegisterInput{Email: randomID() + "@example.test", Name: "Rotate", Password: "correct horse battery 9"})
	if err != nil {
		t.Fatal(err)
	}
	f.orgID, f.userID = o.ID, u.ID
	f.keys = mcpauth.New(f.db, f.newID)
	return f
}

func (f *rotateFixture) create(t *testing.T, name string, ttl time.Duration) (*mcpauth.APIKey, string) {
	t.Helper()
	rec, secret, err := f.keys.Create(t.Context(), mcpauth.CreateInput{OrgID: f.orgID, PrincipalKind: "user", PrincipalID: f.userID, Name: name, TTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return rec, secret
}

func (f *rotateFixture) rotate(t *testing.T, id string, grace time.Duration) (*mcpauth.Rotation, error) {
	t.Helper()
	return f.keys.Rotate(t.Context(), mcpauth.RotateInput{OrgID: f.orgID, ID: id, ActorID: f.userID, Self: true, Grace: grace})
}

// expiry reads a key's stored expires_at.
func (f *rotateFixture) expiry(t *testing.T, id string) *time.Time {
	t.Helper()
	var at *time.Time
	err := f.db.Tx(tenant.WithOrg(t.Context(), f.orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT expires_at FROM api_keys WHERE id = $1`, id).Scan(&at)
	})
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func (f *rotateFixture) successors(t *testing.T, id string) int {
	t.Helper()
	var n int
	err := f.db.Tx(tenant.WithOrg(t.Context(), f.orgID), func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM api_keys WHERE rotated_from = $1`, id).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRotateGrace(t *testing.T) {
	f := newRotateFixture(t)

	tests := []struct {
		name  string
		ttl   time.Duration
		grace time.Duration
		// want is the old key's expiry relative to the rotation.
		want      time.Duration
		oldWorks  bool
		wantError error
	}{
		{name: "one hour grace", ttl: 0, grace: time.Hour, want: time.Hour, oldWorks: true},
		{name: "grace never extends an earlier expiry", ttl: 10 * time.Minute, grace: 24 * time.Hour, want: 10 * time.Minute, oldWorks: true},
		{name: "never-expiring key gets the grace", ttl: -1, grace: 2 * time.Hour, want: 2 * time.Hour, oldWorks: true},
		{name: "zero grace stops the old key now", ttl: 0, grace: 0, want: 0, oldWorks: false},
		{name: "maximum grace", ttl: 0, grace: mcpauth.MaxRotationGrace, want: mcpauth.MaxRotationGrace, oldWorks: true},
		{name: "negative grace", ttl: 0, grace: -time.Second, wantError: mcpauth.ErrGraceRange},
		{name: "grace over the cap", ttl: 0, grace: mcpauth.MaxRotationGrace + time.Second, wantError: mcpauth.ErrGraceRange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old, oldSecret := f.create(t, tt.name, tt.ttl)
			before := f.expiry(t, old.ID)
			start := time.Now()
			rot, err := f.rotate(t, old.ID, tt.grace)
			if tt.wantError != nil {
				if !errors.Is(err, tt.wantError) {
					t.Fatalf("rotate: got %v, want %v", err, tt.wantError)
				}
				if after := f.expiry(t, old.ID); !sameTime(before, after) {
					t.Errorf("refused rotation changed expiry: %v -> %v", before, after)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rot.Key.RotatedFrom != old.ID || rot.Key.Name != old.Name || rot.Secret == "" {
				t.Fatalf("replacement: %+v", rot.Key)
			}
			wantAt := start.Add(tt.want)
			if tt.ttl > 0 {
				wantAt = *old.ExpiresAt
			}
			if d := rot.PreviousExpiresAt.Sub(wantAt); d < -2*time.Second || d > 2*time.Second {
				t.Errorf("old key expires at %v, want about %v", rot.PreviousExpiresAt, wantAt)
			}
			if stored := f.expiry(t, old.ID); stored == nil || !stored.Equal(rot.PreviousExpiresAt) {
				t.Errorf("stored expiry %v, reported %v", stored, rot.PreviousExpiresAt)
			}
			_, err = f.keys.Authenticate(t.Context(), oldSecret, "")
			if tt.oldWorks && err != nil {
				t.Errorf("old key inside grace: %v", err)
			}
			if !tt.oldWorks && !errors.Is(err, mcpauth.ErrKeyExpired) {
				t.Errorf("old key after zero grace: %v", err)
			}
			if _, err := f.keys.Authenticate(t.Context(), rot.Secret, ""); err != nil {
				t.Errorf("new key: %v", err)
			}
		})
	}
}

// TestRotateAtomic forces the insert of the replacement to fail and checks
// the old key is left exactly as it was.
func TestRotateAtomic(t *testing.T) {
	f := newRotateFixture(t)
	other, _ := f.create(t, "collides", 0)
	old, oldSecret := f.create(t, "atomic", 0)
	before := f.expiry(t, old.ID)

	// The replacement is minted with an id that already exists, so its
	// INSERT hits the primary key after the old key has been shortened.
	f.forceNextID(other.ID)
	if _, err := f.rotate(t, old.ID, 0); err == nil {
		t.Fatal("rotation with a colliding id succeeded")
	}
	if after := f.expiry(t, old.ID); !sameTime(before, after) {
		t.Fatalf("old key expiry changed by a failed rotation: %v -> %v", before, after)
	}
	if n := f.successors(t, old.ID); n != 0 {
		t.Fatalf("failed rotation left %d replacements", n)
	}
	if _, err := f.keys.Authenticate(t.Context(), oldSecret, ""); err != nil {
		t.Fatalf("old key after failed rotation: %v", err)
	}
	// And the key can still be rotated once the fault is gone.
	if _, err := f.rotate(t, old.ID, time.Hour); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestRotateRefusals(t *testing.T) {
	f := newRotateFixture(t)
	ctx := t.Context()

	revoked, _ := f.create(t, "revoked", 0)
	if err := f.keys.Revoke(ctx, f.orgID, revoked.ID, f.userID, true, "test"); err != nil {
		t.Fatal(err)
	}
	expired, _ := f.create(t, "expired", 0)
	err := f.db.Tx(tenant.WithOrg(ctx, f.orgID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 minute' WHERE id = $1`, expired.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated, _ := f.create(t, "rotated", 0)
	if _, err := f.rotate(t, rotated.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Someone else's key, rotated with Self set, is indistinguishable
	// from a missing one.
	foreign, _, err := f.keys.Create(ctx, mcpauth.CreateInput{OrgID: f.orgID, PrincipalKind: "user", PrincipalID: randomID(), Name: "foreign"})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		id     string
		exists bool
		want   error
	}{
		{name: "revoked", id: revoked.ID, exists: true, want: mcpauth.ErrRotateRevoked},
		{name: "expired", id: expired.ID, exists: true, want: mcpauth.ErrRotateExpired},
		{name: "already rotated", id: rotated.ID, exists: true, want: mcpauth.ErrRotateTwice},
		{name: "unknown", id: randomID(), want: mcpauth.ErrKeyNotFound},
		{name: "another principal's", id: foreign.ID, exists: true, want: mcpauth.ErrKeyNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var before *time.Time
			if tt.exists {
				before = f.expiry(t, tt.id)
			}
			if _, err := f.rotate(t, tt.id, time.Hour); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if !tt.exists {
				return
			}
			if after := f.expiry(t, tt.id); !sameTime(before, after) {
				t.Errorf("refused rotation changed expiry: %v -> %v", before, after)
			}
			if n := f.successors(t, tt.id); !errors.Is(tt.want, mcpauth.ErrRotateTwice) && n != 0 {
				t.Errorf("refused rotation stored %d replacements", n)
			}
		})
	}
}

// TestRotateConcurrent races several rotations of one key: exactly one
// wins, the rest are told it was already rotated.
func TestRotateConcurrent(t *testing.T) {
	f := newRotateFixture(t)
	old, _ := f.create(t, "raced", 0)

	const racers = 8
	start := make(chan struct{})
	errs := make(chan error, racers)
	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.keys.Rotate(t.Context(), mcpauth.RotateInput{OrgID: f.orgID, ID: old.ID, ActorID: f.userID, Self: true, Grace: time.Hour})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	wins := 0
	for err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, mcpauth.ErrRotateTwice):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d rotations succeeded, want 1", wins)
	}
	if n := f.successors(t, old.ID); n != 1 {
		t.Fatalf("%d replacements stored, want 1", n)
	}
}

// sameTime compares two nullable timestamps.
func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
