package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/testdb"
)

// TestSessionRegistrationOpen checks what the anonymous session tells the
// sign-in screen. The harness runs in dev mode throughout, and dev mode
// must not open registration: with one user and open registration off,
// the answer is closed.
func TestSessionRegistrationOpen(t *testing.T) {
	for _, tc := range []struct {
		name   string
		closed bool
		// want is the answer with no users and then with one.
		want [2]bool
	}{
		{name: "open registration off", closed: true, want: [2]bool{true, false}},
		{name: "open registration on", closed: false, want: [2]bool{true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: tc.closed})
			if !h.deps.Config.Dev {
				t.Fatal("the harness is meant to run in dev mode")
			}
			for users := range 2 {
				if users == 1 {
					if _, _, err := h.deps.Identity.Register(context.Background(), identity.RegisterInput{
						Email: newID() + "@e2e.test", Password: "correct horse battery 9", OrgName: "First",
					}); err != nil {
						t.Fatalf("register the first user: %v", err)
					}
				}
				if got := h.anonymousRegistrationOpen(t); got != tc.want[users] {
					t.Errorf("with %d users, registrationOpen is %t, want %t", users, got, tc.want[users])
				}
				if got := h.deps.Identity.RegistrationOpen(context.Background()); got != tc.want[users] {
					t.Errorf("with %d users, RegistrationOpen is %t, want %t", users, got, tc.want[users])
				}
			}
		})
	}
}

// TestRegisterAgreesWithSession registers through the API after asking the
// session whether it may, with no users and with one, open registration
// off and on. Whatever the session says, register does, and a refusal is
// recorded as denied.
func TestRegisterAgreesWithSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		closed bool
	}{{"open registration off", true}, {"open registration on", false}} {
		closed := tc.closed
		t.Run(tc.name, func(t *testing.T) {
			h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: closed})
			// The first registration is always allowed, and it makes the
			// one user the second round runs with.
			for users := range 2 {
				want := users == 0 || !closed
				open := h.anonymousRegistrationOpen(t)
				if open != want {
					t.Errorf("with %d users, registrationOpen is %t, want %t", users, open, want)
				}
				h.cookie = ""
				var refusal apiError
				email := newID() + "@e2e.test"
				code := h.do(t, http.MethodPost, "/api/v1/auth/register", map[string]any{
					"email": email, "password": "correct horse battery 9", "orgName": "Agree",
				}, &refusal)
				switch {
				case open && code != http.StatusOK:
					t.Errorf("with %d users the session says open and register answers %d: %+v", users, code, refusal)
				case !open && code != http.StatusForbidden:
					t.Errorf("with %d users the session says closed and register answers %d", users, code)
				case !open && refusal.Detail != identity.RegistrationClosedMessage:
					t.Errorf("the refusal says %q, want %q", refusal.Detail, identity.RegistrationClosedMessage)
				}
				if !open {
					if got := registerOutcomes(t, h, email); !slices.Equal(got, []string{audit.Denied}) {
						t.Errorf("a refused sign-up left account.register outcomes %v, want [%s]", got, audit.Denied)
					}
				}
			}
		})
	}
}

// TestRegisterConcurrently fires sign-ups together at an unclaimed
// instance. With open registration off exactly one may claim it, however
// the others interleave with it; with it on, every one succeeds.
func TestRegisterConcurrently(t *testing.T) {
	const n = 8
	for _, tc := range []struct {
		name   string
		closed bool
		want   int // accounts afterwards
	}{
		{name: "open registration off", closed: true, want: 1},
		{name: "open registration on", closed: false, want: n},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: tc.closed})
			ctx := context.Background()
			errs := make([]error, n)
			ready := make(chan struct{})
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					<-ready
					_, _, errs[i] = h.deps.Identity.Register(ctx, identity.RegisterInput{
						Email: newID() + "@e2e.test", Password: "correct horse battery 9", OrgName: "Race",
					})
				})
			}
			close(ready)
			wg.Wait()

			var ok, closed int
			for i, err := range errs {
				switch {
				case err == nil:
					ok++
				case errors.Is(err, identity.ErrRegistrationClosed):
					closed++
				default:
					t.Errorf("registration %d: %v", i, err)
				}
			}
			if ok != tc.want || closed != n-tc.want {
				t.Errorf("%d registrations succeeded and %d were refused, want %d and %d", ok, closed, tc.want, n-tc.want)
			}
			var count int64
			if err := h.db.Pre(ctx, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, "SELECT auth_user_count()").Scan(&count)
			}); err != nil {
				t.Fatalf("count users: %v", err)
			}
			if count != int64(tc.want) {
				t.Errorf("auth_user_count() is %d, want %d", count, tc.want)
			}
		})
	}
}

// TestRegisterFunctionDecides calls auth_register the way each release
// does on a claimed instance. The current one refuses with SQLSTATE SM001
// when open registration is off, so the refusal does not rest on the
// check Register makes before it; the seven-argument form, which pods of
// the previous release call during a rolling upgrade, still works.
func TestRegisterFunctionDecides(t *testing.T) {
	h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: true})
	ctx := context.Background()
	if _, _, err := h.deps.Identity.Register(ctx, identity.RegisterInput{
		Email: newID() + "@e2e.test", Password: "correct horse battery 9", OrgName: "First",
	}); err != nil {
		t.Fatalf("register the first user: %v", err)
	}
	for _, tc := range []struct {
		name     string
		sql      string
		open     *bool
		wantCode string // "" for success
	}{
		{name: "closed", sql: "SELECT auth_register($1,$2,'',NULL,$3,$4,'Org',$5)", open: new(false), wantCode: "SM001"},
		{name: "open", sql: "SELECT auth_register($1,$2,'',NULL,$3,$4,'Org',$5)", open: new(true)},
		{name: "previous release", sql: "SELECT auth_register($1,$2,'',NULL,$3,$4,'Org')"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := newID()
			args := []any{id, id + "@e2e.test", newID(), "org-" + id}
			if tc.open != nil {
				args = append(args, *tc.open)
			}
			err := h.db.Pre(ctx, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, tc.sql, args...)
				return err
			})
			var pgErr *pgconn.PgError
			switch {
			case tc.wantCode == "" && err != nil:
				t.Errorf("auth_register: %v", err)
			case tc.wantCode != "" && (!errors.As(err, &pgErr) || pgErr.Code != tc.wantCode):
				t.Errorf("auth_register answered %v, want SQLSTATE %s", err, tc.wantCode)
			}
		})
	}
}

// registerOutcomes flushes the audit writer and returns the outcomes of
// the account.register events for email. A refused sign-up has no
// organisation, so its event is instance-level and read directly.
func registerOutcomes(t *testing.T, h *harness, email string) []string {
	t.Helper()
	ctx := context.Background()
	if err := h.deps.Audit.Flush(ctx); err != nil {
		t.Fatalf("waiting for the audit writer: %v", err)
	}
	rows, err := h.db.Maint.Query(ctx, `SELECT outcome FROM audit_events
		WHERE action = 'account.register' AND target_display = $1 ORDER BY seq`, email)
	if err != nil {
		t.Fatalf("reading the audit trail: %v", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("reading the audit trail: %v", err)
	}
	return out
}

// anonymousRegistrationOpen asks the session endpoint, without a cookie,
// whether registration is open.
func (h *harness) anonymousRegistrationOpen(t *testing.T) bool {
	t.Helper()
	h.cookie = ""
	var body struct {
		Anonymous        bool `json:"anonymous"`
		RegistrationOpen bool `json:"registrationOpen"`
	}
	if code := h.do(t, http.MethodGet, "/api/v1/auth/session", nil, &body); code != http.StatusOK {
		t.Fatalf("session: %d", code)
	}
	if !body.Anonymous {
		t.Fatal("the session is not anonymous")
	}
	return body.RegistrationOpen
}

// unclaimedDatabase makes a migrated database with no users beside the one
// DATABASE_URL names, and drops it when the test ends. The name is unique
// to the run, so nothing else counts users in it.
func unclaimedDatabase(t *testing.T) string {
	t.Helper()
	base := os.Getenv("DATABASE_URL")
	if base == "" {
		t.Skip("DATABASE_URL not set")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := fmt.Sprintf("supermcp_e2e_unclaimed_%d_%s", os.Getpid(), hex.EncodeToString(b))
	// Registered before the database exists, so a failure half-way
	// through creating it still cleans up. Not the test's context: it is
	// done by the time cleanups run, and a leaked database outlives the run.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		u, err := url.Parse(base)
		if err != nil {
			return
		}
		u.Path = "/postgres"
		conn, err := pgx.Connect(ctx, u.String())
		if err != nil {
			t.Logf("drop %s: %v", name, err)
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
			t.Logf("drop %s: %v", name, err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return testdb.Own(ctx, t, base, name)
}
