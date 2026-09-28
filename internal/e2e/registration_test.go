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
	"strings"
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
// check Register makes before it; the eight- and seven-argument forms,
// which pods of earlier releases call during a rolling upgrade, still
// work, and the eight-argument one still refuses.
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
		binding  bool           // pass a binding id, as the current form takes
		iso      pgx.TxIsoLevel // "" is the server's default, READ COMMITTED
		wantCode string         // "" for success
	}{
		{name: "closed", sql: registerSQL, open: new(false), binding: true, wantCode: pgRegistrationClosed},
		{name: "open", sql: registerSQL, open: new(true), binding: true},
		{name: "previous release closed", sql: registerPreviousSQL, open: new(false), wantCode: pgRegistrationClosed},
		{name: "previous release open", sql: registerPreviousSQL, open: new(true)},
		{name: "release before", sql: "SELECT auth_register($1,$2,'',NULL,$3,$4,'Org')"},
		// The lock only works under READ COMMITTED, so anything else is
		// refused rather than left to race; an open instance takes no lock.
		{name: "closed under repeatable read", sql: registerSQL, open: new(false), binding: true, iso: pgx.RepeatableRead, wantCode: "P0001"},
		{name: "closed under serializable", sql: registerSQL, open: new(false), binding: true, iso: pgx.Serializable, wantCode: "P0001"},
		{name: "open under repeatable read", sql: registerSQL, open: new(true), binding: true, iso: pgx.RepeatableRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := newID()
			args := []any{id, id + "@e2e.test", newID(), "org-" + id}
			if tc.open != nil {
				args = append(args, *tc.open)
			}
			if tc.binding {
				args = append(args, newID())
			}
			err := pgx.BeginTxFunc(ctx, h.db.App, pgx.TxOptions{IsoLevel: tc.iso}, func(tx pgx.Tx) error {
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

// registerSQL calls the current auth_register with $1 the user id, $2 the
// email, $3 the organisation id, $4 its slug, $5 whether open
// registration is on and $6 the owner binding's id.
const registerSQL = "SELECT auth_register($1,$2,'',NULL,$3,$4,'Org',$5,$6)"

// registerPreviousSQL is the eight-argument auth_register of migration
// 00035, which pods of the previous release call: registerSQL without $6.
const registerPreviousSQL = "SELECT auth_register($1,$2,'',NULL,$3,$4,'Org',$5)"

const (
	// pgRegistrationClosed is the SQLSTATE auth_register refuses with.
	pgRegistrationClosed = "SM001"
	// pgForeignKeyViolation is what a binding to a missing role raises.
	pgForeignKeyViolation = "23503"
	// pgLockNotAvailable is what running out of lock_timeout raises.
	pgLockNotAvailable = "55P03"
	// registerLockClass is the advisory lock class auth_register takes
	// (migration 00035), with 0 as the second key.
	registerLockClass = 0x5247
)

// registerArgs are registerSQL's arguments for a fresh user.
func registerArgs(open bool) []any {
	id := newID()
	return []any{id, id + "@e2e.test", newID(), "org-" + id, open, newID()}
}

// TestRegisterWaitsForTheLock orders two closed registrations on an
// unclaimed instance by hand: the first holds its transaction open, the
// second is seen waiting on the lock, the first commits, and the second
// is refused. Nothing depends on how the scheduler happens to interleave
// them.
func TestRegisterWaitsForTheLock(t *testing.T) {
	h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: true})
	ctx := context.Background()

	first, err := h.db.App.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Rollback(ctx) }()
	if _, err := first.Exec(ctx, registerSQL, registerArgs(false)...); err != nil {
		t.Fatalf("the first registration: %v", err)
	}

	// Owned by this test; it ends when the second call returns, which the
	// commit below or lock_timeout guarantees.
	second := make(chan error, 1)
	go func() {
		second <- h.db.Pre(ctx, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, registerSQL, registerArgs(false)...)
			return err
		})
	}()
	waitForRegisterWaiter(t, h, second)

	if err := first.Commit(ctx); err != nil {
		t.Fatalf("commit the first registration: %v", err)
	}
	err = <-second
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgRegistrationClosed {
		t.Errorf("the second registration answered %v, want SQLSTATE %s", err, pgRegistrationClosed)
	}
}

// waitForRegisterWaiter returns once a session in h's database is waiting
// for the registration lock. It fails the test if the waiter finishes
// first or none shows up.
func waitForRegisterWaiter(t *testing.T, h *harness, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := h.db.Maint.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks
			WHERE locktype = 'advisory' AND NOT granted AND classid = $1 AND objid = 0 AND objsubid = 2
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database()))`,
			registerLockClass).Scan(&waiting); err != nil {
			t.Fatalf("reading pg_locks: %v", err)
		}
		if waiting {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("the second registration returned without waiting for the lock: %v", err)
		case <-ctx.Done():
			t.Fatal("the second registration never waited for the lock")
		case <-tick.C:
		}
	}
}

// TestRegisterLockTimeout holds the registration lock. A closed
// registration gives up after auth_register's lock_timeout with an error
// that is not a refusal, and an open one does not wait at all.
func TestRegisterLockTimeout(t *testing.T) {
	h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: true})
	ctx := context.Background()

	holder, err := h.db.Maint.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_xact_lock($1, 0)", registerLockClass); err != nil {
		t.Fatalf("take the registration lock: %v", err)
	}

	_, _, err = h.deps.Identity.Register(ctx, identity.RegisterInput{
		Email: newID() + "@e2e.test", Password: "correct horse battery 9", OrgName: "Held",
	})
	if errors.Is(err, identity.ErrRegistrationClosed) {
		t.Errorf("a registration that timed out on the lock was refused as closed")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgLockNotAvailable {
		t.Errorf("a registration behind a held lock answered %v, want SQLSTATE %s", err, pgLockNotAvailable)
	}

	// Well under lock_timeout: an open registration that waited would
	// fail here rather than succeed late.
	openCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := h.db.Pre(openCtx, func(tx pgx.Tx) error {
		_, err := tx.Exec(openCtx, registerSQL, registerArgs(true)...)
		return err
	}); err != nil {
		t.Errorf("an open registration behind a held lock: %v", err)
	}
}

// TestRegisterWritesEverythingTogether registers on an unclaimed instance
// and reads, in one statement and so one snapshot, what registration
// leaves: one user, one organisation with them as its member, their
// password in the history, and them bound to the owner role.
func TestRegisterWritesEverythingTogether(t *testing.T) {
	h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: true})
	ctx := context.Background()
	u, o, err := h.deps.Identity.Register(ctx, identity.RegisterInput{
		Email: newID() + "@e2e.test", Password: "correct horse battery 9", OrgName: "Together",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var users, orgs, members, history, bindings, owner int64
	if err := h.db.Maint.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM users),
			(SELECT count(*) FROM organizations),
			(SELECT count(*) FROM organization_members WHERE user_id = $1 AND organization_id = $2),
			(SELECT count(*) FROM password_history p JOIN users u ON u.id = p.user_id
			  WHERE p.user_id = $1 AND p.hash = u.password_hash),
			(SELECT count(*) FROM role_bindings),
			(SELECT count(*) FROM role_bindings WHERE organization_id = $2 AND principal_kind = 'user'
			  AND principal_id = $1 AND role_id = 'role_owner' AND scope_kind = 'org' AND created_by = $1)`,
		u.ID, o.ID).Scan(&users, &orgs, &members, &history, &bindings, &owner); err != nil {
		t.Fatalf("read what registration wrote: %v", err)
	}
	for _, c := range []struct {
		what string
		got  int64
	}{
		{"users", users}, {"organisations", orgs}, {"memberships", members},
		{"password history rows", history}, {"role bindings", bindings}, {"owner bindings", owner},
	} {
		if c.got != 1 {
			t.Errorf("registration left %d %s, want 1", c.got, c.what)
		}
	}
}

// TestRegisterFailsWhole makes the owner binding fail by removing the
// owner role from this test's database. The registration fails, leaves no
// user and no organisation behind, and the instance is still unclaimed,
// so the person can try again once the fault is fixed. Before migration
// 00037 the user and organisation stayed, without an owner, and closed
// registration then refused the retry.
func TestRegisterFailsWhole(t *testing.T) {
	h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: true})
	ctx := context.Background()
	if _, err := h.db.Maint.Exec(ctx, "DELETE FROM roles WHERE id = 'role_owner'"); err != nil {
		t.Fatalf("remove the owner role: %v", err)
	}
	_, _, err := h.deps.Identity.Register(ctx, identity.RegisterInput{
		Email: newID() + "@e2e.test", Password: "correct horse battery 9", OrgName: "Broken",
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgForeignKeyViolation {
		t.Fatalf("registering without an owner role answered %v, want SQLSTATE %s", err, pgForeignKeyViolation)
	}
	var users, orgs, history int64
	if err := h.db.Maint.QueryRow(ctx, `SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM organizations),
			(SELECT count(*) FROM password_history)`).Scan(&users, &orgs, &history); err != nil {
		t.Fatalf("count what is left: %v", err)
	}
	if users != 0 || orgs != 0 || history != 0 {
		t.Errorf("a failed registration left %d users, %d organisations and %d password history rows, want none",
			users, orgs, history)
	}
	var exists bool
	if err := h.db.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT auth_users_exist()").Scan(&exists)
	}); err != nil {
		t.Fatalf("auth_users_exist: %v", err)
	}
	if exists {
		t.Error("auth_users_exist() is true after a failed registration, want the instance unclaimed")
	}
	if !h.deps.Identity.RegistrationOpen(ctx) {
		t.Error("registration is closed after a failed first registration")
	}
}

// TestRegisterEmailTaken registers the same address twice with open
// registration on, the second time in other case. The second answers
// ErrEmailTaken, which Register reads from the unique violation's
// SQLSTATE and constraint, and adds no account.
func TestRegisterEmailTaken(t *testing.T) {
	h := startWith(t, harnessOptions{dsn: unclaimedDatabase(t), closedRegistration: false})
	ctx := context.Background()
	email := newID() + "@e2e.test"
	for i, addr := range []string{email, strings.ToUpper(email)} {
		_, _, err := h.deps.Identity.Register(ctx, identity.RegisterInput{
			Email: addr, Password: "correct horse battery 9", OrgName: "Taken",
		})
		switch {
		case i == 0 && err != nil:
			t.Fatalf("the first registration: %v", err)
		case i == 1 && !errors.Is(err, identity.ErrEmailTaken):
			t.Errorf("registering a taken address answered %v, want %v", err, identity.ErrEmailTaken)
		}
	}
	var users, orgs int64
	if err := h.db.Maint.QueryRow(ctx, `SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM organizations)`).
		Scan(&users, &orgs); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	if users != 1 || orgs != 1 {
		t.Errorf("after a refused duplicate there are %d users and %d organisations, want 1 and 1", users, orgs)
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
