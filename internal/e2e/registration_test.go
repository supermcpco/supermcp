package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/testdb"
)

// registrationClosed is what register answers when it refuses.
const registrationClosed = "Registration is closed. Ask an administrator for an invitation."

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
			}
		})
	}
}

// TestRegisterAgreesWithSession registers through the API after asking the
// session whether it may, with no users and with one, open registration
// off and on. Whatever the session says, register does.
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
				code := h.do(t, http.MethodPost, "/api/v1/auth/register", map[string]any{
					"email": newID() + "@e2e.test", "password": "correct horse battery 9", "orgName": "Agree",
				}, &refusal)
				switch {
				case open && code != http.StatusOK:
					t.Errorf("with %d users the session says open and register answers %d: %+v", users, code, refusal)
				case !open && code != http.StatusForbidden:
					t.Errorf("with %d users the session says closed and register answers %d", users, code)
				case !open && refusal.Detail != registrationClosed:
					t.Errorf("the refusal says %q, want %q", refusal.Detail, registrationClosed)
				}
			}
		})
	}
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
