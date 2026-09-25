package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/identity"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "t" + hex.EncodeToString(b)
}

// TestIdentityAuthzAPIKeys runs the login path end to end on a real
// database: first-user bootstrap, owner binding, lockout, sessions, API
// keys and permission evaluation including fail-closed defaults.
func TestIdentityAuthzAPIKeys(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
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
	defer st.Close()
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}
	az := authz.New(db)
	ids := identity.New(db, identity.Config{OpenRegistration: true, LockoutThreshold: 3, LockoutWindow: time.Minute}, az, newID)
	keys := mcpauth.New(db, newID)

	email := newID() + "@example.test"
	u, o, err := ids.Register(ctx, identity.RegisterInput{Email: email, Name: "Test", Password: "correct horse battery 9"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ids.Register(ctx, identity.RegisterInput{Email: email, Name: "Dup", Password: "correct horse battery 9"}); !errors.Is(err, identity.ErrEmailTaken) {
		t.Fatalf("duplicate email: %v", err)
	}
	if _, _, err := ids.Register(ctx, identity.RegisterInput{Email: newID() + "@x.test", Password: "short"}); !errors.Is(err, identity.ErrWeakPassword) {
		t.Fatalf("weak password: %v", err)
	}

	// Login, wrong password thrice → locked.
	if _, err := ids.Login(ctx, email, "correct horse battery 9", "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := ids.Login(ctx, email, "wrong", "203.0.113.5"); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := ids.Login(ctx, email, "correct horse battery 9", "203.0.113.5"); !errors.Is(err, identity.ErrLocked) {
		t.Fatalf("expected lockout, got %v", err)
	}
	// Unknown email is indistinguishable from a wrong password.
	if _, err := ids.Login(ctx, "nobody-"+email, "x", "203.0.113.6"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}

	// Sessions.
	sess, err := ids.CreateSession(ctx, u.ID, o.ID, "password", "", nil, time.Now(), "203.0.113.5", "test")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ids.LoadSession(ctx, sess.ID)
	if err != nil || loaded.UserID != u.ID || loaded.OrgID != o.ID {
		t.Fatalf("load session: %+v %v", loaded, err)
	}
	if _, err := ids.LoadSession(ctx, "nope"); !errors.Is(err, identity.ErrSessionInvalid) {
		t.Fatalf("bogus session: %v", err)
	}
	if _, err := ids.RevokeSession(ctx, sess.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := ids.LoadSession(ctx, sess.ID); !errors.Is(err, identity.ErrSessionInvalid) {
		t.Fatalf("revoked session still loads: %v", err)
	}

	// Authorization: the creator owns the org.
	p := ids.Principal(loaded, email)
	for _, perm := range []authz.Permission{authz.OrgDelete, authz.ConnectorsCreate, authz.ToolsInvoke} {
		if err := az.Require(authz.WithPrincipal(ctx, p), perm, authz.Resource{}); err != nil {
			t.Errorf("owner should hold %s: %v", perm, err)
		}
	}
	// A stranger in another org gets nothing, even with a valid principal.
	stranger := &authz.Principal{Kind: authz.KindUser, ID: newID(), OrgID: o.ID}
	if d, _ := az.Evaluate(ctx, stranger, authz.ToolsRead, authz.Resource{}); d.Allow {
		t.Error("principal without bindings was allowed")
	}
	if d, _ := az.Evaluate(ctx, p, authz.ToolsRead, authz.Resource{OrgID: "other-org"}); d.Allow {
		t.Error("cross-org resource was allowed")
	}

	// API keys: create, authenticate, scopes, revoke.
	rec, secret, err := keys.Create(ctx, mcpauth.CreateInput{OrgID: o.ID, PrincipalKind: "user", PrincipalID: u.ID, Name: "Claude Desktop", Scopes: []string{authz.ScopeToolsRead}})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 50 || secret[:4] != "smk_" {
		t.Fatalf("secret shape %q", secret)
	}
	kp, err := keys.Authenticate(ctx, secret, "203.0.113.5")
	if err != nil || kp.ID != u.ID || kp.OrgID != o.ID || kp.APIKeyID != rec.ID {
		t.Fatalf("authenticate: %+v %v", kp, err)
	}
	if _, err := keys.Authenticate(ctx, secret[:len(secret)-1]+"x", ""); !errors.Is(err, mcpauth.ErrInvalidKey) {
		t.Fatalf("tampered key accepted: %v", err)
	}
	// Read-only scope: tools:read allowed, tools:invoke denied, admin ops denied.
	if err := az.Require(authz.WithPrincipal(ctx, kp), authz.ToolsRead, authz.Resource{}); err != nil {
		t.Errorf("key should read tools: %v", err)
	}
	if d, _ := az.Evaluate(ctx, kp, authz.ToolsInvoke, authz.Resource{}); d.Allow {
		t.Error("read-only key could invoke")
	}
	if d, _ := az.Evaluate(ctx, kp, authz.ConnectorsCreate, authz.Resource{}); d.Allow {
		t.Error("key could create connectors")
	}
	list, err := keys.List(ctx, o.ID, u.ID, false)
	if err != nil || len(list) != 1 || list[0].Prefix != rec.Prefix {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := keys.Revoke(ctx, o.ID, rec.ID, u.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Authenticate(ctx, secret, ""); !errors.Is(err, mcpauth.ErrInvalidKey) {
		t.Fatalf("revoked key accepted: %v", err)
	}

	// Rotation: old key keeps a grace window, new key works.
	rec2, secret2, err := keys.Create(ctx, mcpauth.CreateInput{OrgID: o.ID, PrincipalKind: "user", PrincipalID: u.ID, Name: "rotating"})
	if err != nil {
		t.Fatal(err)
	}
	rot, err := keys.Rotate(ctx, mcpauth.RotateInput{OrgID: o.ID, ID: rec2.ID, ActorID: u.ID, Self: true, Grace: time.Hour})
	if err != nil || rot.Key.RotatedFrom != rec2.ID {
		t.Fatalf("rotate: %+v %v", rot, err)
	}
	if _, err := keys.Authenticate(ctx, secret2, ""); err != nil {
		t.Errorf("old key inside grace: %v", err)
	}
	if _, err := keys.Authenticate(ctx, rot.Secret, ""); err != nil {
		t.Errorf("new key: %v", err)
	}
}
