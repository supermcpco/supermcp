package upstreamauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

func conn(a adapter.Auth) *engine.Connector {
	return &engine.Connector{ID: "c1", Auth: a}
}

var env = tmpl.Vars{Env: map[string]string{"KEY": "k1", "USER": "u", "PASS": "p", "CID": "id", "CSEC": "sec", "RT": "rt0"}}

func omap(pairs ...string) adapter.OrderedMap[string] {
	m := adapter.NewOrderedMap[string]()
	for i := 0; i+1 < len(pairs); i += 2 {
		m.Set(pairs[i], pairs[i+1])
	}
	return m
}

func TestSimpleSchemes(t *testing.T) {
	cases := []struct {
		name  string
		auth  adapter.Auth
		check func(*http.Request) bool
	}{
		{"apiKey header", adapter.Auth{Type: adapter.AuthAPIKey, In: "header", Name: "X-Key", Value: "{{env.KEY}}", ExtraHeaders: omap("X-Extra", "1")},
			func(r *http.Request) bool { return r.Header.Get("X-Key") == "k1" && r.Header.Get("X-Extra") == "1" }},
		{"apiKey query", adapter.Auth{Type: adapter.AuthAPIKey, In: "query", Name: "api_key", Value: "{{env.KEY}}"},
			func(r *http.Request) bool { return r.URL.Query().Get("api_key") == "k1" }},
		{"apiKey cookie", adapter.Auth{Type: adapter.AuthAPIKey, In: "cookie", Name: "sid", Value: "{{env.KEY}}"},
			func(r *http.Request) bool { c, _ := r.Cookie("sid"); return c != nil && c.Value == "k1" }},
		{"bearer", adapter.Auth{Type: adapter.AuthBearer, Token: "{{env.KEY}}"},
			func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer k1" }},
		{"bearer custom", adapter.Auth{Type: adapter.AuthBearer, Token: "{{env.KEY}}", Header: "X-Token", Prefix: "Token"},
			func(r *http.Request) bool { return r.Header.Get("X-Token") == "Token k1" }},
		{"basic", adapter.Auth{Type: adapter.AuthBasic, Username: "{{env.USER}}", Password: "{{env.PASS}}"},
			func(r *http.Request) bool { u, p, ok := r.BasicAuth(); return ok && u == "u" && p == "p" }},
		{"basic empty password", adapter.Auth{Type: adapter.AuthBasic, Username: "{{env.KEY}}"},
			func(r *http.Request) bool { u, p, ok := r.BasicAuth(); return ok && u == "k1" && p == "" }},
		{"query", adapter.Auth{Type: adapter.AuthQuery, Params: omap("key", "{{env.KEY}}", "format", "json")},
			func(r *http.Request) bool { return r.URL.RawQuery == "a=1&key=k1&format=json" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _, err := Prepare(context.Background(), conn(c.auth), env, Deps{})
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest(http.MethodGet, "https://x.example/p?a=1", nil)
			if err := a.Apply(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if !c.check(req) {
				t.Errorf("check failed: %v %v", req.URL, req.Header)
			}
		})
	}
	// Optional apiKey with no credential sends nothing.
	a, _, err := Prepare(context.Background(), conn(adapter.Auth{Type: adapter.AuthAPIKey, In: "header", Name: "X", Value: "{{env.NOPE}}", Optional: true}), env, Deps{})
	if err != nil || a == nil {
		t.Fatalf("optional apiKey: %v", err)
	}
	if _, _, err := Prepare(context.Background(), conn(adapter.Auth{Type: adapter.AuthAPIKey, In: "header", Name: "X", Value: "{{env.NOPE}}"}), env, Deps{}); err == nil {
		t.Fatal("expected error for missing required credential")
	}
	// Database auth populates the auth namespace only.
	_, vars, err := Prepare(context.Background(), conn(adapter.Auth{Type: adapter.AuthDatabase, Username: "{{env.USER}}", Password: "{{env.PASS}}"}), env, Deps{})
	if err != nil || vars.Auth["username"] != "u" || vars.Auth["password"] != "p" {
		t.Fatalf("database vars %v %v", vars.Auth, err)
	}
}

func TestOAuth2ClientCredentialsAndRefreshRotation(t *testing.T) {
	var tokenCalls int32
	var lastGrant, lastAuth, lastRefresh string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			atomic.AddInt32(&tokenCalls, 1)
			b, _ := io.ReadAll(r.Body)
			f := string(b)
			lastGrant = valueOf(f, "grant_type")
			lastRefresh = valueOf(f, "refresh_token")
			lastAuth = r.Header.Get("Authorization")
			n := atomic.LoadInt32(&tokenCalls)
			_, _ = w.Write([]byte(`{"access_token":"at` + string(rune('0'+n)) + `","expires_in":3600,"refresh_token":"rt` + string(rune('0'+n)) + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	store := NewMemoryStore()
	var rotated []string
	deps := Deps{HTTP: srv.Client(), Store: store, RefreshedRefreshToken: func(_ context.Context, _ string, rt string) error { rotated = append(rotated, rt); return nil }}

	// client_credentials: basic auth by default, cached second call.
	cc := adapter.Auth{Type: adapter.AuthOAuth2, Grant: "client_credentials", ClientID: "{{env.CID}}", ClientSecret: "{{env.CSEC}}", TokenURL: srv.URL + "/token", Scopes: []string{"a", "b"}}
	a, _, err := Prepare(context.Background(), conn(cc), env, deps)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api", nil)
		if err := a.Apply(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if req.Header.Get("Authorization") != "Bearer at1" {
			t.Fatalf("auth header %q", req.Header.Get("Authorization"))
		}
	}
	if atomic.LoadInt32(&tokenCalls) != 1 || lastGrant != "client_credentials" || !strings.HasPrefix(lastAuth, "Basic ") {
		t.Fatalf("calls=%d grant=%q auth=%q", tokenCalls, lastGrant, lastAuth)
	}

	// refresh_token with rotation: second fetch must use the rotated token.
	atomic.StoreInt32(&tokenCalls, 0)
	rotated = nil
	store2 := NewMemoryStore()
	deps.Store = store2
	rt := adapter.Auth{Type: adapter.AuthOAuth2, Grant: "refresh_token", ClientID: "{{env.CID}}", ClientSecret: "{{env.CSEC}}", RefreshToken: "{{env.RT}}", TokenURL: srv.URL + "/token", ClientAuth: "body"}
	a, _, err = Prepare(context.Background(), conn(rt), env, deps)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api", nil)
	if err := a.Apply(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if lastRefresh != "rt0" || lastAuth != "" {
		t.Fatalf("first refresh used %q auth=%q", lastRefresh, lastAuth)
	}
	if ok, err := a.(engine.Refresher).Refresh(context.Background()); !ok || err != nil {
		t.Fatal(err)
	}
	if lastRefresh != "rt1" {
		t.Fatalf("second refresh should use rotated token, used %q", lastRefresh)
	}
	if len(rotated) != 2 || rotated[1] != "rt2" {
		t.Fatalf("rotation callbacks %v", rotated)
	}
}

func valueOf(form, key string) string {
	for _, kv := range strings.Split(form, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if k == key {
			return v
		}
	}
	return ""
}

func TestHMACSignature(t *testing.T) {
	fixed := time.Unix(1700000000, 0)
	a, _, err := Prepare(context.Background(), conn(adapter.Auth{
		Type: adapter.AuthHMAC, Algorithm: "sha256", Encoding: "hex", Secret: "{{env.CSEC}}",
		StringToSign:    "{{req.method}}\n{{req.url}}\n{{req.body}}\n{{req.timestamp}}\n",
		SignatureHeader: "Shop-Signature", TimestampHeader: "Shop-Timestamp",
		ExtraHeaders: omap("Shop-Client-Key", "{{env.CID}}"),
	}), env, Deps{Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"a":1}`)
	req, _ := http.NewRequest(http.MethodPost, "https://sellerapi.kaufland.com/v2/orders?storefront=de", strings.NewReader(string(body)))
	_ = a.Apply(context.Background(), req)
	if err := a.(engine.Signer).Sign(context.Background(), req, body); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("sec"))
	mac.Write([]byte("POST\nhttps://sellerapi.kaufland.com/v2/orders?storefront=de\n{\"a\":1}\n1700000000\n"))
	want := hex.EncodeToString(mac.Sum(nil))
	if req.Header.Get("Shop-Signature") != want || req.Header.Get("Shop-Timestamp") != "1700000000" || req.Header.Get("Shop-Client-Key") != "id" {
		t.Fatalf("headers %v", req.Header)
	}
}

func TestLoginBodyAndSetCookie(t *testing.T) {
	var logins int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			atomic.AddInt32(&logins, 1)
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), `"user":"u"`) || !strings.Contains(string(b), `"pw":"p"`) {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"sid":"S1","exp":"2099-01-01T00:00:00Z"}}`))
		case "/cookie-login":
			if r.URL.Query().Get("account") != "u" {
				w.WriteHeader(401)
				return
			}
			w.Header().Add("Set-Cookie", "other=x; Path=/")
			w.Header().Add("Set-Cookie", "B1SESSION=abc123; Path=/; HttpOnly")
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	body, _ := adapter.NodeFromJSON([]byte(`{"user":"{{auth.username}}","pw":"{{auth.password}}"}`))
	a, vars, err := Prepare(context.Background(), conn(adapter.Auth{
		Type:         adapter.AuthLogin,
		Request:      &adapter.LoginRequest{Method: "POST", URL: srv.URL + "/login", Body: body},
		Credentials:  omap("username", "{{env.USER}}", "password", "{{env.PASS}}", "aud", "supermcp"),
		TokenSource:  &adapter.TokenSource{From: "body", JSONPath: "data.sid"},
		Expiry:       &adapter.Expiry{JSONPath: "data.exp", Format: "iso8601"},
		Inject:       &adapter.Inject{Header: "Authorization", Template: "Bearer {{auth.token}}"},
		ExtraHeaders: omap("JWT-AUD", "{{auth.aud}}"),
	}), env, Deps{HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if vars.Auth["aud"] != "supermcp" {
		t.Fatalf("auth vars %v", vars.Auth)
	}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api", nil)
		if err := a.Apply(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if req.Header.Get("Authorization") != "Bearer S1" || req.Header.Get("JWT-AUD") != "supermcp" {
			t.Fatalf("headers %v", req.Header)
		}
	}
	if atomic.LoadInt32(&logins) != 1 {
		t.Fatalf("login called %d times", logins)
	}

	// GET login with query form, token harvested from Set-Cookie, injected as cookie.
	q, _ := adapter.NodeFromJSON([]byte(`{"account":"{{auth.username}}","passwd":"{{auth.password}}","format":"sid"}`))
	a, _, err = Prepare(context.Background(), conn(adapter.Auth{
		Type:        adapter.AuthLogin,
		Request:     &adapter.LoginRequest{Method: "GET", URL: srv.URL + "/cookie-login", Query: q},
		Credentials: omap("username", "{{env.USER}}", "password", "{{env.PASS}}"),
		TokenSource: &adapter.TokenSource{From: "setCookie", CookieName: "B1SESSION"},
		Inject:      &adapter.Inject{Cookie: "B1SESSION"},
	}), env, Deps{HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api", nil)
	if err := a.Apply(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if c, _ := req.Cookie("B1SESSION"); c == nil || c.Value != "abc123" {
		t.Fatalf("cookie not injected: %v", req.Header)
	}
}

func TestJSONPathAndExpiry(t *testing.T) {
	doc := map[string]any{"a": []any{map[string]any{"b": "x"}}}
	if jsonPath(doc, "a.0.b") != "x" || jsonPath(doc, "a.1.b") != nil || jsonPath(doc, "nope") != nil {
		t.Fatal("jsonPath")
	}
	now := time.Unix(1000, 0)
	if ts, ok := parseExpiry(float64(1700000000), "unix", now); !ok || ts.Unix() != 1700000000 {
		t.Fatal("unix")
	}
	if ts, ok := parseExpiry(float64(1700000000000), "unix", now); !ok || ts.Unix() != 1700000000 {
		t.Fatal("unix ms")
	}
	if ts, ok := parseExpiry("30", "ttl_seconds", now); !ok || ts.Unix() != 1030 {
		t.Fatal("ttl")
	}
}
