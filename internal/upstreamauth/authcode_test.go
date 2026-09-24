package upstreamauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// vendor is a fake authorization server: it shows a consent screen that
// always says yes, and a token endpoint that checks what the client sent
// before answering.
type vendor struct {
	srv    *httptest.Server
	answer answer

	mu        sync.Mutex
	challenge string     // what the authorization request carried
	authQuery url.Values // the whole authorization request
	tokenForm url.Values // the whole token request
	tokenAuth string     // the token request's Authorization header
}

// answer is how the token endpoint behaves, fixed before it serves
// anything so that no test writes to a field the server is reading.
type answer struct {
	noRefresh bool
	status    int
	body      string
}

const vendorBodySecret = "upstream http://10.0.0.7:9000 refused the grant"

func newVendor(t *testing.T, a answer) *vendor {
	t.Helper()
	v := &vendor{answer: a}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", v.authorize)
	mux.HandleFunc("/token", v.token)
	v.srv = httptest.NewServer(mux)
	t.Cleanup(v.srv.Close)
	return v
}

// authorize records the request and redirects back with a code, which is
// what a person clicking "allow" amounts to.
func (v *vendor) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	v.mu.Lock()
	v.authQuery, v.challenge = q, q.Get("code_challenge")
	v.mu.Unlock()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := back.Query()
	rq.Set("code", "vendor-code-1")
	rq.Set("state", q.Get("state"))
	back.RawQuery = rq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (v *vendor) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	v.mu.Lock()
	v.tokenForm, v.tokenAuth = r.PostForm, r.Header.Get("Authorization")
	challenge := v.challenge
	v.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if v.answer.status != 0 {
		w.WriteHeader(v.answer.status)
		_, _ = w.Write([]byte(v.answer.body))
		return
	}
	if v.answer.noRefresh {
		_, _ = w.Write([]byte(`{"access_token":"at1","expires_in":3600}`))
		return
	}
	_, _ = w.Write([]byte(`{"access_token":"at1","refresh_token":"rt1","expires_in":1800}`))
}

func (v *vendor) params() Params {
	return Params{
		ConnectorID: "c1", OrgID: "org1", ClientID: "cid", ClientSecret: "csec",
		AuthorizationURL: v.srv.URL + "/authorize", TokenURL: v.srv.URL + "/token",
		Scopes: []string{"read", "write"},
	}
}

// flow builds the service under test against a vendor.
func (v *vendor) flow() *AuthCode {
	pub, _ := url.Parse("https://mcp.example")
	return NewAuthCode(NewMemoryConsentStore(), v.srv.Client(), pub)
}

// consent walks the browser's half of the round trip: it opens the
// authorization URL and returns the query the vendor redirected back with.
func consent(t *testing.T, a *AuthCode, v *vendor, p Params) url.Values {
	t.Helper()
	authURL, err := a.Begin(context.Background(), p, "user1")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// The browser does not follow the redirect back to us; the test is
	// standing in for it, and the callback is the next step.
	client := &http.Client{
		Transport:     v.srv.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatalf("authorization request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authorization request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("callback URL: %v", err)
	}
	return back.Query()
}

func TestAuthCodeStoresAUsableRefreshToken(t *testing.T) {
	t.Parallel()
	v := newVendor(t, answer{})
	a := v.flow()
	p := v.params()

	back := consent(t, a, v, p)
	c, err := a.Consume(context.Background(), back.Get("state"))
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if c.ConnectorID != "c1" || c.OrgID != "org1" || c.ActorID != "user1" {
		t.Fatalf("consent lost track of the connector: %+v", c)
	}
	tok, err := a.Exchange(context.Background(), p, c, back.Get("code"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.Refresh != "rt1" || tok.Access != "at1" {
		t.Fatalf("tokens %+v", tok)
	}
	if d := time.Until(tok.ExpiresAt); d < 25*time.Minute || d > 30*time.Minute {
		t.Fatalf("expiry %v is not the vendor's half hour", d)
	}

	// The authorization request asked for what the adapter declares, and
	// nothing else.
	if got := v.authQuery.Get("scope"); got != "read write" {
		t.Errorf("scope %q", got)
	}
	if got := v.authQuery.Get("redirect_uri"); got != "https://mcp.example/auth/connectors/callback" {
		t.Errorf("redirect_uri %q", got)
	}
	if got := v.authQuery.Get("code_challenge_method"); got != "S256" || v.authQuery.Get("code_challenge") == "" {
		t.Errorf("no PKCE challenge: %v", v.authQuery)
	}
	// The token request carries the verifier (the vendor already checked
	// it hashes to the challenge) and no scope of its own.
	if v.tokenForm.Get("code_verifier") == "" || v.tokenForm.Has("scope") {
		t.Errorf("token form %v", v.tokenForm)
	}
	if v.tokenForm.Get("client_secret") != "csec" || v.tokenAuth != "" {
		t.Errorf("client should authenticate in the body by default: %v %q", v.tokenForm, v.tokenAuth)
	}
}

func TestAuthCodeClientSecretBasic(t *testing.T) {
	t.Parallel()
	v := newVendor(t, answer{})
	a := v.flow()
	p := v.params()
	p.ClientAuth = "basic"

	back := consent(t, a, v, p)
	c, err := a.Consume(context.Background(), back.Get("state"))
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := a.Exchange(context.Background(), p, c, back.Get("code")); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:csec"))
	if v.tokenAuth != want || v.tokenForm.Has("client_secret") {
		t.Errorf("basic auth %q, form %v", v.tokenAuth, v.tokenForm)
	}
}

func TestAuthCodeStateIsGoodOnce(t *testing.T) {
	t.Parallel()
	v := newVendor(t, answer{})
	a := v.flow()
	back := consent(t, a, v, v.params())

	if _, err := a.Consume(context.Background(), back.Get("state")); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := a.Consume(context.Background(), back.Get("state")); !errors.Is(err, ErrConsentInvalid) {
		t.Fatalf("replay: %v", err)
	}
}

func TestAuthCodeRefusesUnknownAndExpiredState(t *testing.T) {
	t.Parallel()

	t.Run("state we never issued", func(t *testing.T) {
		t.Parallel()
		v := newVendor(t, answer{})
		a := v.flow()
		back := consent(t, a, v, v.params())
		// A consent is in flight, so the refusal is about this state and
		// not about an empty store.
		for _, state := range []string{"", "not-a-state", back.Get("state") + "x"} {
			if _, err := a.Consume(context.Background(), state); !errors.Is(err, ErrConsentInvalid) {
				t.Errorf("state %q: %v", state, err)
			}
		}
	})

	t.Run("state that sat too long", func(t *testing.T) {
		t.Parallel()
		v := newVendor(t, answer{})
		a := v.flow()
		back := consent(t, a, v, v.params())
		a.now = func() time.Time { return time.Now().Add(consentTTL + time.Minute) }
		if _, err := a.Consume(context.Background(), back.Get("state")); !errors.Is(err, ErrConsentInvalid) {
			t.Fatalf("expired: %v", err)
		}
	})

	t.Run("two consents do not cross", func(t *testing.T) {
		t.Parallel()
		v := newVendor(t, answer{})
		a := v.flow()
		first := v.params()
		second := v.params()
		second.ConnectorID, second.OrgID = "c2", "org2"
		backFirst := consent(t, a, v, first)
		backSecond := consent(t, a, v, second)
		if backFirst.Get("state") == backSecond.Get("state") {
			t.Fatal("two consents shared a state")
		}
		// The state says which connector is being connected. Nothing the
		// vendor sends in the URL gets a say.
		c, err := a.Consume(context.Background(), backSecond.Get("state"))
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if c.ConnectorID != "c2" || c.OrgID != "org2" {
			t.Fatalf("state resolved to the wrong connector: %+v", c)
		}
	})
}

func TestAuthCodeReportsAMissingRefreshToken(t *testing.T) {
	t.Parallel()
	v := newVendor(t, answer{noRefresh: true})
	a := v.flow()
	p := v.params()

	back := consent(t, a, v, p)
	c, err := a.Consume(context.Background(), back.Get("state"))
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	tok, err := a.Exchange(context.Background(), p, c, back.Get("code"))
	if !errors.Is(err, ErrNoRefreshToken) {
		t.Fatalf("err %v", err)
	}
	// Nothing usable comes back: an access token on its own would be a
	// connector that works until tea time.
	if tok != nil {
		t.Fatalf("token %+v", tok)
	}
}

func TestAuthCodeSurfacesAVendorErrorWithoutItsBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"refusal", http.StatusBadRequest, `{"error":"invalid_client","error_description":"` + vendorBodySecret + `"}`},
		{"server trouble", http.StatusInternalServerError, vendorBodySecret},
		{"success with an error inside", http.StatusOK, `{"error":"invalid_scope","error_description":"` + vendorBodySecret + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := newVendor(t, answer{status: tc.status, body: tc.body})
			a := v.flow()
			p := v.params()

			back := consent(t, a, v, p)
			c, err := a.Consume(context.Background(), back.Get("state"))
			if err != nil {
				t.Fatalf("consume: %v", err)
			}
			_, err = a.Exchange(context.Background(), p, c, back.Get("code"))
			if !errors.Is(err, ErrVendorRejected) {
				t.Fatalf("err %v", err)
			}
			// What an administrator is shown is derived from the sentinel;
			// what is logged must not repeat the vendor's prose, which can
			// name an internal address.
			if strings.Contains(err.Error(), vendorBodySecret) || strings.Contains(err.Error(), "10.0.0.7") {
				t.Fatalf("the vendor's body leaked into %q", err)
			}
			if strings.Contains(ErrVendorRejected.Error(), vendorBodySecret) {
				t.Fatal("the redirect reason is not a constant")
			}
		})
	}
}

func TestParamsForReadsTheAuthBlock(t *testing.T) {
	t.Parallel()
	creds := map[string]string{"CID": "id", "CSEC": "sec"}
	base := adapter.Auth{
		Type: adapter.AuthOAuth2, Grant: "authorization_code",
		ClientID: "{{env.CID}}", ClientSecret: "{{env.CSEC}}",
		AuthorizationURL: "https://vendor.example/authorize", TokenURL: "https://vendor.example/token",
		Scopes: []string{"a"}, ExtraTokenParams: omap("resource", "https://vendor.example/api"),
	}
	p, err := ParamsFor(conn(base), "org1", creds)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	if p.ClientID != "id" || p.ClientSecret != "sec" || p.ConnectorID != "c1" || p.OrgID != "org1" {
		t.Fatalf("params %+v", p)
	}
	if p.ExtraTokenParams["resource"] != "https://vendor.example/api" {
		t.Fatalf("extra token params %v", p.ExtraTokenParams)
	}

	plainHTTP := base
	plainHTTP.TokenURL = "http://vendor.example/token"
	if _, err := ParamsFor(conn(plainHTTP), "org1", creds); err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Fatalf("plain http token endpoint: %v", err)
	}
	loopback := base
	loopback.AuthorizationURL = "http://127.0.0.1:9/authorize"
	if _, err := ParamsFor(conn(loopback), "org1", creds); err != nil {
		t.Fatalf("loopback is for tests and development: %v", err)
	}
	other := base
	other.Grant = "client_credentials"
	if _, err := ParamsFor(conn(other), "org1", creds); !errors.Is(err, ErrNotAuthCode) {
		t.Fatalf("wrong grant: %v", err)
	}
	missing := base
	missing.ClientID = "{{env.NOPE}}"
	if _, err := ParamsFor(conn(missing), "org1", creds); err == nil {
		t.Fatal("expected an error when the client id credential is not set")
	}
}
