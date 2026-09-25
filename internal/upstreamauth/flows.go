package upstreamauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is required by some upstream APIs
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// refreshBuffer: tokens are renewed this long before expiry.
const refreshBuffer = 5 * time.Minute

var flights singleflight.Group

// ---------------------------------------------------------------------------
// OAuth2 (client_credentials, refresh_token)

type oauth2Auth struct {
	connID     string
	grant      string
	clientID   string
	secret     string
	tokenURL   string
	scopes     []string
	clientAuth string // basic | body
	refresh    string // configured refresh token (may be rotated later)
	extraTok   map[string]string
	extra      map[string]string
	inject     adapter.Inject
	deps       Deps
	mu         sync.Mutex
	cached     *Token
}

func newOAuth2(ctx context.Context, conn *engine.Connector, vars tmpl.Vars, deps Deps, render func(string) (string, error), renderMap func(adapter.OrderedMap[string]) (map[string]string, error)) (engine.Authenticator, tmpl.Vars, error) {
	a := conn.Auth
	o := &oauth2Auth{connID: conn.ID, grant: a.Grant, scopes: a.Scopes, clientAuth: a.ClientAuth, deps: deps}
	var err error
	if o.clientID, err = render(a.ClientID); err != nil {
		return nil, vars, err
	}
	if o.secret, err = render(a.ClientSecret); err != nil {
		return nil, vars, err
	}
	if o.tokenURL, err = render(a.TokenURL); err != nil {
		return nil, vars, err
	}
	if o.refresh, err = render(a.RefreshToken); err != nil {
		return nil, vars, err
	}
	if o.extraTok, err = renderMap(a.ExtraTokenParams); err != nil {
		return nil, vars, err
	}
	if o.extra, err = renderMap(a.ExtraHeaders); err != nil {
		return nil, vars, err
	}
	if a.Inject != nil {
		o.inject = *a.Inject
	}
	switch o.grant {
	case "client_credentials":
		if o.clientID == "" || o.secret == "" || o.tokenURL == "" {
			return nil, vars, errors.New("oauth2 client_credentials: clientId, clientSecret and tokenUrl are required")
		}
	case "refresh_token":
		if o.refresh == "" || o.tokenURL == "" {
			return nil, vars, errors.New("oauth2 refresh_token: refreshToken and tokenUrl are required")
		}
	case "authorization_code":
		if o.tokenURL == "" {
			return nil, vars, errors.New("oauth2 authorization_code: tokenUrl is required")
		}
		// A stored refresh token drives renewal. It may live in the token
		// store rather than in a credential, because the consent flow put
		// it there and several adapters declare no placeholder for one.
		if o.refresh == "" {
			if st, ok, _ := deps.Store.Get(ctx, conn.ID); ok && st.Refresh != "" {
				o.refresh = st.Refresh
			}
		}
		if o.refresh == "" {
			return nil, vars, errors.New("oauth2 authorization_code: connector has not completed the consent flow (no refresh token)")
		}
	default:
		return nil, vars, fmt.Errorf("oauth2: unsupported grant %q", o.grant)
	}
	if deps.HTTP == nil {
		return nil, vars, errors.New("oauth2: no HTTP client for the token endpoint")
	}
	return o, vars, nil
}

func (o *oauth2Auth) Apply(ctx context.Context, req *http.Request) error {
	tok, err := o.token(ctx, false)
	if err != nil {
		return err
	}
	injectToken(req, o.inject, tok.Access)
	for k, v := range o.extra {
		req.Header.Set(k, v)
	}
	return nil
}

func (o *oauth2Auth) Refresh(ctx context.Context) (bool, error) {
	_, err := o.token(ctx, true)
	return err == nil, err
}

func (o *oauth2Auth) token(ctx context.Context, force bool) (*Token, error) {
	if !force {
		o.mu.Lock()
		c := o.cached
		o.mu.Unlock()
		if c != nil && c.ExpiresAt.After(o.deps.now().Add(refreshBuffer)) {
			return c, nil
		}
		if st, ok, _ := o.deps.Store.Get(ctx, o.connID); ok && st.ExpiresAt.After(o.deps.now().Add(refreshBuffer)) {
			o.mu.Lock()
			o.cached = st
			o.mu.Unlock()
			return st, nil
		}
	}
	v, err, _ := flights.Do("oauth2:"+o.connID, func() (any, error) {
		return o.fetch(ctx)
	})
	if err != nil {
		return nil, err
	}
	return v.(*Token), nil
}

func (o *oauth2Auth) fetch(ctx context.Context) (*Token, error) {
	form := url.Values{}
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}}
	useBasic := o.clientAuth == "basic" || (o.clientAuth == "" && o.grant == "client_credentials")
	switch o.grant {
	case "client_credentials":
		form.Set("grant_type", "client_credentials")
	default:
		form.Set("grant_type", "refresh_token")
		refresh := o.refresh
		if st, ok, _ := o.deps.Store.Get(ctx, o.connID); ok && st.Refresh != "" {
			refresh = st.Refresh // a rotated token supersedes the configured one
		}
		form.Set("refresh_token", refresh)
	}
	if len(o.scopes) > 0 {
		form.Set("scope", strings.Join(o.scopes, " "))
	}
	if useBasic && o.clientID != "" {
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(o.clientID+":"+o.secret)))
	} else {
		if o.clientID != "" {
			form.Set("client_id", o.clientID)
		}
		if o.secret != "" {
			form.Set("client_secret", o.secret)
		}
	}
	for k, v := range o.extraTok {
		form.Set(k, v)
	}
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }
	req.Header = headers
	resp, err := o.deps.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2 token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("oauth2 token endpoint returned %d: %s", resp.StatusCode, truncate(string(data), 300))
	}
	var tr struct {
		AccessToken  string          `json:"access_token"`
		ExpiresIn    json.RawMessage `json:"expires_in"`
		RefreshToken string          `json:"refresh_token"`
	}
	if err := json.Unmarshal(data, &tr); err != nil || tr.AccessToken == "" {
		return nil, errors.New("oauth2 token endpoint returned no access_token")
	}
	ttl := 3600 * time.Second
	if n, err := strconv.ParseFloat(strings.Trim(string(tr.ExpiresIn), `"`), 64); err == nil && n > 0 {
		ttl = time.Duration(n) * time.Second
	}
	tok := &Token{Access: tr.AccessToken, ExpiresAt: o.deps.now().Add(ttl), Refresh: tr.RefreshToken}
	if tok.Refresh == "" {
		if st, ok, _ := o.deps.Store.Get(ctx, o.connID); ok {
			tok.Refresh = st.Refresh
		}
	}
	// Persist the rotated refresh token before the new access token is used:
	// losing it would strand the connector.
	if err := o.deps.Store.Put(ctx, o.connID, tok); err != nil {
		return nil, fmt.Errorf("persist token: %w", err)
	}
	if tr.RefreshToken != "" && tr.RefreshToken != o.refresh && o.deps.RefreshedRefreshToken != nil {
		if err := o.deps.RefreshedRefreshToken(ctx, o.connID, tr.RefreshToken); err != nil {
			return nil, fmt.Errorf("persist rotated refresh token: %w", err)
		}
	}
	o.mu.Lock()
	o.cached = tok
	o.mu.Unlock()
	return tok, nil
}

func injectToken(req *http.Request, inj adapter.Inject, token string) {
	switch {
	case inj.Cookie != "":
		req.AddCookie(&http.Cookie{Name: inj.Cookie, Value: token}) //nolint:gosec // outbound request cookie; response-only attributes do not apply
	case inj.Template != "":
		name := inj.Header
		if name == "" {
			name = "Authorization"
		}
		req.Header.Set(name, strings.ReplaceAll(inj.Template, "{{auth.token}}", token))
	default:
		name, prefix := inj.Header, inj.Prefix
		if name == "" {
			name = "Authorization"
		}
		if prefix == "" && name == "Authorization" {
			prefix = "Bearer"
		}
		req.Header.Set(name, strings.TrimSpace(prefix+" "+token))
	}
}

// ---------------------------------------------------------------------------
// HMAC request signing

type hmacSigner struct {
	cfg    adapter.Auth
	secret string
	extra  map[string]string
	now    func() time.Time
}

func (h *hmacSigner) Apply(_ context.Context, req *http.Request) error {
	for k, v := range h.extra {
		req.Header.Set(k, v)
	}
	return nil
}

func (h *hmacSigner) Sign(_ context.Context, req *http.Request, body []byte) error {
	now := h.now()
	var ts string
	switch h.cfg.TimestampFormat {
	case "unix_ms":
		ts = strconv.FormatInt(now.UnixMilli(), 10)
	case "iso8601":
		ts = now.UTC().Format(time.RFC3339)
	default:
		ts = strconv.FormatInt(now.Unix(), 10)
	}
	full := req.URL.String()
	path := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	vars := tmpl.Vars{Req: map[string]string{
		"method": strings.ToUpper(req.Method), "url": full, "path": path, "body": string(body), "timestamp": ts,
	}}
	canonical, err := tmpl.RenderString(h.cfg.StringToSign, vars, tmpl.Strict)
	if err != nil {
		return fmt.Errorf("hmac stringToSign: %w", err)
	}
	var newHash func() hash.Hash
	switch h.cfg.Algorithm {
	case "sha1":
		newHash = sha1.New
	case "sha512":
		newHash = sha512.New
	default:
		newHash = sha256.New
	}
	mac := hmac.New(newHash, []byte(h.secret))
	mac.Write([]byte(canonical))
	var sig string
	if h.cfg.Encoding == "base64" {
		sig = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	} else {
		sig = hex.EncodeToString(mac.Sum(nil))
	}
	req.Header.Set(h.cfg.SignatureHeader, sig)
	if h.cfg.TimestampHeader != "" {
		req.Header.Set(h.cfg.TimestampHeader, ts)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Login token (session-style APIs)

type loginAuth struct {
	connID   string
	cfg      adapter.Auth
	creds    map[string]string
	vars     tmpl.Vars
	deps     Deps
	extra    map[string]string
	mu       sync.Mutex
	cached   *Token
	ttl      time.Duration
	refreshB time.Duration
}

func newLogin(conn *engine.Connector, vars tmpl.Vars, deps Deps, render func(string) (string, error), renderMap func(adapter.OrderedMap[string]) (map[string]string, error)) (engine.Authenticator, tmpl.Vars, error) {
	a := conn.Auth
	if a.Request == nil || a.TokenSource == nil || a.Inject == nil {
		return nil, vars, errors.New("login auth: request, tokenSource and inject are required")
	}
	if len(a.Preprocess) > 0 {
		return nil, vars, fmt.Errorf("login auth: preprocess steps are not supported: %w", engine.ErrUnsupported)
	}
	creds, err := renderMap(a.Credentials)
	if err != nil {
		return nil, vars, err
	}
	for k, v := range creds {
		vars.Auth[k] = v
	}
	extra, err := renderMap(a.ExtraHeaders)
	if err != nil {
		return nil, vars, err
	}
	if deps.HTTP == nil {
		return nil, vars, errors.New("login auth: no HTTP client")
	}
	l := &loginAuth{connID: conn.ID, cfg: a, creds: creds, vars: vars, deps: deps, extra: extra, ttl: 30 * 24 * time.Hour, refreshB: 24 * time.Hour}
	if a.Expiry != nil {
		if a.Expiry.TTL != 0 {
			l.ttl = time.Duration(a.Expiry.TTL)
		}
		if a.Expiry.RefreshBefore != 0 {
			l.refreshB = time.Duration(a.Expiry.RefreshBefore)
		}
	}
	return l, vars, nil
}

func (l *loginAuth) Apply(ctx context.Context, req *http.Request) error {
	tok, err := l.token(ctx, false)
	if err != nil {
		return err
	}
	// Templates may reference any credential besides the token.
	authVars := map[string]string{"token": tok.Access}
	for k, v := range l.creds {
		authVars[k] = v
	}
	inj := *l.cfg.Inject
	if inj.Template != "" {
		rendered, err := tmpl.RenderString(inj.Template, tmpl.Vars{Auth: authVars}, tmpl.Strict)
		if err != nil {
			return fmt.Errorf("login inject template: %w", err)
		}
		inj.Template = "{{auth.token}}"
		injectToken(req, inj, rendered)
	} else {
		injectToken(req, inj, tok.Access)
	}
	for k, v := range l.extra {
		rendered, err := tmpl.RenderString(v, tmpl.Vars{Auth: authVars, Env: l.vars.Env}, tmpl.Value)
		if err == nil {
			req.Header.Set(k, rendered)
		}
	}
	return nil
}

func (l *loginAuth) Refresh(ctx context.Context) (bool, error) {
	if l.cfg.Expiry != nil && l.cfg.Expiry.RefreshOn401 != nil && !*l.cfg.Expiry.RefreshOn401 {
		return false, nil
	}
	_, err := l.token(ctx, true)
	return err == nil, err
}

func (l *loginAuth) token(ctx context.Context, force bool) (*Token, error) {
	if !force {
		l.mu.Lock()
		c := l.cached
		l.mu.Unlock()
		if c != nil && c.ExpiresAt.After(l.deps.now().Add(l.refreshB)) {
			return c, nil
		}
		if st, ok, _ := l.deps.Store.Get(ctx, l.connID); ok && st.ExpiresAt.After(l.deps.now().Add(l.refreshB)) {
			l.mu.Lock()
			l.cached = st
			l.mu.Unlock()
			return st, nil
		}
	}
	v, err, _ := flights.Do("login:"+l.connID, func() (any, error) { return l.login(ctx) })
	if err != nil {
		return nil, err
	}
	return v.(*Token), nil
}

func (l *loginAuth) login(ctx context.Context) (*Token, error) {
	r := l.cfg.Request
	vars := tmpl.Vars{Auth: l.creds, Env: l.vars.Env}
	u, err := tmpl.RenderString(r.URL, vars, tmpl.Strict)
	if err != nil {
		return nil, fmt.Errorf("login url: %w", err)
	}
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = http.MethodPost
	}
	var body []byte
	contentType := ""
	for _, k := range r.Headers.Keys {
		if strings.EqualFold(k, "Content-Type") {
			contentType, _ = tmpl.RenderString(r.Headers.Values[k], vars, tmpl.Strict)
		}
	}
	if r.Query != nil && r.Query.N != nil {
		raw, _ := r.Query.Value()
		rendered, err := tmpl.RenderValue(raw, vars)
		if err != nil {
			return nil, fmt.Errorf("login query: %w", err)
		}
		q := url.Values{}
		if m, ok := rendered.(map[string]any); ok {
			for k, v := range m {
				q.Set(k, tmpl.Stringify(v))
			}
		}
		if strings.Contains(u, "?") {
			u += "&" + q.Encode()
		} else {
			u += "?" + q.Encode()
		}
	}
	if r.Body != nil && r.Body.N != nil {
		raw, _ := r.Body.Value()
		rendered, err := tmpl.RenderValue(raw, vars)
		if err != nil {
			return nil, fmt.Errorf("login body: %w", err)
		}
		if strings.Contains(contentType, "x-www-form-urlencoded") {
			f := url.Values{}
			if m, ok := rendered.(map[string]any); ok {
				for k, v := range m {
					f.Set(k, tmpl.Stringify(v))
				}
			}
			body = []byte(f.Encode())
		} else {
			body, _ = json.Marshal(rendered)
			if contentType == "" {
				contentType = "application/json"
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	for _, k := range r.Headers.Keys {
		v, _ := tmpl.RenderString(r.Headers.Values[k], vars, tmpl.Strict)
		req.Header.Set(k, v)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := l.deps.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("login endpoint returned %d: %s", resp.StatusCode, truncate(string(data), 300))
	}
	var doc any
	_ = json.Unmarshal(data, &doc)

	var token string
	ts := l.cfg.TokenSource
	switch ts.From {
	case "setCookie":
		token = cookieValue(resp.Header.Values("Set-Cookie"), ts.CookieName)
		if token == "" && ts.JSONPath != "" {
			token = tmpl.Stringify(jsonPath(doc, ts.JSONPath))
		}
		if token == "" {
			return nil, fmt.Errorf("login: cookie %q not found in Set-Cookie", ts.CookieName)
		}
	default:
		token = tmpl.Stringify(jsonPath(doc, ts.JSONPath))
		if token == "" {
			return nil, fmt.Errorf("login: token not found at %q in login response", ts.JSONPath)
		}
	}
	expires := l.deps.now().Add(l.ttl)
	if e := l.cfg.Expiry; e != nil && e.JSONPath != "" {
		if v := jsonPath(doc, e.JSONPath); v != nil {
			if t, ok := parseExpiry(v, e.Format, l.deps.now()); ok {
				expires = t
			}
		}
	}
	tok := &Token{Access: token, ExpiresAt: expires}
	if err := l.deps.Store.Put(ctx, l.connID, tok); err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.cached = tok
	l.mu.Unlock()
	return tok, nil
}

func parseExpiry(v any, format string, now time.Time) (time.Time, bool) {
	switch format {
	case "unix":
		if f, err := strconv.ParseFloat(tmpl.Stringify(v), 64); err == nil {
			if f > 1e12 {
				f /= 1000
			}
			return time.Unix(int64(f), 0), true
		}
	case "ttl_seconds":
		if f, err := strconv.ParseFloat(tmpl.Stringify(v), 64); err == nil {
			return now.Add(time.Duration(f) * time.Second), true
		}
	default:
		if t, err := time.Parse(time.RFC3339, tmpl.Stringify(v)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func cookieValue(setCookies []string, name string) string {
	for _, sc := range setCookies {
		first, _, _ := strings.Cut(sc, ";")
		k, v, ok := strings.Cut(strings.TrimSpace(first), "=")
		if ok && k == name {
			return v
		}
	}
	return ""
}

// jsonPath resolves a dotted path with numeric indices (a.b.0.c).
func jsonPath(doc any, path string) any {
	cur := doc
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		switch c := cur.(type) {
		case map[string]any:
			cur = c[part]
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(c) {
				return nil
			}
			cur = c[i]
		default:
			return nil
		}
	}
	return cur
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
