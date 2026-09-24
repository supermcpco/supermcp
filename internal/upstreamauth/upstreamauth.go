// Package upstreamauth turns an adapter's auth block into an
// engine.Authenticator. Credential values arrive already rendered through
// tmpl (env namespace); this package only decides where they go on the
// wire and, for token-based schemes, how tokens are obtained and cached.
package upstreamauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/pkg/adapter"
	"github.com/supermcpco/supermcp/pkg/tmpl"
)

// Token is a cached upstream credential.
type Token struct {
	Access    string
	Refresh   string
	ExpiresAt time.Time
	Extra     map[string]string
}

// TokenStore persists tokens across processes (DB-backed in production;
// MemoryStore for tests and single-node use).
type TokenStore interface {
	Get(ctx context.Context, connectorID string) (*Token, bool, error)
	Put(ctx context.Context, connectorID string, t *Token) error
	Delete(ctx context.Context, connectorID string) error
}

// MemoryStore is an in-process TokenStore.
type MemoryStore struct {
	mu sync.Mutex
	m  map[string]*Token
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{m: map[string]*Token{}} }

func (s *MemoryStore) Get(_ context.Context, id string) (*Token, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[id]
	if !ok {
		return nil, false, nil
	}
	cp := *t
	return &cp, true, nil
}

func (s *MemoryStore) Put(_ context.Context, id string, t *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.m[id] = &cp
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

// Deps are the collaborators an authenticator may need.
type Deps struct {
	HTTP  engine.HTTPDoer // for token endpoints and login requests
	Store TokenStore
	Now   func() time.Time
	// RefreshedRefreshToken is called when an OAuth2 provider rotates the
	// refresh token, so the connector's stored credential can be updated.
	RefreshedRefreshToken func(ctx context.Context, connectorID, newRefreshToken string) error
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Prepare builds the authenticator for a connector and returns vars with
// the auth namespace populated (username, password, domain and login
// credentials), so engines and templates can reference {{auth.*}}.
func Prepare(ctx context.Context, conn *engine.Connector, vars tmpl.Vars, deps Deps) (engine.Authenticator, tmpl.Vars, error) {
	a := conn.Auth
	render := func(s string) (string, error) {
		if s == "" {
			return "", nil
		}
		v, ok, err := tmpl.Render(s, vars, tmpl.Value)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", nil
		}
		return tmpl.Stringify(v), nil
	}
	renderMap := func(m adapter.OrderedMap[string]) (map[string]string, error) {
		out := map[string]string{}
		for _, k := range m.Keys {
			v, err := render(m.Values[k])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			if v != "" {
				out[k] = v
			}
		}
		return out, nil
	}
	if vars.Auth == nil {
		vars.Auth = map[string]string{}
	}
	if deps.Store == nil {
		deps.Store = NewMemoryStore()
	}

	switch a.Type {
	case adapter.AuthNone, "":
		return nil, vars, nil

	case adapter.AuthAPIKey:
		val, err := render(a.Value)
		if err != nil {
			return nil, vars, err
		}
		extra, err := renderMap(a.ExtraHeaders)
		if err != nil {
			return nil, vars, err
		}
		if val == "" {
			if a.Optional {
				return headersOnly(extra), vars, nil
			}
			return nil, vars, errors.New("apiKey auth: credential is not set")
		}
		return &apiKey{in: a.In, name: a.Name, value: a.Prefix + val, extra: extra}, vars, nil

	case adapter.AuthBearer:
		tok, err := render(a.Token)
		if err != nil {
			return nil, vars, err
		}
		if tok == "" && !a.Optional {
			return nil, vars, errors.New("bearer auth: token is not set")
		}
		extra, err := renderMap(a.ExtraHeaders)
		if err != nil {
			return nil, vars, err
		}
		header, prefix := a.Header, a.Prefix
		if header == "" {
			header = "Authorization"
		}
		if prefix == "" && header == "Authorization" {
			prefix = "Bearer"
		}
		if tok == "" {
			return headersOnly(extra), vars, nil
		}
		return &staticHeader{name: header, value: strings.TrimSpace(prefix + " " + tok), extra: extra}, vars, nil

	case adapter.AuthBasic:
		u, err := render(a.Username)
		if err != nil {
			return nil, vars, err
		}
		p, err := render(a.Password)
		if err != nil {
			return nil, vars, err
		}
		vars.Auth["username"], vars.Auth["password"] = u, p
		if u == "" && p == "" {
			if a.Optional {
				return nil, vars, nil
			}
			return nil, vars, errors.New("basic auth: credentials are not set")
		}
		extra, err := renderMap(a.ExtraHeaders)
		if err != nil {
			return nil, vars, err
		}
		return &staticHeader{name: "Authorization", value: "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p)), extra: extra}, vars, nil

	case adapter.AuthDatabase:
		for k, s := range map[string]string{"username": a.Username, "password": a.Password, "domain": a.Domain} {
			v, err := render(s)
			if err != nil {
				return nil, vars, err
			}
			if v != "" {
				vars.Auth[k] = v
			}
		}
		return nil, vars, nil

	case adapter.AuthQuery:
		params, err := renderMap(a.Params)
		if err != nil {
			return nil, vars, err
		}
		if len(params) == 0 && !a.Optional {
			return nil, vars, errors.New("query auth: no parameters set")
		}
		return &queryAuth{params: params, keys: a.Params.Keys}, vars, nil

	case adapter.AuthOAuth2:
		return newOAuth2(ctx, conn, vars, deps, render, renderMap)

	case adapter.AuthHMAC:
		secret, err := render(a.Secret)
		if err != nil {
			return nil, vars, err
		}
		if secret == "" {
			return nil, vars, errors.New("hmac auth: secret is not set")
		}
		extra, err := renderMap(a.ExtraHeaders)
		if err != nil {
			return nil, vars, err
		}
		return &hmacSigner{cfg: a, secret: secret, extra: extra, now: deps.now}, vars, nil

	case adapter.AuthLogin:
		return newLogin(conn, vars, deps, render, renderMap)

	case adapter.AuthOAuth1, adapter.AuthWSSec, adapter.AuthMTLS:
		return nil, vars, fmt.Errorf("auth type %s: %w (planned for M4)", a.Type, engine.ErrUnsupported)
	}
	return nil, vars, fmt.Errorf("unknown auth type %q", a.Type)
}

// --- simple schemes --------------------------------------------------------

type headersOnly map[string]string

func (h headersOnly) Apply(_ context.Context, req *http.Request) error {
	for k, v := range h {
		req.Header.Set(k, v)
	}
	return nil
}

type staticHeader struct {
	name, value string
	extra       map[string]string
}

func (s *staticHeader) Apply(_ context.Context, req *http.Request) error {
	req.Header.Set(s.name, s.value)
	for k, v := range s.extra {
		req.Header.Set(k, v)
	}
	return nil
}

type apiKey struct {
	in, name, value string
	extra           map[string]string
}

func (a *apiKey) Apply(_ context.Context, req *http.Request) error {
	switch a.in {
	case "query":
		q := req.URL.Query()
		q.Set(a.name, a.value)
		req.URL.RawQuery = q.Encode()
	case "cookie":
		req.AddCookie(&http.Cookie{Name: a.name, Value: a.value}) //nolint:gosec // outbound request cookie
	default:
		req.Header.Set(a.name, a.value)
	}
	for k, v := range a.extra {
		req.Header.Set(k, v)
	}
	return nil
}

type queryAuth struct {
	params map[string]string
	keys   []string
}

func (q *queryAuth) Apply(_ context.Context, req *http.Request) error {
	if len(q.params) == 0 {
		return nil
	}
	// Append in authored order without re-encoding what the engine built.
	var sb strings.Builder
	sb.WriteString(req.URL.RawQuery)
	for _, k := range q.keys {
		v, ok := q.params[k]
		if !ok {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(queryEscape(k) + "=" + queryEscape(v))
	}
	req.URL.RawQuery = sb.String()
	return nil
}

func queryEscape(s string) string {
	r := strings.NewReplacer("%", "%25", "&", "%26", "=", "%3D", "+", "%2B", "#", "%23", " ", "+")
	return r.Replace(s)
}
