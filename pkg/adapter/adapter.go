// Package adapter defines the supermcp adapter format (apiVersion
// supermcp.dev/v2), loads and validates adapter documents, and computes their
// content hash.
//
// An adapter is a pre-built connector: one upstream (transport + auth) and a
// list of tools. Free-form structures that come from JSON Schema or request
// templates are kept as yaml.Node so that authoring order survives a
// round trip; everything else is typed.
package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "supermcp.dev/v2"
	KindName   = "Adapter"
	SchemaURL  = "https://supermcp.dev/schema/adapter/v2.json"
)

// Adapter is one adapter document.
type Adapter struct {
	APIVersion   string                 `yaml:"apiVersion" json:"apiVersion"`
	Kind         string                 `yaml:"kind" json:"kind"`
	Metadata     Metadata               `yaml:"metadata" json:"metadata"`
	Credentials  OrderedMap[Credential] `yaml:"credentials,omitempty" json:"credentials,omitempty,omitzero"`
	Transport    Transport              `yaml:"transport" json:"transport"`
	Auth         Auth                   `yaml:"auth" json:"auth"`
	Healthcheck  *Healthcheck           `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty,omitzero"`
	Instructions string                 `yaml:"instructions,omitempty" json:"instructions,omitempty,omitzero"`
	Tools        []Tool                 `yaml:"tools" json:"tools"`
}

// Metadata is the catalog-facing description of an adapter.
type Metadata struct {
	Slug         string `yaml:"slug" json:"slug"`
	Name         string `yaml:"name" json:"name"`
	Description  string `yaml:"description" json:"description"`
	Region       string `yaml:"region" json:"region"`
	Category     string `yaml:"category" json:"category"`
	Icon         string `yaml:"icon" json:"icon"`
	DocsURL      string `yaml:"docsUrl" json:"docsUrl"`
	Priority     int    `yaml:"priority,omitempty" json:"priority,omitempty,omitzero"`
	Featured     bool   `yaml:"featured,omitempty" json:"featured,omitempty,omitzero"`
	SelfHostOnly bool   `yaml:"selfHostOnly,omitempty" json:"selfHostOnly,omitempty,omitzero"`
	Lint         *Lint  `yaml:"lint,omitempty" json:"lint,omitempty,omitzero"`
}

// Lint carries per-adapter linter exemptions (rule ids).
type Lint struct {
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty,omitzero"`
}

// Credential declares one environment variable the adapter needs.
type Credential struct {
	Required    bool   `yaml:"required" json:"required"`
	Secret      bool   `yaml:"secret,omitempty" json:"secret,omitempty,omitzero"`
	Usage       string `yaml:"usage,omitempty" json:"usage,omitempty,omitzero"` // template (default) | manual
	Description string `yaml:"description,omitempty" json:"description,omitempty,omitzero"`
}

// Transport describes how to reach the upstream.
type Transport struct {
	Type      TransportType      `yaml:"type" json:"type"`
	BaseURL   string             `yaml:"baseUrl,omitempty" json:"baseUrl,omitempty,omitzero"`
	DSN       string             `yaml:"dsn,omitempty" json:"dsn,omitempty,omitzero"`       // database
	Driver    string             `yaml:"driver,omitempty" json:"driver,omitempty,omitzero"` // database: postgres|mysql|mssql|oracle|sqlite|mongodb
	Headers   OrderedMap[string] `yaml:"headers,omitempty" json:"headers,omitempty,omitzero"`
	Timeout   Duration           `yaml:"timeout,omitempty" json:"timeout,omitempty,omitzero"`
	RateLimit *RateLimit         `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty,omitzero"`
	Proxy     bool               `yaml:"proxy,omitempty" json:"proxy,omitempty,omitzero"`
}

// TransportType enumerates upstream protocols.
type TransportType string

const (
	TransportHTTP     TransportType = "http"
	TransportGraphQL  TransportType = "graphql"
	TransportDatabase TransportType = "database"
	TransportSOAP     TransportType = "soap"
	TransportMCP      TransportType = "mcp"
)

// RateLimit is a token-bucket limit applied by the gateway before calling
// upstream.
type RateLimit struct {
	RPS   float64 `yaml:"rps" json:"rps"`
	Burst int     `yaml:"burst,omitempty" json:"burst,omitempty,omitzero"`
}

// AuthType enumerates upstream authentication schemes.
type AuthType string

const (
	AuthNone     AuthType = "none"
	AuthAPIKey   AuthType = "apiKey"
	AuthBearer   AuthType = "bearer"
	AuthBasic    AuthType = "basic"
	AuthQuery    AuthType = "query"
	AuthOAuth2   AuthType = "oauth2"
	AuthOAuth1   AuthType = "oauth1"
	AuthLogin    AuthType = "login"
	AuthHMAC     AuthType = "hmac"
	AuthDatabase AuthType = "database"
	AuthWSSec    AuthType = "wsSecurity"
	AuthMTLS     AuthType = "mtls"
)

// Auth is a discriminated union on Type. Only the fields for the chosen
// type may be set; the validator enforces this.
type Auth struct {
	Type     AuthType `yaml:"type" json:"type"`
	Optional bool     `yaml:"optional,omitempty" json:"optional,omitempty,omitzero"` // send unauthenticated when no credential is set

	// apiKey
	In    string `yaml:"in,omitempty" json:"in,omitempty,omitzero"` // header | query | cookie
	Name  string `yaml:"name,omitempty" json:"name,omitempty,omitzero"`
	Value string `yaml:"value,omitempty" json:"value,omitempty,omitzero"`

	// bearer
	Token  string `yaml:"token,omitempty" json:"token,omitempty,omitzero"`
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty,omitzero"`
	Header string `yaml:"header,omitempty" json:"header,omitempty,omitzero"`

	// basic, database
	Username string `yaml:"username,omitempty" json:"username,omitempty,omitzero"`
	Password string `yaml:"password,omitempty" json:"password,omitempty,omitzero"`
	Domain   string `yaml:"domain,omitempty" json:"domain,omitempty,omitzero"` // database (NTLM)

	// query
	Params OrderedMap[string] `yaml:"params,omitempty" json:"params,omitempty,omitzero"`

	// oauth2
	Grant            string             `yaml:"grant,omitempty" json:"grant,omitempty,omitzero"` // client_credentials | refresh_token | authorization_code
	ClientID         string             `yaml:"clientId,omitempty" json:"clientId,omitempty,omitzero"`
	ClientSecret     string             `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty,omitzero"`
	TokenURL         string             `yaml:"tokenUrl,omitempty" json:"tokenUrl,omitempty,omitzero"`
	AuthorizationURL string             `yaml:"authorizationUrl,omitempty" json:"authorizationUrl,omitempty,omitzero"`
	Scopes           []string           `yaml:"scopes,omitempty" json:"scopes,omitempty,omitzero"`
	ClientAuth       string             `yaml:"clientAuth,omitempty" json:"clientAuth,omitempty,omitzero"` // basic | body
	RefreshToken     string             `yaml:"refreshToken,omitempty" json:"refreshToken,omitempty,omitzero"`
	ExtraTokenParams OrderedMap[string] `yaml:"extraTokenParams,omitempty" json:"extraTokenParams,omitempty,omitzero"`

	// oauth1
	ConsumerKey    string `yaml:"consumerKey,omitempty" json:"consumerKey,omitempty,omitzero"`
	ConsumerSecret string `yaml:"consumerSecret,omitempty" json:"consumerSecret,omitempty,omitzero"`
	TokenSecret    string `yaml:"tokenSecret,omitempty" json:"tokenSecret,omitempty,omitzero"`
	Signature      string `yaml:"signature,omitempty" json:"signature,omitempty,omitzero"` // HMAC-SHA1 (default)

	// login
	Request     *LoginRequest      `yaml:"request,omitempty" json:"request,omitempty,omitzero"`
	Credentials OrderedMap[string] `yaml:"credentials,omitempty" json:"credentials,omitempty,omitzero"` // addressable as {{auth.<key>}}
	Preprocess  []Preprocess       `yaml:"preprocess,omitempty" json:"preprocess,omitempty,omitzero"`
	TokenSource *TokenSource       `yaml:"tokenSource,omitempty" json:"tokenSource,omitempty,omitzero"`
	Expiry      *Expiry            `yaml:"expiry,omitempty" json:"expiry,omitempty,omitzero"`

	// hmac
	Algorithm       string `yaml:"algorithm,omitempty" json:"algorithm,omitempty,omitzero"` // sha256 | sha1 | sha512
	Encoding        string `yaml:"encoding,omitempty" json:"encoding,omitempty,omitzero"`   // hex | base64
	Secret          string `yaml:"secret,omitempty" json:"secret,omitempty,omitzero"`
	StringToSign    string `yaml:"stringToSign,omitempty" json:"stringToSign,omitempty,omitzero"`
	SignatureHeader string `yaml:"signatureHeader,omitempty" json:"signatureHeader,omitempty,omitzero"`
	TimestampHeader string `yaml:"timestampHeader,omitempty" json:"timestampHeader,omitempty,omitzero"`
	TimestampFormat string `yaml:"timestampFormat,omitempty" json:"timestampFormat,omitempty,omitzero"` // unix (default) | unix_ms | iso8601

	// mtls
	Cert string `yaml:"cert,omitempty" json:"cert,omitempty,omitzero"`
	Key  string `yaml:"key,omitempty" json:"key,omitempty,omitzero"`
	CA   string `yaml:"ca,omitempty" json:"ca,omitempty,omitzero"`

	// shared by oauth2, login, hmac
	Inject       *Inject            `yaml:"inject,omitempty" json:"inject,omitempty,omitzero"`
	ExtraHeaders OrderedMap[string] `yaml:"extraHeaders,omitempty" json:"extraHeaders,omitempty,omitzero"`
}

// Inject says where the obtained token goes on each request.
type Inject struct {
	Header   string `yaml:"header,omitempty" json:"header,omitempty,omitzero"`     // header name
	Prefix   string `yaml:"prefix,omitempty" json:"prefix,omitempty,omitzero"`     // e.g. "Bearer"
	Template string `yaml:"template,omitempty" json:"template,omitempty,omitzero"` // full header value, e.g. "id={{auth.token}}"
	Cookie   string `yaml:"cookie,omitempty" json:"cookie,omitempty,omitzero"`     // send as cookie name=token
}

// LoginRequest describes the request that obtains a session token.
type LoginRequest struct {
	Method  string             `yaml:"method" json:"method"`
	URL     string             `yaml:"url" json:"url"`
	Headers OrderedMap[string] `yaml:"headers,omitempty" json:"headers,omitempty,omitzero"`
	Query   *Node              `yaml:"query,omitempty" json:"query,omitempty,omitzero"` // GET logins carry the form in the query
	Body    *Node              `yaml:"body,omitempty" json:"body,omitempty,omitzero"`
}

// Preprocess transforms a credential before the login request is sent.
type Preprocess struct {
	Kind   string      `yaml:"kind" json:"kind"` // bcrypt
	Input  string      `yaml:"input" json:"input"`
	Output string      `yaml:"output" json:"output"`
	Salt   *SaltSource `yaml:"salt,omitempty" json:"salt,omitempty,omitzero"`
}

// SaltSource fetches or fixes a bcrypt salt.
type SaltSource struct {
	Value    string        `yaml:"value,omitempty" json:"value,omitempty,omitzero"`
	Request  *LoginRequest `yaml:"request,omitempty" json:"request,omitempty,omitzero"`
	JSONPath string        `yaml:"jsonPath,omitempty" json:"jsonPath,omitempty,omitzero"`
}

// TokenSource says where the token is in the login response.
type TokenSource struct {
	From       string `yaml:"from" json:"from"` // body | setCookie
	JSONPath   string `yaml:"jsonPath,omitempty" json:"jsonPath,omitempty,omitzero"`
	CookieName string `yaml:"cookieName,omitempty" json:"cookieName,omitempty,omitzero"`
}

// Expiry controls token lifetime and refresh.
type Expiry struct {
	JSONPath      string   `yaml:"jsonPath,omitempty" json:"jsonPath,omitempty,omitzero"`
	Format        string   `yaml:"format,omitempty" json:"format,omitempty,omitzero"` // iso8601 | unix | ttl_seconds
	TTL           Duration `yaml:"ttl,omitempty" json:"ttl,omitempty,omitzero"`
	RefreshBefore Duration `yaml:"refreshBefore,omitempty" json:"refreshBefore,omitempty,omitzero"`
	RefreshOn401  *bool    `yaml:"refreshOn401,omitempty" json:"refreshOn401,omitempty,omitzero"`
}

// Healthcheck is what `supermcp adapter probe` and the catalog probe call.
type Healthcheck struct {
	Tool   string           `yaml:"tool,omitempty" json:"tool,omitempty,omitzero"`
	Params *Node            `yaml:"params,omitempty" json:"params,omitempty,omitzero"`
	HTTP   *HTTPHealthcheck `yaml:"http,omitempty" json:"http,omitempty,omitzero"`
}

// HTTPHealthcheck probes a raw path instead of a tool.
type HTTPHealthcheck struct {
	Method string `yaml:"method,omitempty" json:"method,omitempty,omitzero"`
	Path   string `yaml:"path" json:"path"`
	Status []int  `yaml:"status,omitempty" json:"status,omitempty,omitzero"`
}

// Tool is one MCP tool.
type Tool struct {
	Name        string       `yaml:"name" json:"name"`
	Description string       `yaml:"description" json:"description"`
	Input       *Node        `yaml:"input" json:"input"` // JSON Schema subset
	Output      *Node        `yaml:"output,omitempty" json:"output,omitempty,omitzero"`
	Annotations *Annotations `yaml:"annotations,omitempty" json:"annotations,omitempty,omitzero"`
	Timeout     Duration     `yaml:"timeout,omitempty" json:"timeout,omitempty,omitzero"`
	RateLimit   *RateLimit   `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty,omitzero"`
	Proxy       *bool        `yaml:"proxy,omitempty" json:"proxy,omitempty,omitzero"`
	Operation   Operation    `yaml:"operation" json:"operation"`
	Response    *Response    `yaml:"response,omitempty" json:"response,omitempty,omitzero"`
}

// Annotations are MCP tool hints. Unset fields are derived at runtime.
type Annotations struct {
	Title           string `yaml:"title,omitempty" json:"title,omitempty,omitzero"`
	ReadOnlyHint    *bool  `yaml:"readOnlyHint,omitempty" json:"readOnlyHint,omitempty,omitzero"`
	DestructiveHint *bool  `yaml:"destructiveHint,omitempty" json:"destructiveHint,omitempty,omitzero"`
	IdempotentHint  *bool  `yaml:"idempotentHint,omitempty" json:"idempotentHint,omitempty,omitzero"`
	OpenWorldHint   *bool  `yaml:"openWorldHint,omitempty" json:"openWorldHint,omitempty,omitzero"`
}

// Operation is a union keyed by Transport.Type.
type Operation struct {
	// http
	Method  string             `yaml:"method,omitempty" json:"method,omitempty,omitzero"`
	Path    string             `yaml:"path,omitempty" json:"path,omitempty,omitzero"`
	Query   *Node              `yaml:"query,omitempty" json:"query,omitempty,omitzero"`
	Headers OrderedMap[string] `yaml:"headers,omitempty" json:"headers,omitempty,omitzero"`
	Body    *Body              `yaml:"body,omitempty" json:"body,omitempty,omitzero"`

	// graphql: kind query|mutation; database: kind sql|schema; any: kind static
	Kind      string `yaml:"kind,omitempty" json:"kind,omitempty,omitzero"`
	Document  string `yaml:"document,omitempty" json:"document,omitempty,omitzero"`
	Variables *Node  `yaml:"variables,omitempty" json:"variables,omitempty,omitzero"`
	Statement string `yaml:"statement,omitempty" json:"statement,omitempty,omitzero"`
	MaxRows   int    `yaml:"maxRows,omitempty" json:"maxRows,omitempty,omitzero"`
	Value     *Node  `yaml:"value,omitempty" json:"value,omitempty,omitzero"` // static

	// soap
	Action   string `yaml:"action,omitempty" json:"action,omitempty,omitzero"`
	Envelope string `yaml:"envelope,omitempty" json:"envelope,omitempty,omitzero"`

	// mcp
	Tool    string `yaml:"tool,omitempty" json:"tool,omitempty,omitzero"`
	ArgsMap *Node  `yaml:"argsMap,omitempty" json:"argsMap,omitempty,omitzero"`
}

// Body is an HTTP request body template.
type Body struct {
	Encoding string `yaml:"encoding,omitempty" json:"encoding,omitempty,omitzero"` // json (default) | form | multipart | raw
	Value    *Node  `yaml:"value" json:"value"`
}

// Response controls what happens to the upstream response.
type Response struct {
	Transform     *Transform `yaml:"transform,omitempty" json:"transform,omitempty,omitzero"`
	Cache         Duration   `yaml:"cache,omitempty" json:"cache,omitempty,omitzero"`
	ExposeHeaders []string   `yaml:"exposeHeaders,omitempty" json:"exposeHeaders,omitempty,omitzero"`
	MaxBytes      int        `yaml:"maxBytes,omitempty" json:"maxBytes,omitempty,omitzero"`
	FallbackToRaw *bool      `yaml:"fallbackToRaw,omitempty" json:"fallbackToRaw,omitempty,omitzero"`
}

// Transform reshapes the response before it reaches the model.
type Transform struct {
	JMESPath string `yaml:"jmespath" json:"jmespath"`
}

// Duration marshals as a Go duration string ("30s", "1m").
type Duration time.Duration

func (d Duration) IsZero() bool { return d == 0 }

func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

// A duration is written as a string, and a tool definition makes the round
// trip through JSON in the database on every call. Only the writing side
// existed, so any connector whose adapter declared a cache installed
// cleanly and then failed on every call with an unmarshalling error.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// A number is accepted so a definition written before this existed
		// still reads, rather than taking the connector down.
		var n int64
		if err2 := json.Unmarshal(data, &n); err2 == nil {
			*d = Duration(n)
			return nil
		}
		return fmt.Errorf("a duration is a string such as \"30s\" or \"24h\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// String renders the shortest exact form: "720h", "5m", "90s", "1h30m".
func (d Duration) String() string {
	s := time.Duration(d).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q: %w", n.Line, s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", d.String())), nil
}

// OrderedMap is a string-keyed map that keeps insertion order in YAML and
// JSON output. yaml.v3 sorts plain maps, which would scramble header and
// credential order on every round trip.
type OrderedMap[V any] struct {
	Keys   []string
	Values map[string]V
}

func NewOrderedMap[V any]() OrderedMap[V] {
	return OrderedMap[V]{Values: map[string]V{}}
}

func (m *OrderedMap[V]) Set(k string, v V) {
	if m.Values == nil {
		m.Values = map[string]V{}
	}
	if _, ok := m.Values[k]; !ok {
		m.Keys = append(m.Keys, k)
	}
	m.Values[k] = v
}

func (m OrderedMap[V]) Get(k string) (V, bool) {
	v, ok := m.Values[k]
	return v, ok
}

func (m OrderedMap[V]) Len() int { return len(m.Keys) }

func (m OrderedMap[V]) IsZero() bool { return len(m.Keys) == 0 }

func (m OrderedMap[V]) MarshalYAML() (any, error) {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, k := range m.Keys {
		var vn yaml.Node
		if err := vn.Encode(m.Values[k]); err != nil {
			return nil, err
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, &vn)
	}
	return n, nil
}

func (m *OrderedMap[V]) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping", n.Line)
	}
	*m = NewOrderedMap[V]()
	for i := 0; i+1 < len(n.Content); i += 2 {
		var v V
		if err := n.Content[i+1].Decode(&v); err != nil {
			return err
		}
		m.Set(n.Content[i].Value, v)
	}
	return nil
}

func (m OrderedMap[V]) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, k := range m.Keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, _ := jsonMarshal(k)
		vb, err := jsonMarshal(m.Values[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, kb...)
		buf = append(buf, ':')
		buf = append(buf, vb...)
	}
	return append(buf, '}'), nil
}

// UnmarshalJSON decodes a JSON object while keeping key order, so a map
// that round-trips through the database keeps the order it was authored in
// (and keeps its entries at all).
func (m *OrderedMap[V]) UnmarshalJSON(data []byte) error {
	*m = NewOrderedMap[V]()
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected a JSON object, got %v", tok)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected a string key, got %v", keyTok)
		}
		var v V
		if err := dec.Decode(&v); err != nil {
			return err
		}
		m.Set(key, v)
	}
	_, err = dec.Token() // closing brace
	return err
}
