// Package v1compat converts legacy v1 adapter JSON into supermcp v2
// adapter documents.
//
// The converter never drops data silently: every v1 key it does not
// understand becomes a blocker finding, and every judgement call (category
// merge, region mismatch, manual credential) becomes a review finding.
package v1compat

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/supermcpco/supermcp/pkg/adapter"
	v1 "github.com/supermcpco/supermcp/pkg/adapter/v1"
	"gopkg.in/yaml.v3"
)

// Level classifies a finding.
type Level string

const (
	Info    Level = "info"
	Review  Level = "review"
	Blocker Level = "blocker"
)

// Finding is one converter observation.
type Finding struct {
	Slug    string `json:"slug"`
	Level   Level  `json:"level"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Result is the converted adapter plus findings.
type Result struct {
	Adapter  *adapter.Adapter
	Findings []Finding
}

// HasBlockers reports whether any finding is a blocker.
func (r *Result) HasBlockers() bool {
	for _, f := range r.Findings {
		if f.Level == Blocker {
			return true
		}
	}
	return false
}

// categoryMerge folds v1 singleton and near-duplicate categories into the
// v2 enum.
var categoryMerge = map[string]string{
	"remote":        "productivity",
	"wholesale":     "e-commerce",
	"gaming":        "entertainment",
	"construction":  "operations",
	"field-service": "operations",
	"dms":           "documents",
}

var secretName = regexp.MustCompile(`(?i)(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS$|PWD|CREDENTIAL|SIGNATURE|PRIVATE)`)

type converter struct {
	slug     string
	rw       *rewriter
	findings []Finding
	raw      *yaml.Node // the source JSON as an ordered node
	declared map[string]bool
}

func (c *converter) add(level Level, path, format string, args ...any) {
	c.findings = append(c.findings, Finding{Slug: c.slug, Level: level, Path: path, Message: fmt.Sprintf(format, args...)})
}

// Convert turns one v1 file into a v2 adapter.
func Convert(f v1.File) (*Result, error) {
	src := f.Adapter
	c := &converter{slug: src.Slug, rw: newRewriter(append(append([]string{}, src.RequiredEnvVars...), src.OptionalEnvVars...))}
	rawNode, err := adapter.NodeFromJSON(f.Raw)
	if err != nil {
		return nil, err
	}
	c.raw = rawNode.N

	out := &adapter.Adapter{
		APIVersion: adapter.APIVersion,
		Kind:       adapter.KindName,
	}

	// --- metadata -------------------------------------------------------
	for k := range src.Extra {
		switch k {
		case "version":
			c.add(Info, k, "dropped dead top-level field %q (adapter version is content-addressed)", k)
		default:
			c.add(Blocker, k, "unknown top-level field %q", k)
		}
	}
	region := f.Region
	if src.Region != "" && src.Region != f.Region {
		c.add(Review, "metadata.region", "region field %q disagrees with directory %q; directory wins", src.Region, f.Region)
	}
	category := src.Category
	if merged, ok := categoryMerge[category]; ok {
		c.add(Info, "metadata.category", "category %q merged into %q", category, merged)
		category = merged
	}
	out.Metadata = adapter.Metadata{
		Slug:         src.Slug,
		Name:         src.Name,
		Description:  src.Description,
		Region:       region,
		Category:     category,
		Icon:         src.Icon,
		DocsURL:      src.DocsURL,
		Featured:     src.Featured,
		SelfHostOnly: src.SelfHostOnly,
	}
	if src.Priority != nil {
		out.Metadata.Priority = *src.Priority
	}

	// --- transport ------------------------------------------------------
	switch src.Connector.Type {
	case "REST":
		out.Transport.Type = adapter.TransportHTTP
		out.Transport.BaseURL = c.rw.env(src.Connector.BaseURL)
	case "GRAPHQL":
		out.Transport.Type = adapter.TransportGraphQL
		out.Transport.BaseURL = c.rw.env(src.Connector.BaseURL)
	case "DATABASE":
		out.Transport.Type = adapter.TransportDatabase
		out.Transport.DSN = c.rw.env(src.Connector.BaseURL)
		out.Transport.Driver = driverFromDSN(src.Connector.BaseURL)
		if out.Transport.Driver == "" {
			c.add(Blocker, "transport.driver", "cannot infer database driver from %q", src.Connector.BaseURL)
		}
	case "SOAP":
		out.Transport.Type = adapter.TransportSOAP
		out.Transport.BaseURL = c.rw.env(src.Connector.BaseURL)
	case "MCP":
		out.Transport.Type = adapter.TransportMCP
		out.Transport.BaseURL = c.rw.env(src.Connector.BaseURL)
	default:
		c.add(Blocker, "transport.type", "unknown connector type %q", src.Connector.Type)
	}
	out.Transport.Headers = c.orderedStrings(adapter.MapGet(adapter.MapGet(c.raw, "connector"), "headers"), func(s string) string { return c.rw.env(s) })

	// --- auth -----------------------------------------------------------
	c.convertAuth(src, out)

	// --- healthcheck ----------------------------------------------------
	hcPath := src.Connector.HealthcheckPath
	if src.Connector.HealthPath != "" {
		c.add(Info, "healthcheck", "healthPath (typo in v1) treated as healthcheckPath")
		if hcPath == "" {
			hcPath = src.Connector.HealthPath
		}
	}
	switch {
	case src.Probe != nil:
		hc := &adapter.Healthcheck{Tool: src.Probe.Tool}
		if p := adapter.MapGet(adapter.MapGet(c.raw, "probe"), "params"); p != nil {
			hc.Params = &adapter.Node{N: p}
		}
		if hcPath != "" {
			hc.HTTP = &adapter.HTTPHealthcheck{Method: "GET", Path: c.rw.env(hcPath)}
		}
		out.Healthcheck = hc
	case hcPath != "":
		out.Healthcheck = &adapter.Healthcheck{HTTP: &adapter.HTTPHealthcheck{Method: "GET", Path: c.rw.env(hcPath)}}
	}

	// Instructions are prose for the model, not a template: {{...}} in them
	// (e.g. lemlist's "{{firstName}}") is left exactly as written.
	out.Instructions = src.Instructions

	// --- tools ----------------------------------------------------------
	toolsNode := adapter.MapGet(c.raw, "tools")
	for i, t := range src.Tools {
		var tn *yaml.Node
		if toolsNode != nil && i < len(toolsNode.Content) {
			tn = toolsNode.Content[i]
		}
		out.Tools = append(out.Tools, c.convertTool(t, tn, out.Transport.Type))
	}

	// --- credentials (after scanning every reference) -------------------
	out.Credentials = c.credentials(src)

	for _, name := range c.rw.unknownEnv {
		c.add(Blocker, "placeholders", "unrecognised {{%s}} placeholder", name)
	}

	// Grandfather every lint warning the converted adapter would raise, so
	// the converted catalog passes --strict while new adapters face the full
	// rule set. Errors are never grandfathered.
	issues := adapter.Validate(&adapter.File{Dir: OutputDir(out), Region: out.Metadata.Region, Adapter: out})
	allow := map[string]bool{}
	for _, is := range issues {
		if is.Severity == adapter.SeverityWarning {
			allow[is.Rule] = true
		} else {
			c.add(Blocker, is.Rule, "converted adapter fails validation: %s", is.Message)
		}
	}
	if len(allow) > 0 {
		rules := make([]string, 0, len(allow))
		for r := range allow {
			rules = append(rules, r)
		}
		sort.Strings(rules)
		out.Metadata.Lint = &adapter.Lint{Allow: rules}
	}

	return &Result{Adapter: out, Findings: c.findings}, nil
}

func driverFromDSN(dsn string) string {
	scheme, _, ok := strings.Cut(dsn, "://")
	if !ok {
		if strings.HasSuffix(dsn, ".db") || strings.HasSuffix(dsn, ".sqlite") {
			return "sqlite"
		}
		return ""
	}
	switch strings.ToLower(scheme) {
	case "postgres", "postgresql":
		return "postgres"
	case "mysql", "mariadb":
		return "mysql"
	case "mssql", "sqlserver":
		return "mssql"
	case "oracle":
		return "oracle"
	case "sqlite", "file":
		return "sqlite"
	case "mongodb", "mongodb+srv":
		return "mongodb"
	}
	return ""
}

// orderedStrings converts a JSON object node of strings into an ordered
// map, applying fn to each value.
func (c *converter) orderedStrings(n *yaml.Node, fn func(string) string) adapter.OrderedMap[string] {
	m := adapter.NewOrderedMap[string]()
	if n == nil || n.Kind != yaml.MappingNode {
		return m
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		m.Set(n.Content[i].Value, fn(n.Content[i+1].Value))
	}
	return m
}

func (c *converter) credentials(src *v1.Adapter) adapter.OrderedMap[adapter.Credential] {
	creds := adapter.NewOrderedMap[adapter.Credential]()
	add := func(name string, required bool) {
		cr := adapter.Credential{Required: required, Secret: secretName.MatchString(name)}
		if !c.rw.envUsed[name] {
			cr.Usage = "manual"
			c.add(Review, "credentials."+name, "declared env var is never referenced as {{env.%s}}; marked usage: manual (agent passes it as a tool parameter)", name)
		}
		creds.Set(name, cr)
	}
	for _, n := range src.RequiredEnvVars {
		add(n, true)
	}
	for _, n := range src.OptionalEnvVars {
		if _, dup := creds.Get(n); dup {
			c.add(Blocker, "credentials."+n, "env var listed as both required and optional")
			continue
		}
		add(n, false)
	}
	// Referenced but undeclared: v1 left the placeholder unresolved when the
	// operator had not set it, which in practice meant "optional".
	var missing []string
	for name := range c.rw.envUsed {
		if _, ok := creds.Get(name); !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		creds.Set(name, adapter.Credential{Required: false, Secret: secretName.MatchString(name)})
		c.add(Review, "credentials."+name, "{{env.%s}} is referenced but was not declared; added as optional credential", name)
	}
	return creds
}

// ---------------------------------------------------------------------------
// auth

func (c *converter) convertAuth(src *v1.Adapter, out *adapter.Adapter) {
	cfg := src.Connector.AuthConfig
	cfgNode := adapter.MapGet(adapter.MapGet(c.raw, "connector"), "authConfig")
	str := func(k string) string {
		v, _ := cfg[k].(string)
		return c.rw.env(v)
	}
	has := func(k string) bool { _, ok := cfg[k]; return ok }
	known := map[string]bool{}
	use := func(keys ...string) {
		for _, k := range keys {
			known[k] = true
		}
	}
	a := &out.Auth

	switch src.Connector.AuthType {
	case "NONE", "":
		a.Type = adapter.AuthNone
	case "BEARER_TOKEN":
		a.Type = adapter.AuthBearer
		a.Token = str("token")
		use("token")
	case "API_KEY":
		a.Type = adapter.AuthAPIKey
		a.In = "header"
		a.Name = str("headerName")
		if a.Name == "" {
			a.Name = "X-API-Key"
		}
		a.Value = str("apiKey")
		a.ExtraHeaders = c.orderedStrings(adapter.MapGet(cfgNode, "extraHeaders"), c.rw.env)
		use("headerName", "apiKey", "extraHeaders")
		if len(src.RequiredEnvVars) == 0 {
			a.Optional = true
			c.add(Review, "auth.optional", "API_KEY auth with no required env vars; marked optional (works unauthenticated, key upgrades limits)")
		}
	case "BASIC_AUTH", "BASIC":
		a.Type = adapter.AuthBasic
		a.Username, a.Password = str("username"), str("password")
		use("username", "password")
	case "QUERY_AUTH":
		a.Type = adapter.AuthQuery
		a.Params = c.orderedStrings(cfgNode, c.rw.env)
		for k := range cfg {
			known[k] = true
		}
	case "OAUTH2":
		a.Type = adapter.AuthOAuth2
		a.ClientID, a.ClientSecret, a.TokenURL, a.AuthorizationURL = str("clientId"), str("clientSecret"), str("tokenUrl"), str("authorizationUrl")
		a.RefreshToken = str("refreshToken")
		switch g := str("grant"); {
		case g != "":
			a.Grant = g
		case a.RefreshToken != "":
			a.Grant = "refresh_token"
		case a.AuthorizationURL != "":
			a.Grant = "authorization_code"
		default:
			a.Grant = "client_credentials"
		}
		if a.ClientID == "" && a.ClientSecret == "" && a.TokenURL == "" {
			c.add(Blocker, "auth", "OAUTH2 adapter has no usable authConfig; author it by hand")
		}
		a.Scopes = scopes(cfg["scopes"], cfg["scope"])
		if m := str("tokenAuthMethod"); m != "" {
			a.ClientAuth = m
		}
		if h, p := str("headerName"), str("tokenPrefix"); h != "" || p != "" {
			a.Inject = &adapter.Inject{Header: h, Prefix: p}
		}
		a.ExtraHeaders = c.orderedStrings(adapter.MapGet(cfgNode, "extraHeaders"), c.rw.env)
		use("clientId", "clientSecret", "tokenUrl", "authorizationUrl", "refreshToken", "grant", "scopes", "scope", "tokenAuthMethod", "headerName", "tokenPrefix", "extraHeaders")
	case "OAUTH1":
		a.Type = adapter.AuthOAuth1
		a.ConsumerKey, a.ConsumerSecret = str("consumerKey"), str("consumerSecret")
		a.Token, a.TokenSecret = str("token"), str("tokenSecret")
		use("consumerKey", "consumerSecret", "token", "tokenSecret")
	case "HMAC":
		a.Type = adapter.AuthHMAC
		sig, _ := cfg["signature"].(map[string]any)
		sigNode := adapter.MapGet(cfgNode, "signature")
		s := func(k string) string { v, _ := sig[k].(string); return c.rw.env(v) }
		a.Algorithm, a.Encoding, a.Secret = s("algorithm"), s("encoding"), s("secret")
		a.SignatureHeader, a.TimestampHeader = s("headerName"), s("timestampHeader")
		// v1 stored the template with literal backslash-n; the engine unescaped it.
		tmpl := strings.ReplaceAll(s("template"), `\n`, "\n")
		a.StringToSign = c.rw.inline(tmpl, "req")
		a.ExtraHeaders = c.orderedStrings(adapter.MapGet(sigNode, "extraHeaders"), c.rw.env)
		for k := range sig {
			switch k {
			case "algorithm", "encoding", "secret", "template", "headerName", "timestampHeader", "extraHeaders":
			default:
				c.add(Blocker, "auth.signature."+k, "unknown HMAC signature key %q", k)
			}
		}
		use("signature")
	case "LOGIN_TOKEN":
		c.convertLogin(cfg, cfgNode, a, known)
	case "CONNECTION_STRING":
		a.Type = adapter.AuthDatabase
		a.Username, a.Password, a.Domain = str("username"), str("password"), str("domain")
		use("username", "password", "domain")
	default:
		c.add(Blocker, "auth.type", "unknown authType %q", src.Connector.AuthType)
	}

	for k := range cfg {
		if !known[k] {
			c.add(Blocker, "auth."+k, "unknown %s authConfig key %q", src.Connector.AuthType, k)
		}
	}
	_ = has
}

func scopes(v ...any) []string {
	for _, x := range v {
		switch s := x.(type) {
		case string:
			if strings.TrimSpace(s) == "" {
				continue
			}
			return strings.Fields(s)
		case []any:
			out := make([]string, 0, len(s))
			for _, e := range s {
				if str, ok := e.(string); ok {
					out = append(out, str)
				}
			}
			return out
		}
	}
	return nil
}

var reCookieTemplate = regexp.MustCompile(`^([^=\s]+)=\$\{token\}$`)

func (c *converter) convertLogin(cfg map[string]any, cfgNode *yaml.Node, a *adapter.Auth, known map[string]bool) {
	a.Type = adapter.AuthLogin
	str := func(k string) string {
		v, _ := cfg[k].(string)
		return c.rw.env(v)
	}
	use := func(keys ...string) {
		for _, k := range keys {
			known[k] = true
		}
	}
	authRewrite := func(s string) string { return c.rw.inline(c.rw.env(s), "auth") }

	// Credentials: username, password, plus any custom key referenced as ${key}.
	a.Credentials = adapter.NewOrderedMap[string]()
	a.Credentials.Set("username", str("username"))
	a.Credentials.Set("password", str("password"))
	use("username", "password")
	if v, ok := cfg["aud"].(string); ok {
		a.Credentials.Set("aud", c.rw.env(v))
		use("aud")
	}
	if v, ok := cfg["otp"].(string); ok {
		a.Credentials.Set("otp", c.rw.env(v))
		use("otp")
	}

	method := strings.ToUpper(str("loginMethod"))
	if method == "" {
		method = "POST"
	}
	req := &adapter.LoginRequest{Method: method, URL: str("loginUrl")}
	req.Headers = c.orderedStrings(adapter.MapGet(cfgNode, "loginHeaders"), authRewrite)
	if body := adapter.MapGet(cfgNode, "loginBody"); body != nil {
		adapter.WalkStrings(body, authRewrite)
		if method == "GET" {
			req.Query = &adapter.Node{N: body}
		} else {
			req.Body = &adapter.Node{N: body}
		}
	}
	if t, ok := cfg["loginBodyTemplate"].(string); ok {
		n, _ := adapter.NodeFromValue(authRewrite(t))
		req.Body = n
		use("loginBodyTemplate")
	}
	a.Request = req
	use("loginMethod", "loginUrl", "loginHeaders", "loginBody")

	// Password hashing (sorare).
	if ph, ok := cfg["passwordHashing"].(map[string]any); ok {
		scheme, _ := ph["scheme"].(string)
		outp, _ := ph["outputParam"].(string)
		p := adapter.Preprocess{Kind: scheme, Input: "password", Output: outp}
		if ss, ok := ph["saltSource"].(map[string]any); ok {
			salt := &adapter.SaltSource{}
			switch ss["type"] {
			case "fetch":
				m, _ := ss["method"].(string)
				u, _ := ss["url"].(string)
				salt.Request = &adapter.LoginRequest{Method: strings.ToUpper(m), URL: authRewrite(u)}
				if hdr, ok := ss["headers"].(map[string]any); ok {
					salt.Request.Headers = adapter.NewOrderedMap[string]()
					for k, v := range hdr {
						if vs, ok := v.(string); ok {
							salt.Request.Headers.Set(k, authRewrite(vs))
						}
					}
				}
				rp, _ := ss["responsePath"].(string)
				salt.JSONPath = rp
			case "static":
				v, _ := ss["value"].(string)
				salt.Value = v
			}
			p.Salt = salt
		}
		a.Preprocess = []adapter.Preprocess{p}
		use("passwordHashing")
	}

	// Token source.
	ts := &adapter.TokenSource{From: "body", JSONPath: str("tokenJsonPath")}
	if src, _ := cfg["tokenSource"].(string); src == "cookie" {
		ts.From = "setCookie"
		ts.CookieName = str("cookieName")
	}
	a.TokenSource = ts
	use("tokenSource", "cookieName", "tokenJsonPath")

	// Injection.
	header := str("headerName")
	template := str("headerTemplate")
	inj := &adapter.Inject{}
	switch {
	case strings.EqualFold(header, "Cookie") && reCookieTemplate.MatchString(template):
		inj.Cookie = reCookieTemplate.FindStringSubmatch(template)[1]
	case template != "":
		inj.Header = header
		if inj.Header == "" {
			inj.Header = "Authorization"
		}
		inj.Template = c.rw.inline(template, "auth")
	default:
		inj.Header = header
		if inj.Header == "" {
			inj.Header = "Authorization"
		}
		inj.Prefix = "Bearer"
	}
	a.Inject = inj
	a.ExtraHeaders = c.orderedStrings(adapter.MapGet(cfgNode, "extraHeaders"), authRewrite)
	use("headerName", "headerTemplate", "extraHeaders")

	// Expiry.
	exp := &adapter.Expiry{JSONPath: str("expiryJsonPath"), Format: str("expiryFormat")}
	if v, ok := numberOf(cfg["tokenTTLSeconds"]); ok {
		exp.TTL = adapter.Duration(time.Duration(v) * time.Second)
	}
	if v, ok := numberOf(cfg["proactiveRefreshSeconds"]); ok {
		exp.RefreshBefore = adapter.Duration(time.Duration(v) * time.Second)
	}
	if v, ok := cfg["refreshOn401"].(bool); ok {
		exp.RefreshOn401 = &v
	}
	a.Expiry = exp
	use("expiryJsonPath", "expiryFormat", "tokenTTLSeconds", "proactiveRefreshSeconds", "refreshOn401", "audJsonPath")
}

func numberOf(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// tools

func (c *converter) convertTool(t v1.Tool, tn *yaml.Node, transport adapter.TransportType) adapter.Tool {
	path := "tools." + t.Name
	out := adapter.Tool{Name: t.Name, Description: t.Description}
	if t.UseProxy {
		tr := true
		out.Proxy = &tr
	}

	// Input schema, order preserved.
	if in := adapter.MapGet(tn, "parameters"); in != nil {
		out.Input = &adapter.Node{N: in}
	} else {
		n, _ := adapter.NodeFromJSON([]byte(`{"type":"object","properties":{}}`))
		out.Input = n
	}
	if o := adapter.MapGet(tn, "outputSchema"); o != nil {
		out.Output = &adapter.Node{N: o}
	}
	c.declared = map[string]bool{}
	for _, k := range adapter.MapKeys(adapter.MapGet(out.Input.N, "properties")) {
		c.declared[k] = true
	}

	m := t.EndpointMapping
	mn := adapter.MapGet(tn, "endpointMapping")
	op := &out.Operation

	switch {
	case m.Method == "static":
		op.Kind = "static"
		n, _ := adapter.NodeFromValue(m.StaticResponse)
		op.Value = n
		if m.Path != "" && m.Path != "/" {
			c.add(Info, path+".operation", "static tool had path %q; dropped", m.Path)
		}
	case transport == adapter.TransportGraphQL:
		switch m.Method {
		case "query", "mutation":
			op.Kind = m.Method
		default:
			c.add(Blocker, path+".operation.kind", "GraphQL tool with method %q", m.Method)
		}
		op.Document = c.rw.env(m.Path)
		op.Variables = c.mergeVars(mn)
	case transport == adapter.TransportDatabase:
		switch m.Method {
		case "query":
			op.Kind = "sql"
			stmt := c.rw.env(m.Path)
			if whole := reInline.FindStringSubmatch(stmt); whole != nil && whole[0] == stmt {
				op.Statement = "{{params." + whole[1] + " | raw}}"
			} else {
				op.Statement = c.rw.inline(stmt, "params")
			}
		case "mongo_schema":
			op.Kind = "schema"
		default:
			c.add(Blocker, path+".operation.kind", "database tool with method %q", m.Method)
		}
	default: // http, soap, mcp
		op.Method = strings.ToUpper(m.Method)
		switch op.Method {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		default:
			c.add(Blocker, path+".operation.method", "unknown HTTP method %q", m.Method)
		}
		p, undeclared := c.rw.path(m.Path, c.declared)
		op.Path = p
		for _, u := range undeclared {
			c.add(Review, path+".operation.path", "path segment {%s} is not a declared parameter; left verbatim", u)
		}
		if q := adapter.MapGet(mn, "queryParams"); q != nil {
			adapter.WalkStrings(q, c.rw.value)
			op.Query = &adapter.Node{N: q}
		}
		op.Headers = c.orderedStrings(adapter.MapGet(mn, "headers"), c.rw.value)
		switch {
		case m.BodyTemplate != "":
			n, _ := adapter.NodeFromValue(c.rw.value(m.BodyTemplate))
			op.Body = &adapter.Body{Encoding: "raw", Value: n}
			// v1 parsed the rendered template as JSON and sent it as JSON, so
			// the raw body needs the media type stated explicitly.
			if !hasHeader(op.Headers, "content-type") {
				op.Headers.Set("Content-Type", "application/json")
			}
			c.add(Review, path+".operation.body", "bodyTemplate converted to encoding: raw with Content-Type: application/json")
		case adapter.MapGet(mn, "bodyMapping") != nil:
			b := adapter.MapGet(mn, "bodyMapping")
			adapter.WalkStrings(b, c.rw.value)
			enc := ""
			switch m.BodyEncoding {
			case "":
			case "form-urlencoded":
				enc = "form"
			default:
				c.add(Blocker, path+".operation.body.encoding", "unknown bodyEncoding %q", m.BodyEncoding)
			}
			op.Body = &adapter.Body{Encoding: enc, Value: &adapter.Node{N: b}}
		}
	}

	// Unknown mapping keys.
	for _, k := range adapter.MapKeys(mn) {
		switch k {
		case "method", "path", "queryParams", "bodyMapping", "headers", "bodyEncoding", "bodyTemplate", "staticResponse", "exposeHeaders":
		default:
			c.add(Blocker, path+".operation."+k, "unknown endpointMapping key %q", k)
		}
	}

	// Response.
	var resp adapter.Response
	if len(m.ExposeHeaders) > 0 {
		resp.ExposeHeaders = m.ExposeHeaders
	}
	if len(t.ResponseMapping) > 0 {
		var rm struct {
			Transform *struct {
				Mode       string `json:"mode"`
				Expression string `json:"expression"`
			} `json:"transform"`
			CacheTTL float64 `json:"cacheTtl"`
		}
		var generic map[string]any
		_ = json.Unmarshal(t.ResponseMapping, &generic)
		if err := json.Unmarshal(t.ResponseMapping, &rm); err != nil {
			c.add(Blocker, path+".response", "cannot parse responseMapping: %v", err)
		}
		for k := range generic {
			if k != "transform" && k != "cacheTtl" {
				c.add(Blocker, path+".response."+k, "unknown responseMapping key %q", k)
			}
		}
		if rm.Transform != nil {
			if rm.Transform.Mode != "" && rm.Transform.Mode != "jmespath" {
				c.add(Blocker, path+".response.transform", "unsupported transform mode %q", rm.Transform.Mode)
			}
			resp.Transform = &adapter.Transform{JMESPath: rm.Transform.Expression}
		}
		if rm.CacheTTL > 0 {
			resp.Cache = adapter.Duration(time.Duration(rm.CacheTTL) * time.Second)
		}
	}
	if resp.Transform != nil || resp.Cache != 0 || len(resp.ExposeHeaders) > 0 {
		out.Response = &resp
	}
	return out
}

// mergeVars builds GraphQL variables from queryParams and bodyMapping.
func (c *converter) mergeVars(mn *yaml.Node) *adapter.Node {
	merged := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, key := range []string{"queryParams", "bodyMapping"} {
		src := adapter.MapGet(mn, key)
		if src == nil || src.Kind != yaml.MappingNode {
			continue
		}
		adapter.WalkStrings(src, c.rw.value)
		merged.Content = append(merged.Content, src.Content...)
	}
	if len(merged.Content) == 0 {
		return nil
	}
	return &adapter.Node{N: merged}
}

// ConvertAll converts every file and returns results in input order. It
// also grandfathers cross-catalog warnings (duplicate tool names between a
// sandbox and its production adapter) that a single-adapter pass cannot
// see.
func ConvertAll(files []v1.File) ([]*Result, error) {
	results := make([]*Result, 0, len(files))
	var v2 []*adapter.File
	for _, f := range files {
		r, err := Convert(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, err)
		}
		results = append(results, r)
		v2 = append(v2, &adapter.File{Dir: OutputDir(r.Adapter), Region: r.Adapter.Metadata.Region, Adapter: r.Adapter})
	}
	byFile := map[string]*Result{}
	for _, r := range results {
		byFile[OutputDir(r.Adapter)+"/"+adapter.FileName] = r
	}
	for _, is := range adapter.ValidateAll(v2) {
		if is.Severity != adapter.SeverityWarning || is.Rule != "tool-name-unique-catalog" {
			continue
		}
		for _, file := range []string{is.File, is.Related} {
			r := byFile[file]
			if r == nil {
				continue
			}
			if r.Adapter.Metadata.Lint == nil {
				r.Adapter.Metadata.Lint = &adapter.Lint{}
			}
			if !contains(r.Adapter.Metadata.Lint.Allow, is.Rule) {
				r.Adapter.Metadata.Lint.Allow = append(r.Adapter.Metadata.Lint.Allow, is.Rule)
				sort.Strings(r.Adapter.Metadata.Lint.Allow)
			}
		}
	}
	return results, nil
}

// hasHeader reports whether the map already names a header, whatever its
// casing.
func hasHeader(m adapter.OrderedMap[string], name string) bool {
	for _, k := range m.Keys {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// OutputDir is where a converted adapter lives relative to the adapters
// root.
func OutputDir(a *adapter.Adapter) string {
	return a.Metadata.Region + "/" + url.PathEscape(a.Metadata.Slug)
}
