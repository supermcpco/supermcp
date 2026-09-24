package adapter

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/jmespath-community/go-jmespath"
	"gopkg.in/yaml.v3"
)

// Severity of a validation issue.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Issue is one validation finding. Rule ids are stable and can be listed in
// metadata.lint.allow to suppress a warning for one adapter.
type Issue struct {
	File     string   `json:"file"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Related  string   `json:"related,omitempty"` // other file involved in a cross-adapter issue
	// Field is the dotted path inside one tool definition the issue is
	// about (e.g. "operation.path"), empty when it is about the whole tool.
	Field string `json:"field,omitempty"`
}

// Regions is the closed set of adapter regions (directory names).
var Regions = map[string]bool{
	"be": true, "br": true, "ch": true, "de": true, "dk": true, "es": true, "fr": true, "gb": true,
	"in": true, "intl": true, "it": true, "jp": true, "ng": true, "nl": true, "se": true,
}

// Categories is the closed set of adapter categories.
var Categories = map[string]bool{
	"accounting": true, "analytics": true, "banking": true, "cms": true, "crm": true, "data": true,
	"database": true, "documents": true, "e-commerce": true, "e-signature": true, "email": true,
	"enrichment": true, "entertainment": true, "erp": true, "finance": true, "food": true,
	"forms": true, "government": true, "healthcare": true, "hr": true, "infrastructure": true,
	"itsm": true, "knowledge": true, "logistics": true, "maps": true, "marketing-automation": true,
	"messaging": true, "monitoring": true, "operations": true, "payments": true,
	"productivity": true, "project-management": true, "publishing": true, "real-estate": true,
	"scheduling": true, "social": true, "sports": true, "storage": true, "support": true,
	"time-tracking": true, "transport": true, "travel": true,
}

var (
	reSlug     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	reToolName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	reCredName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	// A name may contain '$': OData parameters are called $top, $filter and
	// $expand, and several adapters expose them under those names.
	rePlaceholder = regexp.MustCompile(`\{\{\s*([a-z]+)\.([A-Za-z0-9_.$]+)(\s*\|[^}]*)?\}\}`)
	reAnyBraces   = regexp.MustCompile(`\{\{`)
)

type validator struct {
	file   string
	a      *Adapter
	allow  map[string]bool
	issues []Issue
}

func (v *validator) errorf(rule, format string, args ...any) {
	v.issues = append(v.issues, Issue{File: v.file, Rule: rule, Severity: SeverityError, Message: fmt.Sprintf(format, args...)})
}

func (v *validator) warnf(rule, format string, args ...any) {
	if v.allow[rule] {
		return
	}
	v.issues = append(v.issues, Issue{File: v.file, Rule: rule, Severity: SeverityWarning, Message: fmt.Sprintf(format, args...)})
}

// Validate checks one adapter. dir is the adapter directory path (used for
// slug-dir and region-dir checks) and may be empty.
func Validate(f *File) []Issue {
	a := f.Adapter
	v := &validator{file: path.Join(f.Dir, FileName), a: a, allow: map[string]bool{}}
	if a.Metadata.Lint != nil {
		for _, r := range a.Metadata.Lint.Allow {
			v.allow[r] = true
		}
	}
	m := a.Metadata

	// --- metadata
	if !reSlug.MatchString(m.Slug) {
		v.errorf("slug-format", "slug %q must be lowercase kebab-case", m.Slug)
	}
	if f.Dir != "" && path.Base(f.Dir) != m.Slug {
		v.errorf("slug-dir", "slug %q does not match directory %q", m.Slug, path.Base(f.Dir))
	}
	if !Regions[m.Region] {
		v.errorf("region-enum", "region %q is not a known region", m.Region)
	}
	if f.Region != "" && f.Region != m.Region {
		v.errorf("region-dir", "region %q does not match directory %q", m.Region, f.Region)
	}
	if !Categories[m.Category] {
		v.errorf("category-enum", "category %q is not a known category", m.Category)
	}
	for _, req := range []struct{ k, val string }{{"name", m.Name}, {"description", m.Description}, {"icon", m.Icon}, {"docsUrl", m.DocsURL}} {
		if strings.TrimSpace(req.val) == "" {
			v.errorf("metadata-required", "metadata.%s is required", req.k)
		}
	}
	if strings.HasPrefix(m.Icon, "http://") {
		v.warnf("icon-https", "icon should be served over https")
	}
	if len(a.Instructions) < 800 {
		v.warnf("instructions-min-800", "instructions are %d chars; 800+ recommended", len(a.Instructions))
	}

	// --- credentials
	declared := map[string]bool{}
	for _, name := range a.Credentials.Keys {
		c := a.Credentials.Values[name]
		if !reCredName.MatchString(name) {
			v.errorf("credential-name", "credential %q must be UPPER_SNAKE_CASE", name)
		}
		if c.Usage != "" && c.Usage != "template" && c.Usage != "manual" {
			v.errorf("credential-usage", "credential %q usage must be template or manual", name)
		}
		declared[name] = true
	}

	// --- transport
	switch a.Transport.Type {
	case TransportHTTP, TransportGraphQL, TransportSOAP, TransportMCP:
		if a.Transport.BaseURL == "" {
			v.errorf("transport-baseurl", "transport.baseUrl is required for %s", a.Transport.Type)
		}
		if a.Transport.DSN != "" || a.Transport.Driver != "" {
			v.errorf("transport-fields", "dsn/driver are only valid for database transports")
		}
	case TransportDatabase:
		if a.Transport.DSN == "" {
			v.errorf("transport-dsn", "transport.dsn is required for database")
		}
		switch a.Transport.Driver {
		case "postgres", "mysql", "mssql", "oracle", "sqlite", "mongodb":
		default:
			v.errorf("transport-driver", "transport.driver %q is not supported", a.Transport.Driver)
		}
	default:
		v.errorf("transport-type", "transport.type %q is not supported", a.Transport.Type)
	}

	// --- auth
	v.validateAuth(declared)

	// --- healthcheck
	toolNames := map[string]bool{}
	for _, t := range a.Tools {
		toolNames[t.Name] = true
	}
	if hc := a.Healthcheck; hc != nil {
		if hc.Tool == "" && hc.HTTP == nil {
			v.errorf("healthcheck-empty", "healthcheck must name a tool or an http path")
		}
		if hc.Tool != "" && !toolNames[hc.Tool] {
			v.errorf("healthcheck-tool", "healthcheck.tool %q is not a tool of this adapter", hc.Tool)
		}
	} else {
		v.warnf("healthcheck-present", "no healthcheck declared")
	}

	// --- tools
	if len(a.Tools) == 0 {
		v.errorf("tools-empty", "at least one tool is required")
	}
	prefix := strings.ReplaceAll(m.Slug, "-", "_") + "_"
	seen := map[string]bool{}
	envUsed := map[string]bool{}
	for i, t := range a.Tools {
		loc := fmt.Sprintf("tools[%d] %s", i, t.Name)
		if !reToolName.MatchString(t.Name) {
			v.errorf("tool-name-format", "%s: tool name must be lowercase snake_case", loc)
		}
		if seen[t.Name] {
			v.errorf("tool-name-unique", "%s: duplicate tool name", loc)
		}
		seen[t.Name] = true
		if !strings.HasPrefix(t.Name, prefix) {
			v.warnf("tool-name-prefix", "%s: name should start with %q", loc, prefix)
		}
		if len(t.Description) < 60 {
			v.warnf("description-min-60", "%s: description is %d chars; 60+ recommended", loc, len(t.Description))
		}
		params := v.validateInputSchema(loc, t.Input)
		v.validateOperation(loc, &t, params, declared, envUsed)
		if t.Response != nil && t.Response.Transform != nil {
			if _, err := jmespath.Compile(t.Response.Transform.JMESPath); err != nil {
				v.errorf("jmespath-parses", "%s: response.transform.jmespath: %v", loc, err)
			}
		}
	}

	// Credentials used vs declared.
	for name := range envUsed {
		if !declared[name] {
			v.errorf("env-declared", "{{env.%s}} is used but not declared in credentials", name)
		}
	}
	for _, name := range a.Credentials.Keys {
		c := a.Credentials.Values[name]
		if c.Usage != "manual" && !envUsed[name] {
			v.warnf("env-unused", "credential %s is declared but never referenced; set usage: manual if the agent passes it", name)
		}
	}

	// Optional-auth consistency: an auth type other than none with zero
	// required credentials must say optional: true.
	if a.Auth.Type != AuthNone && !a.Auth.Optional {
		anyRequired := false
		for _, name := range a.Credentials.Keys {
			if a.Credentials.Values[name].Required {
				anyRequired = true
			}
		}
		if !anyRequired && a.Credentials.Len() > 0 {
			v.errorf("auth-optional-consistency", "auth.type %s with no required credentials must set auth.optional: true", a.Auth.Type)
		}
	}
	return v.issues
}

func (v *validator) validateAuth(declared map[string]bool) {
	a := v.a.Auth
	set := func(name string, val bool) {
		if val {
			v.errorf("auth-fields", "auth.%s is not valid for type %s", name, a.Type)
		}
	}
	// Fields that belong to exactly one type; report if set on another.
	notAPIKey := a.Type != AuthAPIKey
	notBearer := a.Type != AuthBearer
	notBasic := a.Type != AuthBasic && a.Type != AuthDatabase && a.Type != AuthLogin
	notQuery := a.Type != AuthQuery
	notOAuth2 := a.Type != AuthOAuth2
	notOAuth1 := a.Type != AuthOAuth1
	notLogin := a.Type != AuthLogin
	notHMAC := a.Type != AuthHMAC
	notMTLS := a.Type != AuthMTLS
	set("in", notAPIKey && a.In != "")
	set("name", notAPIKey && a.Name != "")
	set("value", notAPIKey && a.Value != "")
	set("token", notBearer && notOAuth1 && a.Token != "")
	set("prefix", notBearer && a.Prefix != "")
	set("header", notBearer && a.Header != "")
	set("username", notBasic && a.Username != "")
	set("password", notBasic && a.Password != "")
	set("domain", a.Type != AuthDatabase && a.Domain != "")
	set("params", notQuery && a.Params.Len() > 0)
	set("grant", notOAuth2 && a.Grant != "")
	set("clientId", notOAuth2 && a.ClientID != "")
	set("tokenUrl", notOAuth2 && a.TokenURL != "")
	set("consumerKey", notOAuth1 && a.ConsumerKey != "")
	set("request", notLogin && a.Request != nil)
	set("credentials", notLogin && a.Credentials.Len() > 0)
	set("tokenSource", notLogin && a.TokenSource != nil)
	set("stringToSign", notHMAC && a.StringToSign != "")
	set("cert", notMTLS && a.Cert != "")

	switch a.Type {
	case AuthNone:
	case AuthAPIKey:
		if a.In != "header" && a.In != "query" && a.In != "cookie" {
			v.errorf("auth-apikey-in", "auth.in must be header, query or cookie")
		}
		if a.Name == "" || a.Value == "" {
			v.errorf("auth-apikey-fields", "auth.name and auth.value are required")
		}
	case AuthBearer:
		if a.Token == "" {
			v.errorf("auth-bearer-token", "auth.token is required")
		}
	case AuthBasic, AuthDatabase:
		// "API key as username, empty password" and the reverse are both
		// common; only both empty is an error.
		if a.Username == "" && a.Password == "" {
			v.errorf("auth-basic-fields", "auth.username or auth.password is required")
		}
	case AuthQuery:
		if a.Params.Len() == 0 {
			v.errorf("auth-query-params", "auth.params must not be empty")
		}
	case AuthOAuth2:
		switch a.Grant {
		case "client_credentials", "refresh_token", "authorization_code":
		default:
			v.errorf("auth-oauth2-grant", "auth.grant %q is not supported", a.Grant)
		}
		if a.TokenURL == "" || a.ClientID == "" {
			v.errorf("auth-oauth2-fields", "auth.tokenUrl and auth.clientId are required")
		}
		if a.Grant == "refresh_token" && a.RefreshToken == "" {
			v.errorf("auth-oauth2-refresh", "auth.refreshToken is required for grant refresh_token")
		}
		if a.Grant == "authorization_code" && a.AuthorizationURL == "" {
			v.errorf("auth-oauth2-authurl", "auth.authorizationUrl is required for grant authorization_code")
		}
		if a.ClientAuth != "" && a.ClientAuth != "basic" && a.ClientAuth != "body" {
			v.errorf("auth-oauth2-clientauth", "auth.clientAuth must be basic or body")
		}
	case AuthOAuth1:
		if a.ConsumerKey == "" || a.ConsumerSecret == "" {
			v.errorf("auth-oauth1-fields", "auth.consumerKey and auth.consumerSecret are required")
		}
	case AuthLogin:
		if a.Request == nil || a.Request.URL == "" {
			v.errorf("auth-login-request", "auth.request.url is required")
		}
		if a.TokenSource == nil {
			v.errorf("auth-login-token", "auth.tokenSource is required")
		} else {
			switch a.TokenSource.From {
			case "body":
				if a.TokenSource.JSONPath == "" {
					v.errorf("auth-login-token", "auth.tokenSource.jsonPath is required for from: body")
				}
			case "setCookie":
				if a.TokenSource.CookieName == "" {
					v.errorf("auth-login-token", "auth.tokenSource.cookieName is required for from: setCookie")
				}
			default:
				v.errorf("auth-login-token", "auth.tokenSource.from must be body or setCookie")
			}
		}
		if a.Inject == nil {
			v.errorf("auth-login-inject", "auth.inject is required")
		}
	case AuthHMAC:
		if a.Secret == "" || a.StringToSign == "" || a.SignatureHeader == "" {
			v.errorf("auth-hmac-fields", "auth.secret, auth.stringToSign and auth.signatureHeader are required")
		}
		switch a.Algorithm {
		case "", "sha256", "sha1", "sha512":
		default:
			v.errorf("auth-hmac-algorithm", "auth.algorithm %q is not supported", a.Algorithm)
		}
	case AuthWSSec, AuthMTLS:
	default:
		v.errorf("auth-type", "auth.type %q is not supported", a.Type)
	}
	_ = declared
}

// validateInputSchema checks the JSON Schema subset and returns the
// declared parameter names.
func (v *validator) validateInputSchema(loc string, in *Node) map[string]bool {
	params := map[string]bool{}
	if in == nil || in.N == nil {
		v.errorf("input-required", "%s: input schema is required", loc)
		return params
	}
	n := in.N
	if n.Kind != yaml.MappingNode {
		v.errorf("input-object", "%s: input must be a JSON Schema object", loc)
		return params
	}
	if t := MapGet(n, "type"); t == nil || t.Value != "object" {
		v.errorf("input-object", "%s: input.type must be \"object\"", loc)
	}
	v.checkSchemaSubset(loc, n)
	props := MapGet(n, "properties")
	for _, k := range MapKeys(props) {
		params[k] = true
	}
	if req := MapGet(n, "required"); req != nil && req.Kind == yaml.SequenceNode {
		for _, r := range req.Content {
			if !params[r.Value] {
				v.errorf("input-required-unknown", "%s: required lists unknown property %q", loc, r.Value)
			}
		}
	}
	return params
}

var forbiddenSchemaKeys = map[string]bool{"$ref": true, "oneOf": true, "anyOf": true, "allOf": true, "not": true, "if": true, "then": true, "else": true, "patternProperties": true, "dependencies": true, "$defs": true, "definitions": true}

func (v *validator) checkSchemaSubset(loc string, n *yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if forbiddenSchemaKeys[k] {
				v.errorf("schema-subset", "%s: input schema uses %q, which is outside the supported subset", loc, k)
			}
			v.checkSchemaSubset(loc, n.Content[i+1])
		}
		return
	}
	for _, c := range n.Content {
		v.checkSchemaSubset(loc, c)
	}
}

func (v *validator) validateOperation(loc string, t *Tool, params, declared, envUsed map[string]bool) {
	op := t.Operation
	tt := v.a.Transport.Type

	// Collect every string in the operation and check placeholders.
	var strs []string
	strs = append(strs, op.Path, op.Document, op.Statement, op.Envelope, op.Action, op.Tool)
	for _, k := range op.Headers.Keys {
		strs = append(strs, op.Headers.Values[k])
	}
	for _, n := range []*Node{op.Query, op.Variables, op.ArgsMap} {
		if n != nil && n.N != nil {
			WalkStrings(n.N, func(s string) string { strs = append(strs, s); return s })
		}
	}
	if op.Body != nil && op.Body.Value != nil && op.Body.Value.N != nil {
		WalkStrings(op.Body.Value.N, func(s string) string { strs = append(strs, s); return s })
	}
	for _, s := range strs {
		v.checkPlaceholders(loc, s, params, envUsed)
	}
	// Also transport/auth strings contribute env usage.
	for _, s := range v.authStrings() {
		v.checkPlaceholders("auth", s, nil, envUsed)
	}
	for _, k := range v.a.Transport.Headers.Keys {
		v.checkPlaceholders("transport.headers", v.a.Transport.Headers.Values[k], nil, envUsed)
	}
	v.checkPlaceholders("transport", v.a.Transport.BaseURL+v.a.Transport.DSN, nil, envUsed)

	if op.Kind == "static" {
		if op.Value == nil {
			v.errorf("operation-static", "%s: static operation needs a value", loc)
		}
		return
	}
	switch tt {
	case TransportHTTP, TransportSOAP:
		switch op.Method {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		default:
			v.errorf("operation-method", "%s: operation.method %q is not an HTTP method", loc, op.Method)
		}
		// An empty path is allowed: the base URL is the resource.
		if op.Body != nil {
			switch op.Body.Encoding {
			case "", "json", "form", "multipart", "raw":
			default:
				v.errorf("operation-body-encoding", "%s: body.encoding %q is not supported", loc, op.Body.Encoding)
			}
			if op.Method == "GET" || op.Method == "HEAD" {
				v.warnf("operation-body-get", "%s: body on a %s request", loc, op.Method)
			}
		}
	case TransportGraphQL:
		if op.Kind != "query" && op.Kind != "mutation" {
			v.errorf("operation-kind", "%s: operation.kind must be query or mutation", loc)
		}
		if strings.TrimSpace(op.Document) == "" {
			v.errorf("operation-document", "%s: operation.document is required", loc)
		}
	case TransportDatabase:
		switch op.Kind {
		case "sql":
			if strings.TrimSpace(op.Statement) == "" {
				v.errorf("operation-statement", "%s: operation.statement is required", loc)
			} else if !isRawParam(op.Statement) && !looksReadOnly(op.Statement) {
				if t.Annotations == nil || t.Annotations.DestructiveHint == nil || !*t.Annotations.DestructiveHint {
					v.warnf("sql-readonly", "%s: statement is not SELECT/WITH and tool is not marked destructive", loc)
				}
			}
		case "schema":
		default:
			v.errorf("operation-kind", "%s: operation.kind must be sql, schema or static", loc)
		}
	case TransportMCP:
		if op.Tool == "" {
			v.errorf("operation-tool", "%s: operation.tool is required", loc)
		}
	}
}

func (v *validator) authStrings() []string {
	a := v.a.Auth
	out := []string{a.Value, a.Token, a.Username, a.Password, a.Domain, a.ClientID, a.ClientSecret, a.TokenURL, a.AuthorizationURL, a.RefreshToken, a.ConsumerKey, a.ConsumerSecret, a.TokenSecret, a.Secret, a.StringToSign, a.Cert, a.Key, a.CA}
	for _, m := range []OrderedMap[string]{a.Params, a.ExtraTokenParams, a.Credentials, a.ExtraHeaders} {
		for _, k := range m.Keys {
			out = append(out, m.Values[k])
		}
	}
	if a.Request != nil {
		out = append(out, a.Request.URL)
		for _, k := range a.Request.Headers.Keys {
			out = append(out, a.Request.Headers.Values[k])
		}
		for _, n := range []*Node{a.Request.Query, a.Request.Body} {
			if n != nil && n.N != nil {
				WalkStrings(n.N, func(s string) string { out = append(out, s); return s })
			}
		}
	}
	for _, p := range a.Preprocess {
		if p.Salt != nil && p.Salt.Request != nil {
			out = append(out, p.Salt.Request.URL)
		}
	}
	return out
}

// checkPlaceholders verifies every {{...}} in s uses a known namespace and,
// for params, a declared parameter. params == nil skips the param check.
func (v *validator) checkPlaceholders(loc, s string, params, envUsed map[string]bool) {
	matches := rePlaceholder.FindAllStringSubmatch(s, -1)
	if len(matches) != len(reAnyBraces.FindAllString(s, -1)) {
		v.errorf("placeholder-syntax", "%s: malformed placeholder in %q", loc, truncate(s))
	}
	for _, m := range matches {
		ns, name := m[1], m[2]
		switch ns {
		case "params":
			if params != nil && !params[name] {
				v.errorf("placeholder-unknown", "%s: {{params.%s}} is not a declared parameter", loc, name)
			}
		case "env":
			envUsed[name] = true
		case "caller":
			switch name {
			case "email", "sub", "org", "server", "authMethod":
			default:
				v.errorf("placeholder-unknown", "%s: {{caller.%s}} is not a caller field", loc, name)
			}
		case "auth", "req":
		default:
			v.errorf("placeholder-namespace", "%s: unknown placeholder namespace %q", loc, ns)
		}
	}
}

func isRawParam(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{{") && strings.HasSuffix(s, "}}") && strings.Contains(s, "| raw") && strings.Count(s, "{{") == 1
}

func looksReadOnly(stmt string) bool {
	s := strings.ToUpper(strings.TrimSpace(stmt))
	return strings.HasPrefix(s, "SELECT") || strings.HasPrefix(s, "WITH") || strings.HasPrefix(s, "{") || strings.HasPrefix(s, "SHOW") || strings.HasPrefix(s, "EXPLAIN") || strings.HasPrefix(s, "DESCRIBE")
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}

// ValidateAll validates a set of adapters and adds cross-adapter checks
// (unique slugs and tool names across the catalog). A duplicate tool name
// is suppressed when either adapter allows tool-name-unique-catalog.
func ValidateAll(files []*File) []Issue {
	var issues []Issue
	slugs := map[string]string{}
	type owner struct {
		file  string
		allow bool
	}
	tools := map[string]owner{}
	allows := func(f *File) bool {
		if f.Adapter.Metadata.Lint == nil {
			return false
		}
		for _, r := range f.Adapter.Metadata.Lint.Allow {
			if r == "tool-name-unique-catalog" {
				return true
			}
		}
		return false
	}
	for _, f := range files {
		issues = append(issues, Validate(f)...)
		file := path.Join(f.Dir, FileName)
		if prev, ok := slugs[f.Adapter.Metadata.Slug]; ok {
			issues = append(issues, Issue{File: file, Rule: "slug-unique-catalog", Severity: SeverityError, Message: fmt.Sprintf("slug %q also used by %s", f.Adapter.Metadata.Slug, prev), Related: prev})
		}
		slugs[f.Adapter.Metadata.Slug] = file
		mine := allows(f)
		for _, t := range f.Adapter.Tools {
			if prev, ok := tools[t.Name]; ok && !mine && !prev.allow {
				// Sandbox/public variants of one API share tool names on purpose;
				// a server never mounts both, so this is a warning.
				issues = append(issues, Issue{File: file, Rule: "tool-name-unique-catalog", Severity: SeverityWarning, Message: fmt.Sprintf("tool %q also defined by %s", t.Name, prev.file), Related: prev.file})
			}
			if _, ok := tools[t.Name]; !ok {
				tools[t.Name] = owner{file: file, allow: mine}
			}
		}
	}
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].File != issues[j].File {
			return issues[i].File < issues[j].File
		}
		return issues[i].Severity < issues[j].Severity
	})
	return issues
}
