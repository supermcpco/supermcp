package parser

// FromPostman turns a Postman collection (schema v2.1, and the v2.0
// shapes an old export still uses) into an adapter.
//
// A collection is not an API description. It is a record of requests
// somebody made, with their own values still in it, and the difference
// decides most of what happens here:
//
//   - Folders are how a collection is organised, so they become the tool
//     name prefix rather than being dropped, which is what keeps "Create"
//     in two folders from becoming one tool.
//   - A {{variable}} is whatever the collection says it is. One the
//     collection marks secret, or names or values like a credential,
//     becomes a declared credential read through {{env.NAME}} and never
//     the literal; anything else becomes a tool parameter, so a model can
//     vary it.
//   - Saved example responses are the only prose many collections carry,
//     so a successful one describes the tool and gives it an output
//     schema.
//
// Like the OpenAPI importer, this one never dials anything: a collection
// arrives from the caller and fetching what it points at would make the
// import endpoint a way to reach arbitrary hosts.

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// maxExampleChars bounds how much of a saved example response is quoted
// into a tool description. A model reads every description in the list on
// every call, so an example is a hint and not an attachment.
const maxExampleChars = 400

// FromPostman converts a Postman collection into an adapter. The adapter
// is returned alongside blocker findings so a caller can preview what an
// import would create next to the decisions it still needs.
func FromPostman(doc []byte, opts Options) (*adapter.Adapter, []ImportFinding, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if len(doc) > maxBytes {
		return nil, nil, fmt.Errorf("collection is %d bytes, over the %d byte limit", len(doc), maxBytes)
	}
	if opts.Region != "" && !adapter.Regions[opts.Region] {
		return nil, nil, fmt.Errorf("region %q is not a known region", opts.Region)
	}
	if opts.Category != "" && !adapter.Categories[opts.Category] {
		return nil, nil, fmt.Errorf("category %q is not a known category", opts.Category)
	}

	root, err := parseTree(doc)
	if err != nil {
		return nil, nil, err
	}
	var col pmCollection
	if err := root.Decode(&col); err != nil {
		return nil, nil, fmt.Errorf("this is not a Postman collection: %w", err)
	}
	if strings.TrimSpace(col.Info.Name) == "" && !strings.Contains(col.Info.Schema, "getpostman.com") {
		return nil, nil, errors.New("this is not a Postman collection: it has no info.name and no collection schema")
	}

	p := &pmImporter{builder: newBuilder(opts), col: &col, vars: map[string]*pmVarBinding{}}
	if !strings.Contains(col.Info.Schema, "v2.1") && col.Info.Schema != "" {
		p.add(Info, "info.schema", "the collection declares schema %s; it is read as v2.1, which is compatible for everything this importer uses", col.Info.Schema)
	}

	p.identify(col.Info.Name, pmText(&col.Info.Description))
	p.out.Instructions = strings.TrimSpace(pmText(&col.Info.Description))
	p.classifyVariables()
	p.chooseBase()
	p.locate(p.base)
	p.auth()
	p.walk(col.Item, nil, nil)
	return p.finish()
}

// pmImporter carries the state of one collection conversion.
type pmImporter struct {
	*builder
	col  *pmCollection
	vars map[string]*pmVarBinding
	base string
	// origins is every scheme://host the collection's requests name, in
	// the order they were first seen.
	origins []string
	// authSeen records the distinct auth types below the collection root,
	// so the importer can say when it flattened several into one.
	authSeen map[string]bool
}

// --- collection model ------------------------------------------------------
//
// Only the parts an adapter can express are modelled. Anything
// polymorphic (a description that is a string or an object, a host that
// is a string or a list) is kept as a yaml.Node and read by a helper,
// because both shapes occur in the wild and an export is not obliged to
// say which it used.

type pmCollection struct {
	Info     pmInfo       `yaml:"info"`
	Item     []pmItem     `yaml:"item"`
	Auth     yaml.Node    `yaml:"auth"`
	Variable []pmVariable `yaml:"variable"`
	Event    []pmEvent    `yaml:"event"`
}

type pmInfo struct {
	Name        string    `yaml:"name"`
	Description yaml.Node `yaml:"description"`
	Schema      string    `yaml:"schema"`
}

type pmItem struct {
	Name        string       `yaml:"name"`
	Description yaml.Node    `yaml:"description"`
	Item        []pmItem     `yaml:"item"`
	Request     yaml.Node    `yaml:"request"`
	Response    []pmResponse `yaml:"response"`
	Auth        yaml.Node    `yaml:"auth"`
	Variable    []pmVariable `yaml:"variable"`
	Event       []pmEvent    `yaml:"event"`
}

type pmRequest struct {
	Method      string    `yaml:"method"`
	Header      yaml.Node `yaml:"header"`
	Body        *pmBody   `yaml:"body"`
	URL         yaml.Node `yaml:"url"`
	Auth        yaml.Node `yaml:"auth"`
	Description yaml.Node `yaml:"description"`
}

type pmHeader struct {
	Key         string    `yaml:"key"`
	Value       string    `yaml:"value"`
	Disabled    bool      `yaml:"disabled"`
	Description yaml.Node `yaml:"description"`
}

type pmURL struct {
	Raw      string       `yaml:"raw"`
	Protocol string       `yaml:"protocol"`
	Host     yaml.Node    `yaml:"host"`
	Port     string       `yaml:"port"`
	Path     yaml.Node    `yaml:"path"`
	Query    []pmQuery    `yaml:"query"`
	Variable []pmVariable `yaml:"variable"`
}

type pmQuery struct {
	Key         string    `yaml:"key"`
	Value       string    `yaml:"value"`
	Disabled    bool      `yaml:"disabled"`
	Description yaml.Node `yaml:"description"`
}

type pmVariable struct {
	Key         string    `yaml:"key"`
	Value       yaml.Node `yaml:"value"`
	Type        string    `yaml:"type"`
	Description yaml.Node `yaml:"description"`
	Disabled    bool      `yaml:"disabled"`
}

type pmBody struct {
	Mode       string    `yaml:"mode"`
	Raw        string    `yaml:"raw"`
	Urlencoded []pmField `yaml:"urlencoded"`
	Formdata   []pmField `yaml:"formdata"`
	GraphQL    *struct {
		Query     string `yaml:"query"`
		Variables string `yaml:"variables"`
	} `yaml:"graphql"`
	Options struct {
		Raw struct {
			Language string `yaml:"language"`
		} `yaml:"raw"`
	} `yaml:"options"`
	Disabled bool `yaml:"disabled"`
}

type pmField struct {
	Key         string    `yaml:"key"`
	Value       string    `yaml:"value"`
	Type        string    `yaml:"type"`
	ContentType string    `yaml:"contentType"`
	Disabled    bool      `yaml:"disabled"`
	Description yaml.Node `yaml:"description"`
}

type pmResponse struct {
	Name   string    `yaml:"name"`
	Code   int       `yaml:"code"`
	Status string    `yaml:"status"`
	Body   string    `yaml:"body"`
	Header yaml.Node `yaml:"header"`
}

type pmEvent struct {
	Listen   string `yaml:"listen"`
	Disabled bool   `yaml:"disabled"`
	Script   struct {
		Exec yaml.Node `yaml:"exec"`
		Type string    `yaml:"type"`
	} `yaml:"script"`
}

// --- variables -------------------------------------------------------------

// pmVarKind says what one {{variable}} becomes in the adapter.
type pmVarKind int

const (
	// pmCredential: a value the workspace holds, read as {{env.NAME}}.
	pmCredential pmVarKind = iota
	// pmConstant: a literal the collection settled on, written out as it
	// stands (a base URL, an API version).
	pmConstant
	// pmParameter: something a model supplies on each call.
	pmParameter
)

type pmVarBinding struct {
	kind        pmVarKind
	name        string // credential name, for pmCredential
	value       string // literal, for pmConstant and a parameter's default
	description string
	usedInHost  bool
}

// A Postman dynamic variable ({{$guid}}, {{$randomEmail}}) is generated
// by the Postman runner, which is not here.
var reDynamicVar = regexp.MustCompile(`^\$`)

var rePostmanVar = regexp.MustCompile(`\{\{([^{}]+)\}\}`)

// classifyVariables decides, once for the whole collection, what each
// declared variable becomes. Deciding it centrally is what keeps the same
// variable from being a credential in one request and a parameter in the
// next.
func (p *pmImporter) classifyVariables() {
	for _, v := range p.col.Variable {
		p.bindVariable(v, "collection")
	}
	// A folder may redeclare a variable. The collection-level binding
	// wins, because an adapter has one set of credentials and a variable
	// that is a secret anywhere is a secret everywhere.
	var walk func(items []pmItem, where string)
	walk = func(items []pmItem, where string) {
		for _, it := range items {
			for _, v := range it.Variable {
				p.bindVariable(v, "folder "+or(it.Name, where))
			}
			walk(it.Item, or(it.Name, where))
		}
	}
	walk(p.col.Item, "collection")
}

func (p *pmImporter) bindVariable(v pmVariable, where string) {
	key := strings.TrimSpace(v.Key)
	if key == "" || v.Disabled {
		return
	}
	if _, exists := p.vars[key]; exists {
		return
	}
	value := strings.TrimSpace(pmScalar(&v.Value))
	description := pmText(&v.Description)

	secret := v.Type == "secret" || looksSecretName(key) || looksSecretValue(value)
	if secret {
		name := envName(key)
		p.vars[key] = &pmVarBinding{kind: pmCredential, name: name, description: or(description, "Read from the "+where+" variable "+key)}
		switch {
		case value != "" && v.Type == "secret":
			p.add(Review, "variables."+key, "the %s variable %q is marked secret and carries a value; the value is not stored in the connector — set the credential %s instead", where, key, name)
		case value != "":
			p.add(Review, "variables."+key, "the %s variable %q looks like a credential and carries a value; the value is not stored in the connector — set the credential %s instead", where, key, name)
		default:
			p.add(Info, "variables."+key, "the %s variable %q is treated as a credential; set %s to give it a value", where, key, name)
		}
		return
	}
	if value != "" {
		p.vars[key] = &pmVarBinding{kind: pmConstant, value: value, description: description}
		return
	}
	p.vars[key] = &pmVarBinding{kind: pmParameter, description: description}
}

// useCredential declares the credential a variable stands for, at the
// moment something actually reads it. Declaring it when the variable was
// classified would leave a credential behind for every variable the
// collection declared and no request used, and the validator rightly
// complains about one nothing reads.
func (p *pmImporter) useCredential(b *pmVarBinding) string {
	return p.credential(b.name, b.description, true)
}

// binding returns what a variable reference resolves to, inventing a
// parameter binding for one the collection never declared.
func (p *pmImporter) binding(name string) *pmVarBinding {
	if b, ok := p.vars[name]; ok {
		return b
	}
	b := &pmVarBinding{kind: pmParameter}
	if reDynamicVar.MatchString(name) {
		b.description = "Postman generated this value with its dynamic variable {{" + name + "}}; the connector cannot, so it is asked for"
	}
	p.vars[name] = b
	return b
}

// --- transport -------------------------------------------------------------

// chooseBase settles which upstream the connector calls. A collection can
// name several hosts, and picking one by coin toss would send most of the
// tools somewhere they do not belong, so several is a blocker.
func (p *pmImporter) chooseBase() {
	p.collectOrigins(p.col.Item)

	if p.opts.ServerURL != "" {
		if err := checkAbsolute(p.opts.ServerURL); err != nil {
			p.add(Blocker, "transport.baseUrl", "the base URL supplied with the import is unusable: %v", err)
		} else {
			if len(p.origins) > 1 {
				p.add(Info, "transport.baseUrl", "the collection calls %d hosts; the base URL supplied with the import is used for all of them", len(p.origins))
			}
			p.base = strings.TrimRight(p.opts.ServerURL, "/")
		}
	} else {
		switch len(p.origins) {
		case 0:
			p.add(Blocker, "transport.baseUrl", "no request in the collection names a host the connector could call; supply the base URL with the import")
		case 1:
			p.base = p.origins[0]
		default:
			p.add(Blocker, "transport.baseUrl", "the collection calls %d hosts (%s); an adapter calls one, so supply the base URL with the import and check the paths afterwards",
				len(p.origins), strings.Join(p.origins, ", "))
			// The first still fills the preview, so the rest of the import
			// can be read.
			p.base = p.origins[0]
		}
	}
	p.out.Transport.Type = adapter.TransportHTTP
	p.out.Transport.BaseURL = p.base
}

func (p *pmImporter) collectOrigins(items []pmItem) {
	for i := range items {
		it := &items[i]
		if len(it.Item) > 0 {
			p.collectOrigins(it.Item)
			continue
		}
		req, ok := p.request(it)
		if !ok {
			continue
		}
		origin, _, _ := p.splitURL(p.requestURL(req))
		if origin == "" {
			continue
		}
		if !containsString(p.origins, origin) {
			p.origins = append(p.origins, origin)
		}
	}
}

// requestURL returns the request's URL as one string, from the raw form
// the collection shows when there is one and from the parts otherwise.
func (p *pmImporter) requestURL(req *pmRequest) string {
	var u pmURL
	if req.URL.Kind == yaml.ScalarNode {
		return req.URL.Value
	}
	if err := req.URL.Decode(&u); err != nil {
		return ""
	}
	if strings.TrimSpace(u.Raw) != "" {
		return u.Raw
	}
	host := strings.Join(pmStrings(&u.Host), ".")
	path := strings.Join(pmStrings(&u.Path), "/")
	var sb strings.Builder
	if u.Protocol != "" {
		sb.WriteString(u.Protocol + "://")
	}
	sb.WriteString(host)
	if u.Port != "" {
		sb.WriteString(":" + u.Port)
	}
	if path != "" && !strings.HasPrefix(path, "/") {
		sb.WriteString("/")
	}
	sb.WriteString(path)
	return sb.String()
}

// splitURL separates a request URL into the origin the connector will
// call, the path a tool will request and the query string written into
// the URL itself. Variables are resolved to their constant values first,
// because {{baseUrl}} is how most collections write their host and the
// origin cannot be read without it.
func (p *pmImporter) splitURL(raw string) (origin, path, query string) {
	return splitRequestURL(p.expandConstants(raw))
}

// expandConstants replaces the variables that resolved to a literal. Any
// other variable is left as it was for the caller to bind.
func (p *pmImporter) expandConstants(s string) string {
	return rePostmanVar.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.TrimSpace(m[2 : len(m)-2])
		if b, ok := p.vars[name]; ok && b.kind == pmConstant {
			b.usedInHost = true
			return b.value
		}
		return m
	})
}

// --- auth ------------------------------------------------------------------

func (p *pmImporter) auth() {
	p.authSeen = map[string]bool{}
	p.collectAuthTypes(p.col.Item)

	node := &p.col.Auth
	if pmAuthType(node) == "" {
		// A collection with no auth of its own may still have one auth
		// used by every request; taking it is better than importing a
		// connector that cannot sign in.
		if n, ok := p.singleRequestAuth(); ok {
			node = n
			p.add(Info, "auth", "the collection declares no auth of its own; the one its requests share is used")
		}
	}
	kind := pmAuthType(node)
	if kind == "" || kind == "noauth" {
		if len(p.authSeen) > 0 {
			p.add(Review, "auth", "the collection's requests declare auth but the collection does not; the connector is created unauthenticated and needs its auth filled in")
		}
		return
	}
	if len(p.authSeen) > 1 {
		kinds := make([]string, 0, len(p.authSeen))
		for k := range p.authSeen {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		p.add(Review, "auth", "the collection mixes %s auth between its requests; an adapter holds one auth block, so %s is used for every tool",
			strings.Join(kinds, ", "), kind)
	}
	p.applyAuth(kind, pmAuthParams(node))
}

func (p *pmImporter) collectAuthTypes(items []pmItem) {
	for i := range items {
		it := &items[i]
		if k := pmAuthType(&it.Auth); k != "" && k != "noauth" {
			p.authSeen[k] = true
		}
		if len(it.Item) > 0 {
			p.collectAuthTypes(it.Item)
			continue
		}
		if req, ok := p.request(it); ok {
			if k := pmAuthType(&req.Auth); k != "" && k != "noauth" {
				p.authSeen[k] = true
			}
		}
	}
}

// singleRequestAuth returns the auth block when exactly one kind is used
// below the collection root.
func (p *pmImporter) singleRequestAuth() (*yaml.Node, bool) {
	if len(p.authSeen) != 1 {
		return nil, false
	}
	var found *yaml.Node
	var walk func(items []pmItem)
	walk = func(items []pmItem) {
		for i := range items {
			it := &items[i]
			if found != nil {
				return
			}
			if pmAuthType(&it.Auth) != "" && pmAuthType(&it.Auth) != "noauth" {
				found = &it.Auth
				return
			}
			if len(it.Item) > 0 {
				walk(it.Item)
				continue
			}
			if req, ok := p.request(it); ok {
				if k := pmAuthType(&req.Auth); k != "" && k != "noauth" {
					found = &req.Auth
					return
				}
			}
		}
	}
	walk(p.col.Item)
	return found, found != nil
}

func (p *pmImporter) applyAuth(kind string, params map[string]string) {
	switch kind {
	case "bearer":
		token := p.authSecret(params["token"], credToken, "Bearer token for "+p.out.Metadata.Name)
		if token == "" {
			p.add(Review, "auth", "the collection's bearer auth carries no token; the connector is created unauthenticated")
			return
		}
		p.out.Auth = adapter.Auth{Type: adapter.AuthBearer, Token: token}
	case "basic":
		user := p.authSecret(params["username"], credUsername, "HTTP basic username")
		pass := p.authSecret(params["password"], credPassword, "HTTP basic password")
		if user == "" && pass == "" {
			p.add(Review, "auth", "the collection's basic auth carries neither username nor password; the connector is created unauthenticated")
			return
		}
		p.out.Auth = adapter.Auth{Type: adapter.AuthBasic, Username: user, Password: pass}
	case "apikey":
		name := p.expandConstants(params["key"])
		in := params["in"]
		if in == "" {
			in = "header"
		}
		if in != "header" && in != "query" && in != "cookie" {
			p.add(Review, "auth", "the collection's API key auth sends the key in %q, which is not somewhere an adapter can put it; the connector is created unauthenticated", in)
			return
		}
		if name == "" {
			p.add(Review, "auth", "the collection's API key auth does not say what the key is called; the connector is created unauthenticated")
			return
		}
		value := p.authSecret(params["value"], credKey, fmt.Sprintf("API key sent as the %q %s", name, in))
		if value == "" {
			p.add(Review, "auth", "the collection's API key auth carries no value; the connector is created unauthenticated")
			return
		}
		p.out.Auth = adapter.Auth{Type: adapter.AuthAPIKey, In: in, Name: name, Value: value}
	case "oauth2":
		p.applyOAuth2(params)
	case "oauth1":
		key := p.authSecret(params["consumerKey"], "OAUTH_CONSUMER_KEY", "OAuth1 consumer key")
		secret := p.authSecret(params["consumerSecret"], "OAUTH_CONSUMER_SECRET", "OAuth1 consumer secret")
		if key == "" || secret == "" {
			p.add(Review, "auth", "the collection's OAuth1 auth has no consumer key and secret; the connector is created unauthenticated")
			return
		}
		p.out.Auth = adapter.Auth{
			Type:           adapter.AuthOAuth1,
			ConsumerKey:    key,
			ConsumerSecret: secret,
			Token:          p.authSecret(params["token"], "OAUTH_TOKEN", "OAuth1 token"),
			TokenSecret:    p.authSecret(params["tokenSecret"], "OAUTH_TOKEN_SECRET", "OAuth1 token secret"),
		}
	default:
		p.add(Review, "auth", "the collection signs in with %q, which an adapter cannot express; the connector is created unauthenticated and needs its auth filled in", kind)
	}
}

func (p *pmImporter) applyOAuth2(params map[string]string) {
	tokenURL := p.expandConstants(params["accessTokenUrl"])
	clientID := params["clientId"]
	if tokenURL == "" || clientID == "" {
		// Postman commonly stores only the access token it last obtained.
		// Sending it as a bearer token is what Postman itself does; it
		// just cannot be refreshed, which is worth saying out loud.
		if token := p.authSecret(params["accessToken"], credToken, "OAuth2 access token, obtained outside this connector"); token != "" {
			p.out.Auth = adapter.Auth{Type: adapter.AuthBearer, Token: token}
			p.add(Review, "auth", "the collection's OAuth2 block holds an access token but not the client credentials that would renew it; the connector sends the token as a bearer token and cannot refresh it")
			return
		}
		p.add(Review, "auth", "the collection's OAuth2 block has neither a token URL and client id nor an access token; the connector is created unauthenticated")
		return
	}
	auth := adapter.Auth{
		Type:     adapter.AuthOAuth2,
		ClientID: p.authSecret(clientID, credClientID, "OAuth2 client id"),
		TokenURL: tokenURL,
	}
	if secret := p.authSecret(params["clientSecret"], credClientSecret, "OAuth2 client secret"); secret != "" {
		auth.ClientSecret = secret
	}
	if scope := strings.TrimSpace(p.expandConstants(params["scope"])); scope != "" {
		auth.Scopes = strings.Fields(strings.ReplaceAll(scope, ",", " "))
	}
	switch params["grant_type"] {
	case "client_credentials", "":
		auth.Grant = "client_credentials"
	case "authorization_code", "authorization_code_with_pkce":
		auth.Grant = "authorization_code"
		auth.AuthorizationURL = p.expandConstants(params["authUrl"])
		if auth.AuthorizationURL == "" {
			p.add(Review, "auth", "the collection's OAuth2 block uses the authorization code grant but names no authorization URL; the connector is created unauthenticated")
			p.dropCredential(credClientID, credClientSecret)
			return
		}
	default:
		p.add(Review, "auth", "the collection's OAuth2 block uses the %q grant, which an adapter does not support; the connector is created unauthenticated", params["grant_type"])
		p.dropCredential(credClientID, credClientSecret)
		return
	}
	p.out.Auth = auth
}

// authSecret turns one Postman auth value into something the adapter can
// hold. A variable resolves to the credential it already stands for; a
// literal is moved into a credential of its own, because a token pasted
// into a collection is a live token and storing it in the connector would
// copy it somewhere new.
func (p *pmImporter) authSecret(raw, credName, description string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if m := rePostmanVar.FindStringSubmatch(raw); m != nil && m[0] == raw {
		name := strings.TrimSpace(m[1])
		b := p.binding(name)
		switch b.kind {
		case pmCredential:
			return p.useCredential(b)
		case pmConstant:
			// A literal reached through a variable is still a literal.
			return p.moveSecret(b.value, envName(name), description)
		default:
			// A per-call parameter cannot fill an adapter-wide auth block.
			b.kind = pmCredential
			b.name = envName(name)
			p.add(Review, "auth", "the variable %q signs the collection in, so it is a credential of the connector rather than something a model passes on each call", name)
			return p.credential(b.name, description, true)
		}
	}
	if strings.Contains(raw, "{{") {
		// A value built out of several variables: resolve what can be
		// resolved and declare the rest as credentials, so nothing is left
		// that the validator would read as a broken placeholder.
		return rePostmanVar.ReplaceAllStringFunc(p.expandConstants(raw), func(m string) string {
			name := strings.TrimSpace(m[2 : len(m)-2])
			b := p.binding(name)
			b.kind = pmCredential
			if b.name == "" {
				b.name = envName(name)
			}
			return p.credential(b.name, description, true)
		})
	}
	return p.moveSecret(raw, credName, description)
}

// moveSecret declares a credential for a literal and says that it did.
func (p *pmImporter) moveSecret(literal, credName, description string) string {
	if literal == "" {
		return ""
	}
	placeholder := p.credential(credName, description, true)
	p.add(Review, "auth", "the collection carries a sign-in value in plain text; it is not stored in the connector — set the credential %s to the value you want used", envName(credName))
	return placeholder
}

// dropCredential removes credentials declared for an auth block that
// turned out to be unusable; the validator warns about one nothing reads.
func (p *pmImporter) dropCredential(names ...string) {
	drop := map[string]bool{}
	for _, n := range names {
		drop[envName(n)] = true
	}
	kept := adapter.NewOrderedMap[adapter.Credential]()
	for _, k := range p.out.Credentials.Keys {
		if drop[k] {
			continue
		}
		v, _ := p.out.Credentials.Get(k)
		kept.Set(k, v)
	}
	p.out.Credentials = kept
}

// --- tools -----------------------------------------------------------------

// walk descends the item tree. folders is the path of folder names above
// the current level, which becomes the tool name prefix.
func (p *pmImporter) walk(items []pmItem, folders []string, scripts []string) {
	for i := range items {
		it := &items[i]
		if len(p.out.Tools) >= p.max {
			p.op = ""
			p.add(Blocker, "item", "the collection holds more than %d requests; the import stops there, so split the collection or raise the limit", p.max)
			return
		}
		if len(it.Item) > 0 || it.Request.Kind == 0 {
			if len(it.Item) == 0 {
				continue // an empty folder describes nothing
			}
			// The slices are copied rather than appended to in place: two
			// sibling folders would otherwise overwrite each other's name.
			p.walk(it.Item, concat(folders, it.Name), concat(scripts, pmScriptNames(it.Event, it.Name)...))
			continue
		}
		req, ok := p.request(it)
		if !ok {
			p.op = it.Name
			p.add(Review, "item."+it.Name, "this request could not be read; it is skipped")
			continue
		}
		p.tool(it, req, folders, concat(scripts, pmScriptNames(it.Event, it.Name)...))
	}
}

func (p *pmImporter) request(it *pmItem) (*pmRequest, bool) {
	switch it.Request.Kind {
	case 0:
		return nil, false
	case yaml.ScalarNode:
		// v2.0 allowed a bare URL string in place of a request object.
		return &pmRequest{Method: "GET", URL: it.Request}, true
	}
	var req pmRequest
	if err := it.Request.Decode(&req); err != nil {
		return nil, false
	}
	return &req, true
}

func (p *pmImporter) tool(it *pmItem, req *pmRequest, folders, scripts []string) {
	name := strings.Join(concat(folders, it.Name), " ")
	p.op = strings.TrimSpace(or(it.Name, name))
	loc := "item." + strings.Join(concat(folders, or(it.Name, "?")), ".")

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	t := adapter.Tool{Name: p.toolName(name, loc)}
	switch method {
	case "GET", "HEAD":
		t.Annotations = &adapter.Annotations{ReadOnlyHint: ptr(true)}
	case "DELETE":
		t.Annotations = &adapter.Annotations{DestructiveHint: ptr(true)}
	case "POST", "PUT", "PATCH", "OPTIONS":
	default:
		p.add(Review, loc, "the request uses the method %q, which is not one an adapter can send; the tool is skipped", method)
		return
	}

	in := newParams(p.builder, loc)
	origin, path, rawQuery := p.splitURL(p.requestURL(req))
	if origin != "" && p.base != "" && origin != p.base {
		p.add(Review, loc, "this request calls %s, but the connector calls %s; the tool keeps the path and will reach the connector's host", origin, p.base)
	}
	t.Operation.Method = method
	t.Operation.Path = p.templatePath(path, req, in, loc)
	p.query(&t, req, rawQuery, in, loc)
	p.headers(&t, req, in, loc)
	if req.Body != nil {
		p.body(&t, method, req.Body, in, loc)
	}
	t.Input = in.schema()
	t.Description = p.description(it, req, folders, method, t.Operation.Path)
	if out := p.outputSchema(it); out != nil {
		t.Output = out
	}
	for _, s := range scripts {
		p.add(Review, loc, "the collection runs the script %q around this request; the connector does not run scripts, so anything it computed has to arrive as a parameter or a credential", s)
	}
	p.out.Tools = append(p.out.Tools, t)
}

// templatePath rewrites the request path into the adapter's placeholder
// syntax: {{variable}} becomes whatever the variable resolved to, and
// Postman's :segment form becomes a required parameter.
func (p *pmImporter) templatePath(path string, req *pmRequest, in *params, loc string) string {
	pathVars := map[string]pmVariable{}
	if req.URL.Kind == yaml.MappingNode {
		var u pmURL
		if err := req.URL.Decode(&u); err == nil {
			for _, v := range u.Variable {
				pathVars[v.Key] = v
			}
		}
	}

	path = p.substitute(path, in, true, loc)
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if !strings.HasPrefix(seg, ":") || len(seg) == 1 {
			continue
		}
		name := seg[1:]
		schema := mapping()
		mapSet(schema, "type", str("string"))
		declared := pathVars[name]
		if def := strings.TrimSpace(pmScalar(&declared.Value)); def != "" {
			mapSet(schema, "default", str(def))
		}
		description := or(pmText(&declared.Description), "The "+name+" this request is about")
		segments[i] = in.declare(name, "path segment", description, schema, true)
	}
	return strings.Join(segments, "/")
}

// substitute rewrites every {{variable}} in a string. A credential
// becomes {{env.NAME}}, a constant its literal value, and anything else a
// tool parameter. Nothing is left in {{...}} form afterwards, which
// matters: the validator reads a stray one as a malformed placeholder.
func (p *pmImporter) substitute(s string, in *params, required bool, loc string) string {
	return rePostmanVar.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.TrimSpace(m[2 : len(m)-2])
		b := p.binding(name)
		switch b.kind {
		case pmCredential:
			return p.useCredential(b)
		case pmConstant:
			return b.value
		default:
			if reDynamicVar.MatchString(name) {
				p.add(Review, loc, "the request uses Postman's dynamic variable {{%s}}, which only Postman generates; it is asked for as a parameter instead", name)
			}
			schema := mapping()
			mapSet(schema, "type", str("string"))
			// The origin is "variable" wherever the reference was found, so
			// one variable used in the path and again in the body is one
			// parameter rather than two that have to agree.
			return in.declare(strings.TrimPrefix(name, "$"), "variable", b.description, schema, required)
		}
	})
}

// query maps the request's query string onto the tool. A value the
// collection filled in becomes the parameter's default rather than a
// fixed value, so a saved example does not become the only call the tool
// can make.
func (p *pmImporter) query(t *adapter.Tool, req *pmRequest, rawQuery string, in *params, loc string) {
	entries := p.queryEntries(req, rawQuery)
	if len(entries) == 0 {
		return
	}
	q := mapping()
	for _, e := range entries {
		value := strings.TrimSpace(e.Value)
		switch {
		case strings.Contains(value, "{{"):
			mapSet(q, e.Key, str(p.substitute(value, in, true, loc)))
		default:
			schema := mapping()
			mapSet(schema, "type", str("string"))
			if value != "" {
				mapSet(schema, "default", str(value))
			}
			description := pmText(&e.Description)
			mapSet(q, e.Key, str(in.declare(e.Key, "query parameter", description, schema, false)))
		}
	}
	if len(q.Content) > 0 {
		t.Operation.Query = &adapter.Node{N: q}
	}
}

// queryEntries prefers the collection's structured query list, which is
// the only place a disabled parameter is marked as such, and falls back
// to whatever was written into the raw URL.
func (p *pmImporter) queryEntries(req *pmRequest, rawQuery string) []pmQuery {
	var out []pmQuery
	if req.URL.Kind == yaml.MappingNode {
		var u pmURL
		if err := req.URL.Decode(&u); err == nil && len(u.Query) > 0 {
			for _, q := range u.Query {
				if q.Disabled || strings.TrimSpace(q.Key) == "" {
					continue
				}
				out = append(out, q)
			}
			return out
		}
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		if k, err := url.QueryUnescape(key); err == nil {
			key = k
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		if strings.TrimSpace(key) == "" {
			continue
		}
		out = append(out, pmQuery{Key: key, Value: value})
	}
	return out
}

// Headers the transport sets for itself. Sending a collection's copy of
// them would override what the engine knows about the body it is about to
// encode.
var pmSkippedHeaders = map[string]bool{
	"accept-encoding": true, "content-length": true, "host": true, "connection": true,
	"user-agent": true, "postman-token": true,
}

func (p *pmImporter) headers(t *adapter.Tool, req *pmRequest, in *params, loc string) {
	for _, h := range pmHeaders(&req.Header) {
		if h.Disabled || strings.TrimSpace(h.Key) == "" {
			continue
		}
		key := strings.TrimSpace(h.Key)
		lower := strings.ToLower(key)
		if pmSkippedHeaders[lower] {
			continue
		}
		value := strings.TrimSpace(h.Value)
		if lower == "authorization" {
			p.authorizationHeader(value, loc)
			continue
		}
		switch {
		case strings.Contains(value, "{{"):
			t.Operation.Headers.Set(key, p.substitute(value, in, true, loc))
		case looksSecretName(key) || looksSecretValue(value):
			// A key written into a header of the collection is a live key.
			name := envName(key)
			t.Operation.Headers.Set(key, p.credential(name, "Sent as the "+key+" header", true))
			p.add(Review, loc, "the %s header carries a value that looks like a credential; it is not stored in the connector — set %s instead", key, name)
		case value == "":
			continue
		default:
			t.Operation.Headers.Set(key, value)
		}
	}
}

// authorizationHeader folds an Authorization header written by hand into
// the connector's auth block, which is where a credential belongs. A
// collection that has both is not contradicted: the auth block wins and
// the header is reported.
func (p *pmImporter) authorizationHeader(value, loc string) {
	if value == "" {
		return
	}
	if p.out.Auth.Type != adapter.AuthNone {
		p.add(Info, loc, "this request sets its own Authorization header; the connector signs in with the collection's auth instead, so the header is dropped")
		return
	}
	scheme, rest, found := strings.Cut(value, " ")
	if !found {
		scheme, rest = "Bearer", value
	}
	token := p.authSecret(strings.TrimSpace(rest), credToken, "Sent in the Authorization header")
	if token == "" {
		return
	}
	auth := adapter.Auth{Type: adapter.AuthBearer, Token: token}
	if !strings.EqualFold(scheme, "Bearer") {
		auth.Prefix = scheme
	}
	p.out.Auth = auth
	p.add(Review, loc, "this request signs in with an Authorization header rather than the collection's auth; the connector now sends %s for every tool — check that the others expect it", or(scheme, "Bearer"))
}

// --- bodies ----------------------------------------------------------------

func (p *pmImporter) body(t *adapter.Tool, method string, body *pmBody, in *params, loc string) {
	if body.Disabled {
		return
	}
	switch body.Mode {
	case "", "none":
		return
	case "raw":
		p.rawBody(t, method, body, in, loc)
	case "urlencoded":
		p.fieldBody(t, "form", body.Urlencoded, in, loc)
	case "formdata":
		p.fieldBody(t, "multipart", body.Formdata, in, loc)
	case "graphql":
		p.graphQLBody(t, body, in, loc)
	case "file":
		p.add(Review, loc, "this request uploads a file from disk; there is no disk here, so the tool is imported without a body — add one by hand if the call needs it")
	default:
		p.add(Review, loc, "the request body mode %q is not one an adapter can send; the tool is imported without a body", body.Mode)
	}
	if t.Operation.Body != nil && (method == "GET" || method == "HEAD") {
		p.add(Info, loc, "a %s request carries a body in the collection; almost nothing sends one, so check this tool before relying on it", method)
	}
}

// rawBody maps a raw body. JSON is the case worth getting right: its
// fields become named parameters, which a model fills in far more
// reliably than it writes a document.
func (p *pmImporter) rawBody(t *adapter.Tool, method string, body *pmBody, in *params, loc string) {
	raw := strings.TrimSpace(body.Raw)
	if raw == "" {
		return
	}
	language := strings.ToLower(body.Options.Raw.Language)
	node, err := adapter.NodeFromJSON([]byte(raw))
	if err != nil || node == nil || node.N == nil || node.N.Kind != yaml.MappingNode {
		// Only complain when the body meant to be JSON. YAML will parse a
		// line of prose as a scalar quite happily, so the parse succeeding
		// says nothing on its own.
		if language == "json" || strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
			p.add(Review, loc, "the request body is meant to be JSON but is not a JSON object, so its fields cannot be named; the whole body is one parameter")
		}
		p.rawTextBody(t, raw, language, in, loc)
		return
	}
	value := p.jsonBody(node.N, in, loc, 0)
	t.Operation.Body = &adapter.Body{Encoding: "json", Value: &adapter.Node{N: value}}
}

// jsonBody rewrites a saved JSON body into a request template. At the top
// level every field becomes a parameter, because those are the fields a
// caller means to vary; deeper down only the variables do, so the shape
// the collection recorded survives.
func (p *pmImporter) jsonBody(n *yaml.Node, in *params, loc string, depth int) *yaml.Node {
	out := mapping()
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		if depth == 0 {
			mapSet(out, key, p.jsonField(key, val, in, loc))
			continue
		}
		mapSet(out, key, p.jsonValue(val, in, loc, depth))
	}
	return out
}

// jsonField turns one top-level body field into a parameter, keeping the
// example the collection saved as the parameter's default so a caller can
// see what a working value looks like.
func (p *pmImporter) jsonField(key string, val *yaml.Node, in *params, loc string) *yaml.Node {
	if pmHasVars(val) {
		// The author already said what varies here; respect it rather than
		// wrapping their variables in a parameter of our own.
		return p.jsonValue(val, in, loc, 1)
	}
	schema := inferSchema(val, 0)
	required := false
	if def := typedScalar(val); def != nil && val.Tag != "!!null" {
		mapSet(schema, "default", def)
	} else if val.Kind != yaml.ScalarNode {
		// A nested structure has no useful default; a caller has to supply
		// the whole of it.
		required = true
	}
	return str(in.declare(key, "body field", "", schema, required))
}

// jsonValue rewrites the variables inside a value the collection wrote,
// leaving everything else as it stands.
func (p *pmImporter) jsonValue(val *yaml.Node, in *params, loc string, depth int) *yaml.Node {
	switch val.Kind {
	case yaml.MappingNode:
		return p.jsonBody(val, in, loc, depth+1)
	case yaml.SequenceNode:
		out := sequence()
		for _, c := range val.Content {
			out.Content = append(out.Content, p.jsonValue(c, in, loc, depth+1))
		}
		return out
	case yaml.ScalarNode:
		if val.Tag != "!!str" || !strings.Contains(val.Value, "{{") {
			return typedScalar(val)
		}
		return str(p.substitute(val.Value, in, true, loc))
	default:
		return typedScalar(val)
	}
}

// rawTextBody sends a body an adapter cannot take apart. When the
// collection parameterised it, the template is kept as written; when it
// did not, the whole body becomes one parameter with the saved text as
// its default, so the tool can send something other than the example.
func (p *pmImporter) rawTextBody(t *adapter.Tool, raw, language string, in *params, loc string) {
	if contentType := pmRawContentType(language); contentType != "" {
		t.Operation.Headers.Set("Content-Type", contentType)
	}
	if strings.Contains(raw, "{{") {
		t.Operation.Body = &adapter.Body{Encoding: "raw", Value: &adapter.Node{N: str(p.substitute(raw, in, true, loc))}}
		return
	}
	schema := mapping()
	mapSet(schema, "type", str("string"))
	mapSet(schema, "default", str(raw))
	placeholder := in.declare("body", "body", "The request body, sent as "+or(pmRawContentType(language), "text"), schema, true)
	t.Operation.Body = &adapter.Body{Encoding: "raw", Value: &adapter.Node{N: str(placeholder)}}
	p.add(Info, loc, "the request body is not JSON, so it is one parameter with the collection's text as its default")
}

func pmRawContentType(language string) string {
	switch strings.ToLower(language) {
	case "json":
		return "application/json"
	case "xml":
		return "application/xml"
	case "html":
		return "text/html"
	case "javascript":
		return "application/javascript"
	case "text":
		return "text/plain"
	default:
		return ""
	}
}

// fieldBody maps a urlencoded or multipart body: every field is a
// parameter, with what the collection filled in as its default.
func (p *pmImporter) fieldBody(t *adapter.Tool, encoding string, fields []pmField, in *params, loc string) {
	value := mapping()
	for _, f := range fields {
		if f.Disabled || strings.TrimSpace(f.Key) == "" {
			continue
		}
		if f.Type == "file" {
			p.add(Review, loc, "the form field %q is a file picked from disk; the tool sends whatever string it is given under that name instead", f.Key)
		}
		raw := strings.TrimSpace(f.Value)
		if strings.Contains(raw, "{{") {
			mapSet(value, f.Key, str(p.substitute(raw, in, true, loc)))
			continue
		}
		schema := mapping()
		mapSet(schema, "type", str("string"))
		if raw != "" {
			mapSet(schema, "default", str(raw))
		}
		mapSet(value, f.Key, str(in.declare(f.Key, "form field", pmText(&f.Description), schema, false)))
	}
	if len(value.Content) == 0 {
		return
	}
	t.Operation.Body = &adapter.Body{Encoding: encoding, Value: &adapter.Node{N: value}}
}

// graphQLBody sends the document the collection saved. The GraphQL
// importer makes a tool per field of the schema and is the better way in;
// this keeps one request working without pretending to be that.
func (p *pmImporter) graphQLBody(t *adapter.Tool, body *pmBody, in *params, loc string) {
	if body.GraphQL == nil || strings.TrimSpace(body.GraphQL.Query) == "" {
		p.add(Review, loc, "this request has a GraphQL body with no document in it; the tool is imported without a body")
		return
	}
	value := mapping()
	mapSet(value, "query", str(p.substitute(body.GraphQL.Query, in, true, loc)))
	schema := mapping()
	mapSet(schema, "type", str("object"))
	if vars := strings.TrimSpace(body.GraphQL.Variables); vars != "" && vars != "{}" {
		if node, err := adapter.NodeFromJSON([]byte(p.expandConstants(vars))); err == nil && node != nil && node.N != nil {
			mapSet(schema, "default", node.N)
		}
	}
	mapSet(value, "variables", str(in.declare("variables", "document", "The GraphQL variables this operation takes", schema, false)))
	t.Operation.Body = &adapter.Body{Encoding: "json", Value: &adapter.Node{N: value}}
	p.add(Info, loc, "this request posts a GraphQL document; it is imported as it stands, but importing the endpoint as GraphQL gives a tool per field instead of one tool that takes a document")
}

// --- descriptions ----------------------------------------------------------

// description writes what a model reads before choosing this tool: what
// the collection called the request, what its author wrote about it,
// where it sat, and what a successful call came back with.
func (p *pmImporter) description(it *pmItem, req *pmRequest, folders []string, method, path string) string {
	var parts []string
	if written := pmText(&req.Description); written != "" {
		parts = append(parts, written)
	} else if written := pmText(&it.Description); written != "" {
		parts = append(parts, written)
	}
	if len(parts) == 0 {
		name := strings.TrimSpace(it.Name)
		if name == "" {
			name = method + " " + path
		}
		parts = append(parts, fmt.Sprintf("%s. Sends %s %s.", name, method, readableTemplate(path)))
	}
	if len(folders) > 0 {
		parts = append(parts, "From the "+strings.Join(folders, " / ")+" folder of the collection.")
	}
	if example := p.exampleText(it); example != "" {
		parts = append(parts, example)
	}
	out := strings.Join(parts, " ")
	if len(out) < minDescription {
		// A one-line description is thin for a model choosing between
		// twenty tools; saying what the request is is better than nothing.
		out += fmt.Sprintf(" Sends %s %s.", method, readableTemplate(or(path, "/")))
	}
	return out
}

// exampleText quotes a saved successful response, which is often the only
// thing in a collection that says what the request returns.
func (p *pmImporter) exampleText(it *pmItem) string {
	r := pmSuccessExample(it.Response)
	if r == nil {
		return ""
	}
	body := strings.TrimSpace(r.Body)
	if body == "" {
		return ""
	}
	body = strings.Join(strings.Fields(body), " ")
	if len(body) > maxExampleChars {
		body = strings.TrimSpace(body[:maxExampleChars]) + "…"
	}
	status := r.Status
	if status == "" && r.Code > 0 {
		status = fmt.Sprintf("%d", r.Code)
	}
	return "A successful call answered " + or(status, "with") + ": " + body
}

// outputSchema infers what the tool returns from a saved example, so the
// model knows the shape before it calls.
func (p *pmImporter) outputSchema(it *pmItem) *adapter.Node {
	r := pmSuccessExample(it.Response)
	if r == nil || strings.TrimSpace(r.Body) == "" {
		return nil
	}
	node, err := adapter.NodeFromJSON([]byte(r.Body))
	if err != nil || node == nil || node.N == nil {
		return nil
	}
	if node.N.Kind != yaml.MappingNode && node.N.Kind != yaml.SequenceNode {
		return nil
	}
	return &adapter.Node{N: inferSchema(node.N, 0)}
}

// pmSuccessExample picks the example worth describing: the first 2xx, or
// the first of any kind when the collection saved only failures.
func pmSuccessExample(responses []pmResponse) *pmResponse {
	for i := range responses {
		if responses[i].Code >= 200 && responses[i].Code < 300 {
			return &responses[i]
		}
	}
	if len(responses) > 0 {
		return &responses[0]
	}
	return nil
}

// --- reading the polymorphic bits ------------------------------------------

// pmText reads a Postman description, which is a string in some exports
// and {content, type} in others.
func pmText(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return strings.TrimSpace(n.Value)
	case yaml.MappingNode:
		return strings.TrimSpace(scalar(mapGet(n, "content")))
	default:
		return ""
	}
}

// pmScalar reads a variable value, which may be any JSON type.
func pmScalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	return n.Value
}

// pmStrings reads a host or path, which is a list of segments in v2.1 and
// a single string in older exports.
func pmStrings(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value == "" {
			return nil
		}
		return []string{n.Value}
	case yaml.SequenceNode:
		out := make([]string, 0, len(n.Content))
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		return out
	default:
		return nil
	}
}

// pmHeaders reads a header list, which some exports write as one string
// of CRLF-separated lines.
func pmHeaders(n *yaml.Node) []pmHeader {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.SequenceNode:
		var out []pmHeader
		for _, c := range n.Content {
			var h pmHeader
			if err := c.Decode(&h); err == nil {
				out = append(out, h)
			}
		}
		return out
	case yaml.ScalarNode:
		var out []pmHeader
		for _, line := range strings.Split(n.Value, "\n") {
			key, value, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			out = append(out, pmHeader{Key: strings.TrimSpace(key), Value: strings.TrimSpace(value)})
		}
		return out
	default:
		return nil
	}
}

// pmAuthType reads the auth block's type.
func pmAuthType(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.MappingNode {
		return ""
	}
	return strings.TrimSpace(scalar(mapGet(n, "type")))
}

// pmAuthParams reads an auth block's parameters. v2.1 writes a list of
// {key, value} objects and v2.0 wrote a plain object; both appear in
// exports people still have.
func pmAuthParams(n *yaml.Node) map[string]string {
	out := map[string]string{}
	kind := pmAuthType(n)
	if kind == "" {
		return out
	}
	block := mapGet(n, kind)
	if block == nil {
		return out
	}
	switch block.Kind {
	case yaml.SequenceNode:
		for _, c := range block.Content {
			key := scalar(mapGet(c, "key"))
			if key == "" {
				continue
			}
			out[key] = pmScalar(mapGet(c, "value"))
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(block.Content); i += 2 {
			out[block.Content[i].Value] = pmScalar(block.Content[i+1])
		}
	}
	return out
}

// pmScriptNames names the scripts attached at one level, so a finding can
// say which one it means.
func pmScriptNames(events []pmEvent, owner string) []string {
	var out []string
	for _, e := range events {
		if e.Disabled || len(pmStrings(&e.Script.Exec)) == 0 {
			continue
		}
		if code := strings.TrimSpace(strings.Join(pmStrings(&e.Script.Exec), "")); code == "" {
			continue
		}
		out = append(out, e.Listen+" on "+or(owner, "the collection"))
	}
	return out
}

// pmHasVars reports whether any string under a node holds a {{variable}}.
func pmHasVars(n *yaml.Node) bool {
	found := false
	adapter.WalkStrings(n, func(s string) string {
		if strings.Contains(s, "{{") {
			found = true
		}
		return s
	})
	return found
}

// concat returns a new slice, so a caller's slice is never written
// through by a recursive call.
func concat(list []string, more ...string) []string {
	out := make([]string, 0, len(list)+len(more))
	out = append(out, list...)
	return append(out, more...)
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// readableTemplate turns a path template back into something a person
// reads, for descriptions only.
func readableTemplate(path string) string {
	return rePlaceholderParam.ReplaceAllString(path, "{$1}")
}

var rePlaceholderParam = regexp.MustCompile(`\{\{\s*params\.([A-Za-z0-9_$]+)[^}]*\}\}`)
