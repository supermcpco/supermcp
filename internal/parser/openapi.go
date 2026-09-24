// Package parser turns an API description someone else wrote into a
// supermcp adapter.
//
// FromOpenAPI is how a customer brings their own API instead of picking
// one from the catalogue: an OpenAPI 3.0 or 3.1 document goes in, an
// adapter that passes pkg/adapter's validator comes out, and everything
// the importer could not do cleanly comes back as a ImportFinding naming the
// operation it came from. The vocabulary is the one pkg/adapter/v1compat
// already uses: info for a decision worth knowing about, review for a
// judgement call to check, blocker for something the caller must settle
// before the result is usable.
//
// Two rules shape the whole file. The importer never dials anything: a
// document is caller-supplied, so an external $ref is reported rather than
// fetched, or the import endpoint would be a way to make the server reach
// arbitrary hosts. And it never guesses where the document offers a real
// choice: several servers, or a templated one, is a finding, because a
// base URL picked by coin toss sends every later request to the wrong
// place.
package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// Bounds. A document arrives over the network from someone who may not
// wish the server well, so every dimension of the work it causes is
// capped rather than trusted.
const (
	// DefaultMaxBytes caps the document text. The parsed node tree costs
	// roughly an order of magnitude more than the bytes it came from, so
	// this is the real memory bound and not a formality.
	DefaultMaxBytes = 5 << 20

	// DefaultMaxOperations caps how many tools one import may produce.
	// Every tool is a database row and an entry in every tools/list
	// response the model reads; a document with four thousand operations
	// would produce a connector no model can use and a listing no client
	// enjoys.
	DefaultMaxOperations = 200

	// maxRefDepth bounds one chain of $ref indirection. Cycles are caught
	// separately by the pointer stack; this catches a chain that is merely
	// absurd rather than circular.
	maxRefDepth = 20

	// maxSchemaNodes bounds one tool's input schema. A handful of
	// components that reference each other broadly (not circularly) expand
	// into an enormous schema from a tiny document, which cycle detection
	// alone does not prevent.
	maxSchemaNodes = 4000

	// minDescription matches the validator's description-min-60 rule: a
	// shorter description is filled from the summary before giving up.
	minDescription = 60

	// maxToolName keeps a generated name inside what MCP clients display
	// and the tools table stores comfortably.
	maxToolName = 64
)

// Level classifies a finding.
type Level string

const (
	Info    Level = "info"
	Review  Level = "review"
	Blocker Level = "blocker"
)

// ImportFinding is one importer observation. Operation names the operation it
// came from (its operationId, or "GET /pets" when the document gave none)
// and is empty for findings about the document as a whole.
type ImportFinding struct {
	Operation string `json:"operation,omitempty"`
	Level     Level  `json:"level"`
	Path      string `json:"path"`
	Message   string `json:"message"`
}

// HasBlockers reports whether any finding needs a decision from the caller
// before the adapter can be used.
func HasBlockers(findings []ImportFinding) bool {
	for _, f := range findings {
		if f.Level == Blocker {
			return true
		}
	}
	return false
}

// Options are the choices the document cannot make for itself.
type Options struct {
	// Slug, Name, Icon and DocsURL fill adapter metadata; each has a
	// derivation from the document when left empty.
	Slug    string
	Name    string
	Icon    string
	DocsURL string

	// Region and Category default to intl and data: an imported API is
	// not a catalogue entry and nothing in a document says where its
	// vendor is incorporated or which market it serves.
	Region   string
	Category string

	// ServerURL settles which upstream to call when the document lists
	// several or templates one with variables.
	ServerURL string

	// MaxBytes and MaxOperations override the defaults above.
	MaxBytes      int
	MaxOperations int
}

// FromOpenAPI converts an OpenAPI 3.0 or 3.1 document (JSON or YAML) into
// an adapter. The adapter is returned even when there are blocker
// findings, so a caller can show a preview of what an import would create
// alongside the decisions it still needs.
func FromOpenAPI(doc []byte, opts Options) (*adapter.Adapter, []ImportFinding, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if len(doc) > maxBytes {
		return nil, nil, fmt.Errorf("document is %d bytes, over the %d byte limit", len(doc), maxBytes)
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
	var d document
	if err := root.Decode(&d); err != nil {
		return nil, nil, fmt.Errorf("decode document: %w", err)
	}
	switch {
	case strings.HasPrefix(d.OpenAPI, "3.0"), strings.HasPrefix(d.OpenAPI, "3.1"):
	case d.Swagger != "":
		return nil, nil, fmt.Errorf("swagger %s is not supported; convert the document to openapi 3 first", d.Swagger)
	case d.OpenAPI == "":
		return nil, nil, errors.New("document has no openapi version field")
	default:
		return nil, nil, fmt.Errorf("openapi version %q is not supported", d.OpenAPI)
	}

	im := &importer{opts: opts, root: root, doc: &d, names: map[string]bool{}, max: opts.MaxOperations}
	if im.max <= 0 {
		im.max = DefaultMaxOperations
	}

	out := &adapter.Adapter{APIVersion: adapter.APIVersion, Kind: adapter.KindName}
	im.metadata(out)
	im.transport(out)
	im.auth(out)
	im.tools(out)
	if len(out.Tools) == 0 {
		return nil, im.findings, errors.New("document declares no operations")
	}
	return out, im.findings, nil
}

// importer carries the state of one conversion.
type importer struct {
	opts     Options
	root     *yaml.Node
	doc      *document
	findings []ImportFinding
	names    map[string]bool // tool names taken so far
	prefix   string          // slug-derived tool name prefix
	base     string          // chosen server URL
	max      int
	op       string // the operation findings are attributed to
}

func (im *importer) add(level Level, path, format string, args ...any) {
	im.findings = append(im.findings, ImportFinding{Operation: im.op, Level: level, Path: path, Message: fmt.Sprintf(format, args...)})
}

// --- document model --------------------------------------------------------
//
// Only the parts the adapter format can express are modelled. Everything
// else in the document (responses, callbacks, links, examples, extensions)
// is ignored on purpose; see the package documentation for why.

type document struct {
	OpenAPI      string                          `yaml:"openapi"`
	Swagger      string                          `yaml:"swagger"`
	Info         info                            `yaml:"info"`
	Servers      []server                        `yaml:"servers"`
	Paths        adapter.OrderedMap[pathItem]    `yaml:"paths"`
	Webhooks     adapter.OrderedMap[yaml.Node]   `yaml:"webhooks"`
	Components   components                      `yaml:"components"`
	Security     *[]adapter.OrderedMap[[]string] `yaml:"security"`
	ExternalDocs externalDocs                    `yaml:"externalDocs"`
}

type info struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Version     string `yaml:"version"`
	Contact     struct {
		URL string `yaml:"url"`
	} `yaml:"contact"`
}

type externalDocs struct {
	URL string `yaml:"url"`
}

type server struct {
	URL         string                             `yaml:"url"`
	Description string                             `yaml:"description"`
	Variables   adapter.OrderedMap[serverVariable] `yaml:"variables"`
}

type serverVariable struct {
	Default string   `yaml:"default"`
	Enum    []string `yaml:"enum"`
}

type pathItem struct {
	Ref        string      `yaml:"$ref"`
	Summary    string      `yaml:"summary"`
	Parameters []parameter `yaml:"parameters"`
	Get        *operation  `yaml:"get"`
	Put        *operation  `yaml:"put"`
	Post       *operation  `yaml:"post"`
	Delete     *operation  `yaml:"delete"`
	Options    *operation  `yaml:"options"`
	Head       *operation  `yaml:"head"`
	Patch      *operation  `yaml:"patch"`
	Trace      *operation  `yaml:"trace"`
}

type operation struct {
	OperationID string                          `yaml:"operationId"`
	Summary     string                          `yaml:"summary"`
	Description string                          `yaml:"description"`
	Deprecated  bool                            `yaml:"deprecated"`
	Parameters  []parameter                     `yaml:"parameters"`
	RequestBody *requestBody                    `yaml:"requestBody"`
	Security    *[]adapter.OrderedMap[[]string] `yaml:"security"`
}

type parameter struct {
	Ref         string    `yaml:"$ref"`
	Name        string    `yaml:"name"`
	In          string    `yaml:"in"`
	Description string    `yaml:"description"`
	Required    bool      `yaml:"required"`
	Deprecated  bool      `yaml:"deprecated"`
	Style       string    `yaml:"style"`
	Schema      yaml.Node `yaml:"schema"`
}

type requestBody struct {
	Ref         string                        `yaml:"$ref"`
	Description string                        `yaml:"description"`
	Required    bool                          `yaml:"required"`
	Content     adapter.OrderedMap[mediaType] `yaml:"content"`
}

type mediaType struct {
	Schema yaml.Node `yaml:"schema"`
}

type components struct {
	SecuritySchemes adapter.OrderedMap[securityScheme] `yaml:"securitySchemes"`
}

type securityScheme struct {
	Ref              string `yaml:"$ref"`
	Type             string `yaml:"type"`
	Description      string `yaml:"description"`
	Name             string `yaml:"name"`
	In               string `yaml:"in"`
	Scheme           string `yaml:"scheme"`
	BearerFormat     string `yaml:"bearerFormat"`
	OpenIDConnectURL string `yaml:"openIdConnectUrl"`
	Flows            struct {
		ClientCredentials *oauthFlow `yaml:"clientCredentials"`
		AuthorizationCode *oauthFlow `yaml:"authorizationCode"`
		Password          *oauthFlow `yaml:"password"`
		Implicit          *oauthFlow `yaml:"implicit"`
	} `yaml:"flows"`
}

type oauthFlow struct {
	AuthorizationURL string                     `yaml:"authorizationUrl"`
	TokenURL         string                     `yaml:"tokenUrl"`
	RefreshURL       string                     `yaml:"refreshUrl"`
	Scopes           adapter.OrderedMap[string] `yaml:"scopes"`
}

// --- metadata --------------------------------------------------------------

func (im *importer) metadata(out *adapter.Adapter) {
	slug := im.opts.Slug
	if slug == "" {
		slug = kebab(im.doc.Info.Title)
	}
	if slug == "" {
		slug = "imported-api"
		im.add(Review, "metadata.slug", "document has no title; the connector is slugged %q", slug)
	}
	name := im.opts.Name
	if name == "" {
		name = im.doc.Info.Title
	}
	if name == "" {
		name = slug
	}
	description := strings.TrimSpace(im.doc.Info.Description)
	if description == "" {
		// The title is the only prose the document offers. Saying so beats
		// inventing a sentence about an API we have never seen.
		description = name
		im.add(Info, "metadata.description", "document has no info.description; the title is used instead")
	}
	out.Metadata = adapter.Metadata{
		Slug:        slug,
		Name:        name,
		Description: firstLine(description),
		Region:      or(im.opts.Region, "intl"),
		Category:    or(im.opts.Category, "data"),
	}
	out.Instructions = strings.TrimSpace(im.doc.Info.Description)
	im.prefix = strings.ReplaceAll(slug, "-", "_") + "_"
}

// docsAndIcon fills the two metadata fields the validator requires and no
// OpenAPI document carries directly. It runs after the server is chosen
// because both fall back to the upstream host.
func (im *importer) docsAndIcon(out *adapter.Adapter) {
	out.Metadata.DocsURL = im.opts.DocsURL
	if out.Metadata.DocsURL == "" {
		out.Metadata.DocsURL = or(im.doc.ExternalDocs.URL, im.doc.Info.Contact.URL)
	}
	if out.Metadata.DocsURL == "" {
		out.Metadata.DocsURL = im.base
		im.add(Info, "metadata.docsUrl", "document links to no documentation; the base URL is used")
	}
	out.Metadata.Icon = im.opts.Icon
	if out.Metadata.Icon == "" {
		if u, err := url.Parse(im.base); err == nil && u.Host != "" {
			out.Metadata.Icon = u.Scheme + "://" + u.Host + "/favicon.ico"
		}
	}
	if out.Metadata.Icon == "" {
		out.Metadata.Icon = out.Metadata.DocsURL
	}
}

// --- transport -------------------------------------------------------------

func (im *importer) transport(out *adapter.Adapter) {
	out.Transport.Type = adapter.TransportHTTP
	im.base = im.chooseBase()
	out.Transport.BaseURL = im.base
	im.docsAndIcon(out)
}

// chooseBase settles which upstream the connector calls, or returns
// nothing and a blocker when the document leaves the choice open.
func (im *importer) chooseBase() string {
	if im.opts.ServerURL != "" {
		if err := checkAbsolute(im.opts.ServerURL); err != nil {
			im.add(Blocker, "transport.baseUrl", "the supplied server URL is unusable: %v", err)
			return ""
		}
		if len(im.doc.Servers) > 1 {
			im.add(Info, "transport.baseUrl", "document lists %d servers; the supplied URL is used", len(im.doc.Servers))
		}
		return strings.TrimRight(im.opts.ServerURL, "/")
	}

	switch len(im.doc.Servers) {
	case 0:
		im.add(Blocker, "transport.baseUrl", "document declares no servers; supply the base URL with the import")
		return ""
	case 1:
	default:
		urls := make([]string, 0, len(im.doc.Servers))
		for _, s := range im.doc.Servers {
			urls = append(urls, s.URL)
		}
		im.add(Blocker, "transport.baseUrl", "document lists %d servers (%s); choose one and supply it with the import",
			len(urls), strings.Join(urls, ", "))
		// The first server still fills the preview, so a caller can see
		// what the rest of the import would look like.
		return strings.TrimRight(urls[0], "/")
	}

	s := im.doc.Servers[0]
	if vars := templateVars(s.URL); len(vars) > 0 {
		// Expanding the defaults is exactly the guess that sends every
		// request to someone else's tenant.
		parts := make([]string, 0, len(vars))
		for _, v := range vars {
			sv, _ := s.Variables.Get(v)
			parts = append(parts, fmt.Sprintf("%s (default %q)", v, sv.Default))
		}
		im.add(Blocker, "transport.baseUrl", "server URL %s is templated on %s; supply the resolved base URL with the import",
			s.URL, strings.Join(parts, ", "))
		return ""
	}
	if err := checkAbsolute(s.URL); err != nil {
		im.add(Blocker, "transport.baseUrl", "server URL %q is unusable: %v; supply the base URL with the import", s.URL, err)
		return ""
	}
	return strings.TrimRight(s.URL, "/")
}

func checkAbsolute(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("it is not an absolute http URL")
	}
	if u.Host == "" {
		return errors.New("it has no host")
	}
	return nil
}

var reTemplateVar = regexp.MustCompile(`\{([^{}/]+)\}`)

func templateVars(s string) []string {
	var out []string
	for _, m := range reTemplateVar.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// --- auth ------------------------------------------------------------------

// Credential names are fixed per auth kind rather than derived from the
// scheme name. An adapter has one auth block, so there is never more than
// one of each, and a name that does not move between imports is worth more
// than one that echoes whatever the document called its scheme.
const (
	credToken        = "API_TOKEN"
	credKey          = "API_KEY"
	credUsername     = "API_USERNAME"
	credPassword     = "API_PASSWORD"
	credClientID     = "OAUTH_CLIENT_ID"     //nolint:gosec // the name of a credential, not one
	credClientSecret = "OAUTH_CLIENT_SECRET" //nolint:gosec // the name of a credential, not one
)

func (im *importer) auth(out *adapter.Adapter) {
	out.Auth.Type = adapter.AuthNone
	out.Credentials = adapter.NewOrderedMap[adapter.Credential]()

	reqs := im.doc.Security
	if reqs == nil || len(*reqs) == 0 {
		if im.doc.Components.SecuritySchemes.Len() > 0 {
			im.add(Info, "auth", "document declares security schemes but requires none globally; the connector is unauthenticated")
		}
		return
	}
	for _, req := range *reqs {
		if req.Len() == 0 {
			// An empty requirement object means "no authentication is also
			// acceptable"; it is not a scheme to import.
			continue
		}
		if req.Len() > 1 {
			im.add(Review, "auth", "security requirement combines %s; an adapter holds one auth block, so only the first that is supported is used",
				strings.Join(req.Keys, " and "))
		}
		for _, name := range req.Keys {
			scopes, _ := req.Get(name)
			scheme, ok := im.doc.Components.SecuritySchemes.Get(name)
			if !ok {
				im.add(Review, "auth", "security scheme %q is required but not declared in components", name)
				continue
			}
			if im.applyScheme(name, scheme, scopes, out) {
				return
			}
		}
	}
	if out.Auth.Type == adapter.AuthNone {
		im.add(Review, "auth", "no supported security scheme; the connector is created unauthenticated and needs its auth block filled in by hand")
	}
}

// applyScheme fills the auth block from one scheme, reporting whether it
// did. An unsupported scheme leaves the connector unauthenticated rather
// than authenticated the wrong way.
func (im *importer) applyScheme(name string, s securityScheme, scopes []string, out *adapter.Adapter) bool {
	cred := func(key, description string, secret bool) string {
		out.Credentials.Set(key, adapter.Credential{Required: true, Secret: secret, Description: description})
		return "{{env." + key + "}}"
	}
	switch s.Type {
	case "http":
		switch strings.ToLower(s.Scheme) {
		case "bearer":
			out.Auth = adapter.Auth{Type: adapter.AuthBearer, Token: cred(credToken, "Bearer token for "+out.Metadata.Name, true)}
			return true
		case "basic":
			out.Auth = adapter.Auth{
				Type:     adapter.AuthBasic,
				Username: cred(credUsername, "HTTP basic username", false),
				Password: cred(credPassword, "HTTP basic password", true),
			}
			return true
		default:
			im.add(Review, "auth", "security scheme %q uses http scheme %q, which is not supported", name, s.Scheme)
		}
	case "apiKey":
		switch s.In {
		case "header", "query":
			out.Auth = adapter.Auth{
				Type:  adapter.AuthAPIKey,
				In:    s.In,
				Name:  s.Name,
				Value: cred(credKey, fmt.Sprintf("API key sent as the %q %s", s.Name, s.In), true),
			}
			return true
		default:
			// in: cookie is left out deliberately: see the package notes.
			im.add(Review, "auth", "security scheme %q puts its API key in %q, which is not supported", name, s.In)
		}
	case "oauth2":
		return im.applyOAuth2(name, s, scopes, out, cred)
	case "openIdConnect":
		im.add(Review, "auth", "security scheme %q is openIdConnect; its configuration lives behind %s, which this importer will not fetch", name, s.OpenIDConnectURL)
	case "mutualTLS":
		im.add(Review, "auth", "security scheme %q is mutualTLS; the certificate and key are not in the document", name)
	default:
		im.add(Review, "auth", "security scheme %q has unknown type %q", name, s.Type)
	}
	return false
}

func (im *importer) applyOAuth2(name string, s securityScheme, scopes []string, out *adapter.Adapter, cred func(string, string, bool) string) bool {
	auth := adapter.Auth{
		Type:         adapter.AuthOAuth2,
		ClientID:     cred(credClientID, "OAuth2 client id", false),
		ClientSecret: cred(credClientSecret, "OAuth2 client secret", true),
		Scopes:       scopes,
	}
	switch {
	case s.Flows.ClientCredentials != nil:
		auth.Grant = "client_credentials"
		auth.TokenURL = im.absolute(s.Flows.ClientCredentials.TokenURL)
		if len(auth.Scopes) == 0 {
			auth.Scopes = s.Flows.ClientCredentials.Scopes.Keys
		}
	case s.Flows.AuthorizationCode != nil:
		auth.Grant = "authorization_code"
		auth.TokenURL = im.absolute(s.Flows.AuthorizationCode.TokenURL)
		auth.AuthorizationURL = im.absolute(s.Flows.AuthorizationCode.AuthorizationURL)
		if len(auth.Scopes) == 0 {
			auth.Scopes = s.Flows.AuthorizationCode.Scopes.Keys
		}
	default:
		which := "none"
		if s.Flows.Password != nil {
			which = "password"
		}
		if s.Flows.Implicit != nil {
			which = "implicit"
		}
		im.add(Review, "auth", "security scheme %q offers only the %s flow, which is not supported", name, which)
		im.dropCredentials(out, credClientID, credClientSecret)
		return false
	}
	if auth.TokenURL == "" {
		im.add(Review, "auth", "security scheme %q declares no token URL", name)
		im.dropCredentials(out, credClientID, credClientSecret)
		return false
	}
	out.Auth = auth
	return true
}

// dropCredentials removes credentials that were declared for an auth block
// that turned out not to be usable; the validator rejects a credential
// nothing references.
func (im *importer) dropCredentials(out *adapter.Adapter, names ...string) {
	drop := map[string]bool{}
	for _, n := range names {
		drop[n] = true
	}
	kept := adapter.NewOrderedMap[adapter.Credential]()
	for _, k := range out.Credentials.Keys {
		if drop[k] {
			continue
		}
		v, _ := out.Credentials.Get(k)
		kept.Set(k, v)
	}
	out.Credentials = kept
}

// absolute resolves a URL that the document may have written relative to
// the server, which OpenAPI 3.1 permits.
func (im *importer) absolute(raw string) string {
	if raw == "" || strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	base, err := url.Parse(im.base)
	if err != nil {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return base.ResolveReference(ref).String()
}

// --- tools -----------------------------------------------------------------

// methods is the order operations are read in, which is the order the
// specification lists them. A fixed order means two imports of one
// document produce the same tools in the same order.
var methods = []struct {
	name string
	pick func(*pathItem) *operation
}{
	{"GET", func(p *pathItem) *operation { return p.Get }},
	{"PUT", func(p *pathItem) *operation { return p.Put }},
	{"POST", func(p *pathItem) *operation { return p.Post }},
	{"DELETE", func(p *pathItem) *operation { return p.Delete }},
	{"OPTIONS", func(p *pathItem) *operation { return p.Options }},
	{"HEAD", func(p *pathItem) *operation { return p.Head }},
	{"PATCH", func(p *pathItem) *operation { return p.Patch }},
}

func (im *importer) tools(out *adapter.Adapter) {
	if im.doc.Webhooks.Len() > 0 {
		im.add(Info, "webhooks", "the document's webhooks are skipped; an adapter calls upstream and does not receive callbacks")
	}
	for _, path := range im.doc.Paths.Keys {
		item, _ := im.doc.Paths.Get(path)
		if item.Ref != "" {
			var resolved pathItem
			node, err := im.resolve(item.Ref)
			if err != nil {
				im.op = ""
				im.add(Review, "paths."+path, "path item reference %q is not resolved: %v", item.Ref, err)
				continue
			}
			if err := node.Decode(&resolved); err != nil {
				im.op = ""
				im.add(Review, "paths."+path, "path item reference %q does not decode: %v", item.Ref, err)
				continue
			}
			item = resolved
		}
		if item.Trace != nil {
			im.op = ""
			im.add(Info, "paths."+path, "TRACE is not an MCP tool; it is skipped")
		}
		for _, m := range methods {
			op := m.pick(&item)
			if op == nil {
				continue
			}
			if len(out.Tools) >= im.max {
				im.op = ""
				im.add(Blocker, "paths", "document has more than %d operations; the import stops there, so narrow the document or raise the limit", im.max)
				return
			}
			out.Tools = append(out.Tools, im.tool(m.name, path, item.Parameters, op))
		}
	}
}

func (im *importer) tool(method, path string, shared []parameter, op *operation) adapter.Tool {
	im.op = op.OperationID
	if im.op == "" {
		im.op = method + " " + path
	}
	loc := "paths." + path + "." + strings.ToLower(method)

	t := adapter.Tool{Name: im.toolName(op.OperationID, method, path, loc)}
	t.Description = im.description(op, method, path, loc)
	switch method {
	case "GET", "HEAD":
		t.Annotations = &adapter.Annotations{ReadOnlyHint: ptr(true)}
	case "DELETE":
		t.Annotations = &adapter.Annotations{DestructiveHint: ptr(true)}
	}
	if op.Deprecated {
		im.add(Info, loc, "operation is marked deprecated; it is imported anyway, disable the tool if you do not want it")
	}
	if op.Security != nil {
		im.add(Review, loc, "operation overrides the document's security; an adapter has one auth block, so the connector's auth is used for this tool too")
	}
	im.operation(&t, method, path, im.parameters(shared, op.Parameters, loc), op.RequestBody, loc)
	return t
}

// parameters merges the path item's parameters with the operation's; an
// operation parameter with the same name and location replaces the shared
// one, which is what the specification says.
func (im *importer) parameters(shared, own []parameter, loc string) []parameter {
	resolve := func(p parameter) (parameter, bool) {
		if p.Ref == "" {
			return p, true
		}
		node, err := im.resolve(p.Ref)
		if err != nil {
			im.add(Review, loc+".parameters", "parameter reference %q is not resolved: %v", p.Ref, err)
			return p, false
		}
		var out parameter
		if err := node.Decode(&out); err != nil {
			im.add(Review, loc+".parameters", "parameter reference %q does not decode: %v", p.Ref, err)
			return p, false
		}
		return out, true
	}
	var merged []parameter
	index := map[string]int{}
	for _, list := range [][]parameter{shared, own} {
		for _, p := range list {
			r, ok := resolve(p)
			if !ok {
				continue
			}
			key := r.In + " " + r.Name
			if i, dup := index[key]; dup {
				merged[i] = r
				continue
			}
			index[key] = len(merged)
			merged = append(merged, r)
		}
	}
	return merged
}

// inputBuilder accumulates a tool's input schema while its HTTP mapping is
// built, so the property a model fills in and the placeholder that reads it
// are always created together and cannot drift apart.
type inputBuilder struct {
	im       *importer
	loc      string
	props    *yaml.Node
	required []string
	taken    map[string]string // property name -> what already claimed it
}

// add declares one property and returns the name the placeholder must use.
// schema is already converted to the adapter subset, or nil for a property
// the importer describes itself.
func (b *inputBuilder) add(name, origin string, schema *yaml.Node, description string, required bool) string {
	key := propName(name)
	if prev, dup := b.taken[key]; dup {
		key = propName(strings.ReplaceAll(origin, " ", "_") + "_" + name)
		b.im.add(Review, b.loc, "%s %q collides with the %s of the same name; it is exposed as %q", origin, name, prev, key)
	} else if key != name {
		b.im.add(Info, b.loc, "%s %q is exposed as %q, because a tool parameter name may hold only letters, digits and underscores", origin, name, key)
	}
	b.taken[key] = origin
	if schema == nil {
		schema = mapping()
	}
	if description != "" && mapGet(schema, "description") == nil {
		mapSet(schema, "description", str(description))
	}
	mapSet(b.props, key, schema)
	if required {
		b.required = append(b.required, key)
	}
	return key
}

// schema builds the finished input schema. properties is always present,
// empty or not, because the adapter schema requires it.
func (b *inputBuilder) schema() *adapter.Node {
	input := mapping()
	mapSet(input, "type", str("object"))
	mapSet(input, "properties", b.props)
	if len(b.required) > 0 {
		mapSet(input, "required", strSeq(b.required))
	}
	return &adapter.Node{N: input}
}

// operation fills the tool's input schema and its HTTP mapping.
func (im *importer) operation(t *adapter.Tool, method, path string, params []parameter, body *requestBody, loc string) {
	in := &inputBuilder{im: im, loc: loc, props: mapping(), taken: map[string]string{}}

	query := mapping()
	cookies := make([]string, 0, 2)
	for _, p := range params {
		origin := p.In + " parameter"
		schema := im.schema(&p.Schema, loc+"."+p.In+"."+p.Name)
		switch p.In {
		case "path":
			// A path parameter is always required, whatever the document says.
			key := in.add(p.Name, origin, schema, p.Description, true)
			path = strings.ReplaceAll(path, "{"+p.Name+"}", "{{params."+key+"}}")
		case "query":
			key := in.add(p.Name, origin, schema, p.Description, p.Required)
			mapSet(query, p.Name, str("{{params."+key+"}}"))
			if p.Style == "deepObject" {
				im.add(Review, loc, "query parameter %q uses style deepObject; it is sent as one encoded value instead", p.Name)
			}
		case "header":
			key := in.add(p.Name, origin, schema, p.Description, p.Required)
			t.Operation.Headers.Set(p.Name, "{{params."+key+"}}")
		case "cookie":
			key := in.add(p.Name, origin, schema, p.Description, p.Required)
			cookies = append(cookies, p.Name+"={{params."+key+"}}")
		default:
			im.add(Review, loc, "parameter %q has location %q, which is not one of path, query, header or cookie", p.Name, p.In)
		}
	}
	switch {
	case len(cookies) == 1:
		t.Operation.Headers.Set("Cookie", cookies[0])
	case len(cookies) > 1:
		// One Cookie header carries them all, so it is rendered as a whole
		// and disappears if any one of them is missing.
		t.Operation.Headers.Set("Cookie", strings.Join(cookies, "; "))
		im.add(Review, loc, "the operation takes %d cookie parameters; they share one Cookie header, so all of them must be supplied together", len(cookies))
	}
	for _, name := range templateVars(path) {
		if !strings.HasPrefix(name, "params.") {
			im.add(Review, loc, "path placeholder {%s} has no parameter declaration; it is left in the URL as written", name)
		}
	}

	t.Operation.Method = method
	t.Operation.Path = path
	if len(query.Content) > 0 {
		t.Operation.Query = &adapter.Node{N: query}
	}
	if body != nil {
		im.body(t, method, body, in, loc)
	}
	t.Input = in.schema()
}

// body maps the request body onto the tool's input. An object body is
// flattened into named parameters, because a model fills those in more
// reliably than it nests one object; anything else becomes a single
// parameter.
func (im *importer) body(t *adapter.Tool, method string, body *requestBody, in *inputBuilder, loc string) {
	loc += ".requestBody"
	if body.Ref != "" {
		node, err := im.resolve(body.Ref)
		if err != nil {
			im.add(Review, loc, "request body reference %q is not resolved: %v", body.Ref, err)
			return
		}
		var resolved requestBody
		if err := node.Decode(&resolved); err != nil {
			im.add(Review, loc, "request body reference %q does not decode: %v", body.Ref, err)
			return
		}
		body = &resolved
	}
	if method == "GET" || method == "HEAD" {
		im.add(Info, loc, "a %s request body is declared; nothing sends one, so it is dropped", method)
		return
	}
	mediaName, media, encoding, ok := im.pickMedia(body, loc)
	if !ok {
		return
	}
	description := strings.TrimSpace(body.Description)
	if encoding == "raw" {
		raw := mapping()
		mapSet(raw, "type", str("string"))
		key := in.add("body", "body", raw, or(description, "Request body, sent as "+mediaName), body.Required)
		t.Operation.Headers.Set("Content-Type", mediaName)
		t.Operation.Body = &adapter.Body{Encoding: "raw", Value: &adapter.Node{N: str("{{params." + key + "}}")}}
		return
	}

	schema := im.schema(&media.Schema, loc)
	fields := mapGet(schema, "properties")
	if typeOf(schema) != "object" || fields == nil {
		// A body that is an array, a scalar or an unconstrained object is
		// one argument: there are no members to name.
		key := in.add("body", "body", schema, description, body.Required)
		t.Operation.Body = &adapter.Body{Encoding: encoding, Value: &adapter.Node{N: str("{{params." + key + "}}")}}
		return
	}
	bodyRequired := map[string]bool{}
	for _, r := range seqStrings(mapGet(schema, "required")) {
		bodyRequired[r] = true
	}
	value := mapping()
	for i := 0; i+1 < len(fields.Content); i += 2 {
		name := fields.Content[i].Value
		// A field is required only when the body itself is: an optional
		// body's members cannot be obligatory.
		key := in.add(name, "body field", fields.Content[i+1], "", bodyRequired[name] && body.Required)
		mapSet(value, name, str("{{params."+key+"}}"))
	}
	t.Operation.Body = &adapter.Body{Encoding: encoding, Value: &adapter.Node{N: value}}
}

// pickMedia chooses the media type to send. JSON first: it is what the
// adapter format encodes natively and what most APIs accept.
func (im *importer) pickMedia(body *requestBody, loc string) (name string, media mediaType, encoding string, ok bool) {
	if body.Content.Len() == 0 {
		im.add(Review, loc, "request body declares no content; the tool sends none")
		return "", mediaType{}, "", false
	}
	var jsonLike, form, multipart, other string
	for _, k := range body.Content.Keys {
		base := strings.TrimSpace(strings.SplitN(k, ";", 2)[0])
		switch {
		case base == "application/json" && jsonLike == "":
			jsonLike = k
		case strings.HasSuffix(base, "+json") && jsonLike == "":
			jsonLike = k
		case base == "application/x-www-form-urlencoded" && form == "":
			form = k
		case base == "multipart/form-data" && multipart == "":
			multipart = k
		case other == "":
			other = k
		}
	}
	switch {
	case jsonLike != "":
		name, encoding = jsonLike, "json"
	case form != "":
		name, encoding = form, "form"
	case multipart != "":
		name, encoding = multipart, "multipart"
		im.add(Info, loc, "body is multipart/form-data; file parts are sent as their string contents")
	default:
		name, encoding = other, "raw"
		im.add(Review, loc, "body media type %q has no structured encoding; the tool takes the body as one string parameter", other)
	}
	media, _ = body.Content.Get(name)
	if body.Content.Len() > 1 {
		im.add(Info, loc, "body offers %d media types; %s is used", body.Content.Len(), name)
	}
	return name, media, encoding, true
}

// --- naming ----------------------------------------------------------------

var reToolName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// toolName settles on a stable name. An operationId is used when there is
// one, because it is the only identifier in the document that its author
// promised not to move; a derived name is reported, since it changes the
// moment the path does and every client that used it breaks.
func (im *importer) toolName(operationID, method, path, loc string) string {
	name := snake(operationID)
	if name == "" {
		name = snake(method + "_" + pathWords(path))
		im.add(Review, loc, "operation has no operationId; the tool is named from the method and path, so it will change if the path does")
	}
	if !strings.HasPrefix(name, im.prefix) {
		name = im.prefix + name
	}
	if len(name) > maxToolName {
		name = strings.Trim(name[:maxToolName], "_")
		im.add(Info, loc, "tool name is truncated to %q", name)
	}
	if !reToolName.MatchString(name) {
		name = "tool_" + name
	}
	if im.names[name] {
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s_%d", name, n)
			if !im.names[candidate] {
				im.add(Review, loc, "tool name %q is already taken by another operation; this one is %q", name, candidate)
				name = candidate
				break
			}
		}
	}
	im.names[name] = true
	return name
}

// description prefers the operation's description and falls back to the
// summary, which is what the validator's 60-character minimum is really
// asking for. When the document says nothing, it says so rather than
// writing filler a model would have to read.
func (im *importer) description(op *operation, method, path, loc string) string {
	description := strings.TrimSpace(op.Description)
	summary := strings.TrimSpace(op.Summary)
	switch {
	case description == "" && summary == "":
		im.add(Review, loc, "operation has neither summary nor description; the tool is described by its method and path, which is thin for a model")
		return method + " " + path
	case description == "":
		return summary
	case len(description) < minDescription && summary != "" && !strings.Contains(description, summary):
		return summary + ". " + description
	default:
		return description
	}
}

// A dot is replaced along with everything else that is not a letter,
// digit, underscore or dollar: {{params.a.b}} would be read as a path into
// a nested object rather than as the name "a.b". Dollars survive because
// OData parameters are called $top and $filter.
var rePropName = regexp.MustCompile(`[^A-Za-z0-9_$]+`)

// propName makes a parameter name usable as a tool parameter. The wire
// name is kept in the operation mapping, so a rename here changes only
// what the model is asked for.
func propName(s string) string {
	out := rePropName.ReplaceAllString(s, "_")
	out = strings.Trim(out, "_")
	if out == "" {
		return "value"
	}
	if r := rune(out[0]); unicode.IsDigit(r) {
		out = "p_" + out
	}
	return out
}

var reNotAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// snake turns anything into lower_snake_case, splitting camelCase.
func snake(s string) string {
	var sb strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if unicode.IsUpper(r) && i > 0 && (unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
			sb.WriteByte('_')
		}
		sb.WriteRune(unicode.ToLower(r))
	}
	out := reNotAlnum.ReplaceAllString(sb.String(), "_")
	out = strings.Trim(out, "_")
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}
	if out != "" && unicode.IsDigit(rune(out[0])) {
		out = "v" + out
	}
	return out
}

// pathWords turns /pets/{petId}/toys into pets_by_pet_id_toys.
func pathWords(path string) string {
	var parts []string
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			parts = append(parts, "by", strings.Trim(seg, "{}"))
			continue
		}
		parts = append(parts, seg)
	}
	return strings.Join(parts, "_")
}

func kebab(s string) string {
	out := strings.ReplaceAll(snake(s), "_", "-")
	if out != "" && unicode.IsDigit(rune(out[0])) {
		// A tool name prefix is derived from the slug and must start with
		// a letter.
		out = "api-" + out
	}
	return out
}

// --- schemas ---------------------------------------------------------------

// schema converts one OpenAPI schema into the JSON Schema subset the
// adapter format accepts: references resolved inside the document,
// compositions folded or dropped, and nothing the validator forbids left
// in it.
func (im *importer) schema(n *yaml.Node, where string) *yaml.Node {
	if n != nil && n.Kind == 0 {
		// A field the document left out decodes into a zero node.
		return mapping()
	}
	s := &schemaConv{im: im, where: where, budget: maxSchemaNodes}
	out := s.convert(n, 0)
	if out == nil || out.Kind != yaml.MappingNode {
		return mapping()
	}
	return out
}

type schemaConv struct {
	im     *importer
	where  string
	budget int
	stack  []string // reference pointers being resolved, innermost last
}

// keys dropped without comment: they describe the document or the wire
// format, not the shape of a value a model fills in.
var quietlyDropped = map[string]bool{
	"$defs": true, "definitions": true, "$schema": true, "$id": true, "$comment": true,
	"discriminator": true, "xml": true, "externalDocs": true, "deprecated": true,
	"readOnly": true, "writeOnly": true, "example": true, "examples": true,
}

// keys dropped with a finding: each one constrains the value in a way the
// model will no longer be told about.
var loudlyDropped = map[string]bool{
	"oneOf": true, "anyOf": true, "not": true, "if": true, "then": true, "else": true,
	"patternProperties": true, "dependencies": true, "dependentSchemas": true,
	"dependentRequired": true, "prefixItems": true, "unevaluatedProperties": true,
}

func (c *schemaConv) convert(n *yaml.Node, depth int) *yaml.Node {
	if n == nil {
		return mapping()
	}
	if c.budget <= 0 {
		return mapping()
	}
	c.budget--
	if n.Kind == yaml.AliasNode {
		// YAML aliases are rejected at parse time; this is belt and braces.
		return mapping()
	}
	if n.Kind != yaml.MappingNode {
		return copyNode(n, &c.budget)
	}
	if ref := mapGet(n, "$ref"); ref != nil && ref.Kind == yaml.ScalarNode {
		return c.deref(n, ref.Value, depth)
	}
	if all := mapGet(n, "allOf"); all != nil {
		return c.mergeAllOf(n, all, depth)
	}
	return c.fields(n, depth)
}

// deref resolves an internal reference. External references are never
// fetched: this runs on a server and an import must not be a way to make
// it dial a URL of the caller's choosing.
func (c *schemaConv) deref(n *yaml.Node, ref string, depth int) *yaml.Node {
	switch {
	case !strings.HasPrefix(ref, "#/"):
		c.im.add(Review, c.where, "reference %q points outside the document; it is not fetched, so the schema here is unconstrained", ref)
		return mapping()
	case depth >= maxRefDepth:
		c.im.add(Review, c.where, "reference chain at %q is deeper than %d; it is cut off here", ref, maxRefDepth)
		return mapping()
	}
	for _, seen := range c.stack {
		if seen == ref {
			// A self-referential schema (a tree, a comment thread) is legal
			// and common; refusing to follow the loop keeps the rest of the
			// schema and terminates.
			c.im.add(Review, c.where, "reference %q is a cycle; the schema is cut where it repeats", ref)
			return mapping()
		}
	}
	target, err := c.im.resolve(ref)
	if err != nil {
		c.im.add(Review, c.where, "reference %q is not resolved: %v", ref, err)
		return mapping()
	}
	c.stack = append(c.stack, ref)
	out := c.convert(target, depth+1)
	c.stack = c.stack[:len(c.stack)-1]
	// OpenAPI 3.1 allows keys beside a $ref; they refine the target.
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "$ref" {
			continue
		}
		mapSet(out, n.Content[i].Value, c.convert(n.Content[i+1], depth))
	}
	return out
}

// mergeAllOf folds the members into one schema, which is what allOf means
// for the object schemas APIs use it for. Properties union, required
// concatenates, and any other key is taken from the first member that
// states it.
func (c *schemaConv) mergeAllOf(n, all *yaml.Node, depth int) *yaml.Node {
	out := mapping()
	merge := func(src *yaml.Node) {
		if src == nil || src.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(src.Content); i += 2 {
			key, val := src.Content[i].Value, src.Content[i+1]
			switch key {
			case "properties":
				props := mapGet(out, "properties")
				if props == nil {
					props = mapping()
					mapSet(out, "properties", props)
				}
				for j := 0; j+1 < len(val.Content); j += 2 {
					mapSet(props, val.Content[j].Value, val.Content[j+1])
				}
			case "required":
				req := mapGet(out, "required")
				if req == nil {
					req = sequence()
					mapSet(out, "required", req)
				}
				for _, r := range val.Content {
					if !containsScalar(req, r.Value) {
						req.Content = append(req.Content, r)
					}
				}
			default:
				if mapGet(out, key) == nil {
					mapSet(out, key, val)
				}
			}
		}
	}
	if all.Kind != yaml.SequenceNode {
		c.im.add(Review, c.where, "allOf is not a list; it is ignored")
		return c.fields(n, depth)
	}
	for _, member := range all.Content {
		converted := c.convert(member, depth)
		if converted.Kind != yaml.MappingNode {
			c.im.add(Review, c.where, "an allOf member is not a schema object; it is dropped")
			continue
		}
		merge(converted)
	}
	// Keys beside the allOf refine the merged result.
	merge(c.fields(n, depth))
	if mapGet(out, "type") == nil && mapGet(out, "properties") != nil {
		mapSet(out, "type", str("object"))
	}
	return out
}

// fields copies a schema object key by key, minus everything the adapter
// subset forbids.
func (c *schemaConv) fields(n *yaml.Node, depth int) *yaml.Node {
	out := mapping()
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		switch {
		case key == "$ref" || key == "allOf":
			continue
		case quietlyDropped[key]:
			continue
		case loudlyDropped[key]:
			c.im.add(Review, c.where, "%q is outside the schema subset a tool input may use; it is dropped and the value is less constrained than the document says", key)
			continue
		case key == "type":
			mapSet(out, key, c.typeOf(val))
		case key == "properties":
			props := mapping()
			for j := 0; j+1 < len(val.Content); j += 2 {
				props.Content = append(props.Content, str(val.Content[j].Value), c.convert(val.Content[j+1], depth))
			}
			mapSet(out, key, props)
		case key == "items" || key == "additionalProperties" || key == "contains":
			if val.Kind == yaml.MappingNode {
				mapSet(out, key, c.convert(val, depth))
				continue
			}
			mapSet(out, key, copyNode(val, &c.budget))
		default:
			mapSet(out, key, copyNode(val, &c.budget))
		}
	}
	return out
}

// typeOf narrows OpenAPI 3.1's type lists. ["string","null"] is a string
// as far as a tool argument is concerned.
func (c *schemaConv) typeOf(val *yaml.Node) *yaml.Node {
	if val.Kind != yaml.SequenceNode {
		return copyNode(val, &c.budget)
	}
	for _, t := range val.Content {
		if t.Value != "null" {
			c.im.add(Info, c.where, "type list is narrowed to %q", t.Value)
			return str(t.Value)
		}
	}
	return str("string")
}

// resolve follows a local JSON pointer (#/components/schemas/Pet) into the
// document. Only local pointers reach this function.
func (im *importer) resolve(ref string) (*yaml.Node, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, errors.New("the reference is not local")
	}
	node := im.root
	for _, raw := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		if unescaped, err := url.PathUnescape(token); err == nil {
			token = unescaped
		}
		next := mapGet(node, token)
		if next == nil {
			return nil, fmt.Errorf("no %q in the document", raw)
		}
		node = next
	}
	return node, nil
}

// --- decoding --------------------------------------------------------------

// parseTree reads the document into an ordered node tree. JSON is
// compacted first: yaml.v3 parses JSON, but not the tab characters a
// pretty-printer puts between its tokens.
func parseTree(doc []byte) (*yaml.Node, error) {
	trimmed := bytes.TrimLeft(doc, " \t\r\n")
	if bytes.HasPrefix(trimmed, []byte("{")) {
		var compact bytes.Buffer
		if err := json.Compact(&compact, trimmed); err != nil {
			return nil, fmt.Errorf("parse json: %w", err)
		}
		node, err := adapter.NodeFromJSON(compact.Bytes())
		if err != nil {
			return nil, fmt.Errorf("parse json: %w", err)
		}
		if node == nil {
			return nil, errors.New("document is empty")
		}
		return node.N, nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if err := rejectAliases(&root); err != nil {
		return nil, err
	}
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil, errors.New("document is empty")
		}
		return root.Content[0], nil
	}
	return &root, nil
}

// rejectAliases refuses YAML anchors. An alias expands on every use, so a
// small document can decode into an enormous tree.
func rejectAliases(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return errors.New("yaml anchors and aliases are not accepted in an imported document")
	}
	for _, c := range n.Content {
		if err := rejectAliases(c); err != nil {
			return err
		}
	}
	return nil
}

// --- node helpers ----------------------------------------------------------

func mapping() *yaml.Node  { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }
func sequence() *yaml.Node { return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"} }

func str(s string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	if s == "" || strings.ContainsAny(s, "\n") {
		n.Style = yaml.DoubleQuotedStyle
	}
	return n
}

func strSeq(items []string) *yaml.Node {
	n := sequence()
	for _, s := range items {
		n.Content = append(n.Content, str(s))
	}
	return n
}

func mapGet(n *yaml.Node, key string) *yaml.Node { return adapter.MapGet(n, key) }

func mapSet(n *yaml.Node, key string, val *yaml.Node) {
	if n == nil || val == nil {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = val
			return
		}
	}
	n.Content = append(n.Content, str(key), val)
}

// copyNode deep-copies a node, spending budget so a pathological document
// cannot turn a small schema into a large one.
func copyNode(n *yaml.Node, budget *int) *yaml.Node {
	if n == nil || *budget <= 0 {
		return mapping()
	}
	*budget--
	out := &yaml.Node{Kind: n.Kind, Style: n.Style, Tag: n.Tag, Value: n.Value}
	for _, c := range n.Content {
		out.Content = append(out.Content, copyNode(c, budget))
	}
	return out
}

func containsScalar(seq *yaml.Node, value string) bool {
	for _, c := range seq.Content {
		if c.Value == value {
			return true
		}
	}
	return false
}

func seqStrings(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]string, 0, len(n.Content))
	for _, c := range n.Content {
		out = append(out, c.Value)
	}
	return out
}

func typeOf(schema *yaml.Node) string {
	if t := mapGet(schema, "type"); t != nil {
		return t.Value
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func ptr[T any](v T) *T { return &v }

// SortFindings orders findings by severity then operation, so the most
// important reason an import needs attention is the first one read.
func SortFindings(findings []ImportFinding) {
	rank := map[Level]int{Blocker: 0, Review: 1, Info: 2}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].Level] != rank[findings[j].Level] {
			return rank[findings[i].Level] < rank[findings[j].Level]
		}
		return findings[i].Operation < findings[j].Operation
	})
}
