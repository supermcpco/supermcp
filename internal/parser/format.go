package parser

// Format detection, and the pieces the Postman, cURL and GraphQL
// importers have in common.
//
// FromOpenAPI came first and carries its own state in `importer`. The
// three that followed share `builder` instead, which does the parts every
// import has to get right whatever the input was: the metadata the
// validator insists on, credential declaration, and tool names that are
// unique, prefixed and short enough for an MCP client. openapi.go is left
// as it was.
//
// One rule runs through all of it. A secret that arrives inline — a token
// in a pasted cURL command, a password in a collection variable — is
// never written into the connector. It becomes a declared credential and
// a {{env.NAME}} placeholder, and a finding says so, because someone who
// pastes a working command has just handed over a live key and should be
// told where it went.

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// errNoTools is what every importer returns when the input described no
// request it could turn into a tool. A connector with no tools is not a
// connector, so this is an error and not a finding.
var errNoTools = errors.New("the input describes no request that could become a tool")

// Format names one of the descriptions this package can import.
type Format string

const (
	// FormatUnknown is what Detect reports when the input could be more
	// than one thing, or none of them.
	FormatUnknown Format = ""
	FormatOpenAPI Format = "openapi"
	FormatPostman Format = "postman"
	FormatCurl    Format = "curl"
	FormatGraphQL Format = "graphql"
)

// Formats lists the formats a caller may name, in the order a chooser
// should offer them.
var Formats = []Format{FormatOpenAPI, FormatPostman, FormatCurl, FormatGraphQL}

// ParseFormat reads a format name, reporting whether it is one.
func ParseFormat(s string) (Format, bool) {
	for _, f := range Formats {
		if string(f) == s {
			return f, true
		}
	}
	return FormatUnknown, false
}

// A pasted command often keeps the shell prompt that was in front of it.
var reCurlCommand = regexp.MustCompile(`(?i)\A(?:[$#>]\s+)?curl\b`)

// Detect works out which format a document is written in, returning
// FormatUnknown and a sentence saying why when it cannot tell.
//
// It never guesses. The importers disagree about what a document means —
// the same JSON object is a set of operations to one and a schema to
// another — so a wrong guess produces a connector that looks finished and
// calls the wrong thing. Every rule below keys on something only one
// format has, and a document that answers to none of them is handed back
// for a person to label.
func Detect(doc []byte) (Format, string) {
	trimmed := bytes.TrimSpace(doc)
	if len(trimmed) == 0 {
		return FormatUnknown, "there is nothing to read"
	}
	if reCurlCommand.Match(trimmed) {
		return FormatCurl, ""
	}
	root, err := parseTree(trimmed)
	if err != nil {
		return FormatUnknown, "it is not a curl command, and it does not parse as JSON or YAML: " + err.Error()
	}
	if root.Kind != yaml.MappingNode {
		return FormatUnknown, "it is not a curl command, and what it does parse as is not an object, so it is none of the formats this importer reads; name the format to import it anyway"
	}

	var matched []Format
	if mapGet(root, "openapi") != nil || mapGet(root, "swagger") != nil {
		matched = append(matched, FormatOpenAPI)
	}
	// A collection is an info block and a list of items. info.schema names
	// the collection version when the export carried it; without it, the
	// pair of keys is still unique to Postman among these four.
	if info := mapGet(root, "info"); info != nil && mapGet(root, "item") != nil {
		if mapGet(info, "name") != nil || strings.Contains(scalar(mapGet(info, "schema")), "getpostman.com") {
			matched = append(matched, FormatPostman)
		}
	}
	if graphQLSchemaNode(root) != nil {
		matched = append(matched, FormatGraphQL)
	}

	switch len(matched) {
	case 1:
		return matched[0], ""
	case 0:
		return FormatUnknown, "it has none of the marks of an OpenAPI document, a Postman collection, a curl command or a GraphQL introspection response; name the format to import it anyway"
	default:
		names := make([]string, 0, len(matched))
		for _, f := range matched {
			names = append(names, string(f))
		}
		return FormatUnknown, "it reads as " + strings.Join(names, " and ") + "; name the one you mean"
	}
}

// graphQLSchemaNode finds the __schema object in an introspection
// response, which servers return wrapped in "data" and people paste
// either way round. A bare __schema value is recognised by the two keys
// every introspection carries.
func graphQLSchemaNode(root *yaml.Node) *yaml.Node {
	if s := mapGet(root, "__schema"); s != nil {
		return s
	}
	if data := mapGet(root, "data"); data != nil {
		if s := mapGet(data, "__schema"); s != nil {
			return s
		}
	}
	if mapGet(root, "types") != nil && (mapGet(root, "queryType") != nil || mapGet(root, "mutationType") != nil) {
		return root
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	return n.Value
}

// --- shared importer state -------------------------------------------------

// builder holds one conversion: the adapter being assembled, what the
// importer decided along the way, and the tool names already taken.
type builder struct {
	opts     Options
	out      *adapter.Adapter
	findings []ImportFinding
	names    map[string]bool
	prefix   string // slug-derived tool name prefix
	op       string // what findings are attributed to just now
	max      int
}

func newBuilder(opts Options) *builder {
	b := &builder{
		opts:  opts,
		names: map[string]bool{},
		max:   opts.MaxOperations,
		out: &adapter.Adapter{
			APIVersion:  adapter.APIVersion,
			Kind:        adapter.KindName,
			Credentials: adapter.NewOrderedMap[adapter.Credential](),
		},
	}
	if b.max <= 0 {
		b.max = DefaultMaxOperations
	}
	b.out.Auth.Type = adapter.AuthNone
	return b
}

func (b *builder) add(level Level, path, format string, args ...any) {
	b.findings = append(b.findings, ImportFinding{Operation: b.op, Level: level, Path: path, Message: fmt.Sprintf(format, args...)})
}

// identify settles slug, name and description, and with them the prefix
// every tool name carries. The validator requires all three, and none of
// these formats is obliged to state any of them.
func (b *builder) identify(name, description string) {
	slug := b.opts.Slug
	if slug == "" {
		slug = kebab(name)
	}
	if slug == "" {
		slug = "imported-api"
		b.add(Review, "metadata.slug", "nothing in the input names the API; the connector is slugged %q, which you can change above", slug)
	}
	if b.opts.Name != "" {
		name = b.opts.Name
	}
	if name == "" {
		name = slug
	}
	if strings.TrimSpace(description) == "" {
		description = name
		b.add(Info, "metadata.description", "the input carries no description of the API; its name is used instead")
	}
	b.out.Metadata = adapter.Metadata{
		Slug:        slug,
		Name:        name,
		Description: firstLine(description),
		Region:      or(b.opts.Region, "intl"),
		Category:    or(b.opts.Category, "data"),
	}
	b.prefix = strings.ReplaceAll(slug, "-", "_") + "_"
}

// locate fills the two metadata fields the validator requires and no
// input of these three kinds carries: where the documentation is and what
// icon to show. Both fall back to the upstream host.
func (b *builder) locate(baseURL string) {
	b.out.Metadata.DocsURL = b.opts.DocsURL
	if b.out.Metadata.DocsURL == "" {
		b.out.Metadata.DocsURL = baseURL
	}
	b.out.Metadata.Icon = b.opts.Icon
	if b.out.Metadata.Icon == "" {
		if host := originOf(baseURL); host != "" {
			b.out.Metadata.Icon = host + "/favicon.ico"
		}
	}
	if b.out.Metadata.Icon == "" {
		b.out.Metadata.Icon = b.out.Metadata.DocsURL
	}
}

// credential declares one credential and returns the placeholder that
// reads it. Declaring the same name twice keeps the first description,
// so a credential named once per request does not accumulate copies.
func (b *builder) credential(name, description string, secret bool) string {
	key := envName(name)
	if _, ok := b.out.Credentials.Get(key); !ok {
		b.out.Credentials.Set(key, adapter.Credential{Required: true, Secret: secret, Description: description})
	}
	return "{{env." + key + "}}"
}

// hasCredential reports whether a credential of this name is declared.
func (b *builder) hasCredential(name string) bool {
	_, ok := b.out.Credentials.Get(envName(name))
	return ok
}

// toolName settles on a unique, prefixed, short-enough tool name.
func (b *builder) toolName(desired, loc string) string {
	name := snake(desired)
	if name == "" {
		name = "call"
		b.add(Review, loc, "nothing in the request names it; the tool is named %q", b.prefix+name)
	}
	if !strings.HasPrefix(name, b.prefix) {
		name = b.prefix + name
	}
	if len(name) > maxToolName {
		name = strings.Trim(name[:maxToolName], "_")
		b.add(Info, loc, "the tool name is longer than the %d characters an MCP client will take; it is shortened to %q", maxToolName, name)
	}
	if !reToolName.MatchString(name) {
		name = "tool_" + name
	}
	if b.names[name] {
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s_%d", name, n)
			if !b.names[candidate] {
				b.add(Review, loc, "the tool name %q is already taken; this one is %q, which you may want to rename to something a model can tell apart", name, candidate)
				name = candidate
				break
			}
		}
	}
	b.names[name] = true
	return name
}

// finish does the last checks every importer wants and returns what the
// caller hands back.
func (b *builder) finish() (*adapter.Adapter, []ImportFinding, error) {
	if len(b.out.Tools) == 0 {
		return nil, b.findings, errNoTools
	}
	return b.out, b.findings, nil
}

// --- tool inputs -----------------------------------------------------------

// params accumulates one tool's input schema while the request that reads
// it is built, so the property a model fills in and the placeholder that
// consumes it are always created together and cannot drift apart.
//
// It is the same idea as openapi.go's inputBuilder, kept separate because
// these formats name their parameters after the wire and that one names
// them after an OpenAPI parameter object.
type params struct {
	b        *builder
	loc      string
	props    *yaml.Node
	required []string
	taken    map[string]string // property name -> what claimed it
}

func newParams(b *builder, loc string) *params {
	return &params{b: b, loc: loc, props: mapping(), taken: map[string]string{}}
}

// declare adds one property and returns the placeholder that reads it. A
// nil schema means an unconstrained string.
func (p *params) declare(name, origin, description string, schema *yaml.Node, required bool) string {
	key := propName(name)
	if prev, dup := p.taken[key]; dup {
		if prev == origin+" "+name {
			// The same thing named twice (a variable used in two places)
			// is one parameter, not two.
			if required {
				p.require(key)
			}
			return "{{params." + key + "}}"
		}
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s_%d", key, n)
			if _, again := p.taken[candidate]; !again {
				p.b.add(Review, p.loc, "the %s %q collides with the %s; it is taken as %q", origin, name, prev, candidate)
				key = candidate
				break
			}
		}
	} else if key != name {
		p.b.add(Info, p.loc, "the %s %q is taken as %q, because a tool parameter name may hold only letters, digits and underscores", origin, name, key)
	}
	p.taken[key] = origin + " " + name
	if schema == nil {
		schema = mapping()
		mapSet(schema, "type", str("string"))
	}
	if description != "" && mapGet(schema, "description") == nil {
		mapSet(schema, "description", str(description))
	}
	mapSet(p.props, key, schema)
	if required {
		p.require(key)
	}
	return "{{params." + key + "}}"
}

func (p *params) require(key string) {
	for _, r := range p.required {
		if r == key {
			return
		}
	}
	p.required = append(p.required, key)
}

// schema builds the finished input. properties is always present, empty
// or not, because the adapter schema requires it.
func (p *params) schema() *adapter.Node {
	in := mapping()
	mapSet(in, "type", str("object"))
	mapSet(in, "properties", p.props)
	if len(p.required) > 0 {
		mapSet(in, "required", strSeq(p.required))
	}
	return &adapter.Node{N: in}
}

// --- naming ----------------------------------------------------------------

var reNotCredChar = regexp.MustCompile(`[^A-Z0-9]+`)

// envName turns anything into the UPPER_SNAKE_CASE the validator demands
// of a credential name.
func envName(s string) string {
	out := reNotCredChar.ReplaceAllString(strings.ToUpper(snake(s)), "_")
	out = strings.Trim(out, "_")
	if out == "" {
		return "CREDENTIAL"
	}
	if unicode.IsDigit(rune(out[0])) {
		out = "C_" + out
	}
	return out
}

// Words that name a secret. They are matched against the name with
// separators removed, so X-Api-Key, api_key and apiKey all hit "apikey".
// "auth" on its own is left out on purpose: it is in "author".
var secretWords = []string{
	"secret", "password", "passwd", "pwd", "token", "apikey", "authorization",
	"bearer", "credential", "privatekey", "accesskey", "signature", "sessionid",
	"clientsecret", "passphrase",
}

// looksSecretName reports whether a name is one a person would not want
// stored in plain text.
func looksSecretName(s string) bool {
	k := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == ' ' || r == '.' {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
	for _, w := range secretWords {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

// Prefixes that identify a live credential on sight. Each is a vendor's
// published key format, so a value carrying one is a real key and not an
// identifier that happens to be long.
var secretValuePrefixes = []string{
	"sk-", "sk_live_", "sk_test_", "rk_live_", "pk_live_", "ghp_", "gho_", "ghu_", "ghs_",
	"github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xapp-", "AIza", "AKIA", "ASIA",
	"ya29.", "shpat_", "shpss_", "npm_", "dop_v1_", "SG.", "key-", "eyJ",
}

var reOpaqueToken = regexp.MustCompile(`\A[A-Za-z0-9_\-.+/=]{32,}\z`)

// looksSecretValue reports whether a literal value is a credential. It is
// deliberately conservative about length alone: a 40-character opaque
// string is only called a secret when it mixes letters and digits, which
// a slug or a path never does.
func looksSecretValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, p := range secretValuePrefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	if !reOpaqueToken.MatchString(v) {
		return false
	}
	var letters, digits bool
	for _, r := range v {
		switch {
		case unicode.IsLetter(r):
			letters = true
		case unicode.IsDigit(r):
			digits = true
		}
	}
	return letters && digits
}

// originOf returns scheme://host for a URL, or "" if there is none.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

var reScheme = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

// splitRequestURL separates a request URL into the origin a connector
// would call, the path one tool would request and the query string
// written into the URL itself.
//
// It is forgiving about the scheme because people write URLs without one
// and mean https, and forgiving about a URL with no host at all because a
// Postman collection often has none — the base URL then has to come from
// somewhere else, and the caller reports that.
func splitRequestURL(raw string) (origin, path, query string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", ""
	}
	if !reScheme.MatchString(raw) && !strings.HasPrefix(raw, "/") && strings.Contains(firstSegment(raw), ".") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		path, query, _ = strings.Cut(raw, "?")
		return "", ensureLeadingSlash(path), query
	}
	// EscapedPath re-escapes the braces that documentation writes a
	// fill-in-the-blank segment with, and {owner} is the point of the
	// example. Everything else keeps whatever escaping it arrived with.
	path = braceUnescaper.Replace(u.EscapedPath())
	return u.Scheme + "://" + u.Host, ensureLeadingSlash(path), u.RawQuery
}

var braceUnescaper = strings.NewReplacer("%7B", "{", "%7b", "{", "%7D", "}", "%7d", "}")

func firstSegment(s string) string {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		return s[:i]
	}
	return s
}

func ensureLeadingSlash(p string) string {
	switch {
	case p == "":
		return ""
	case strings.HasPrefix(p, "/"):
		return p
	default:
		return "/" + p
	}
}

// hostName turns an upstream host into something worth calling a
// connector: api.stripe.com becomes stripe, shop.example.co.uk becomes
// example. It is only ever a default, and every importer lets the caller
// override it.
func hostName(host string) string {
	host = strings.ToLower(host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	labels := strings.Split(host, ".")
	// Drop the service label people put in front of an API host, and the
	// public suffix behind it, keeping whatever names the organisation.
	for len(labels) > 1 {
		switch labels[0] {
		case "www", "api", "api2", "app", "rest", "graph", "graphql", "sandbox", "staging", "dev", "test":
			labels = labels[1:]
			continue
		}
		break
	}
	switch len(labels) {
	case 0:
		return ""
	case 1:
		return labels[0]
	}
	// example.co.uk and example.com both name "example".
	if len(labels) >= 3 && len(labels[len(labels)-2]) <= 3 {
		return labels[len(labels)-3]
	}
	return labels[len(labels)-2]
}

// --- example-derived schemas -----------------------------------------------

// maxInferDepth bounds how far an inferred schema follows a nested
// example. A deep example describes itself; a model filling in a tool
// does not need six levels of it.
const maxInferDepth = 4

// inferSchema derives a JSON Schema from one example value. Postman
// collections carry saved request bodies and saved responses, and the
// shape of a real example says more about a field than "string" does.
func inferSchema(n *yaml.Node, depth int) *yaml.Node {
	out := mapping()
	if n == nil || depth > maxInferDepth {
		mapSet(out, "type", str("object"))
		return out
	}
	switch n.Kind {
	case yaml.MappingNode:
		mapSet(out, "type", str("object"))
		props := mapping()
		for i := 0; i+1 < len(n.Content); i += 2 {
			mapSet(props, n.Content[i].Value, inferSchema(n.Content[i+1], depth+1))
		}
		mapSet(out, "properties", props)
	case yaml.SequenceNode:
		mapSet(out, "type", str("array"))
		if len(n.Content) > 0 {
			mapSet(out, "items", inferSchema(n.Content[0], depth+1))
		}
	default:
		mapSet(out, "type", str(scalarType(n)))
	}
	return out
}

// scalarType names the JSON type of a scalar node. A JSON document that
// came through NodeFromJSON keeps its tags, so a number stays a number.
func scalarType(n *yaml.Node) string {
	switch n.Tag {
	case "!!int":
		return "integer"
	case "!!float":
		return "number"
	case "!!bool":
		return "boolean"
	case "!!null":
		return "string"
	default:
		return "string"
	}
}

// typedScalar renders a literal as the YAML scalar it is, so an example
// value used as a schema default keeps its type.
func typedScalar(n *yaml.Node) *yaml.Node {
	if n == nil || n.Kind != yaml.ScalarNode {
		return nil
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: n.Tag, Value: n.Value, Style: n.Style}
}
