package parser

// FromGraphQL turns a GraphQL introspection response into an adapter:
// one tool per field of the query and mutation roots.
//
// The hard part is the document, and it is where the system this replaces
// went wrong. It emitted `query name($id: ID!) { user(id: $id) }`, which
// no server will accept: a field returning an object type must have a
// selection set. So the selection set is generated here, from the return
// type, leaf fields first and nested objects to a bounded depth, skipping
// anything that would itself need arguments. A field whose type offers
// nothing selectable falls back to __typename, which is always legal.
//
// The rest follows from the same idea — say what the schema says, and say
// so when it cannot be said:
//
//   - An input object argument becomes an object schema built from its
//     input fields, not a string, so a model knows what to put in it.
//   - An enum argument carries its values.
//   - Variable declarations are written from the introspected type,
//     brackets and exclamation marks included, so the document and the
//     variables agree.
//
// This function never dials anything. A live endpoint is introspected by
// the caller, through the guarded HTTP client, and the response handed in
// here; IntrospectionQuery is the query to send.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// IntrospectionQuery is what a caller posts to a live endpoint to get the
// response this importer reads. It asks for exactly what the importer
// uses — no more, because a server that limits introspection is more
// likely to answer a modest query, and no less, because a missing
// enumValues or inputFields turns a precise schema into a string.
const IntrospectionQuery = `query SupermcpIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: false) {
        name
        description
        isDeprecated
        args { name description defaultValue type { ...TypeRef } }
        type { ...TypeRef }
      }
      inputFields { name description defaultValue type { ...TypeRef } }
      enumValues(includeDeprecated: false) { name description }
    }
  }
}

fragment TypeRef on __Type {
  kind name
  ofType { kind name
    ofType { kind name
      ofType { kind name
        ofType { kind name
          ofType { kind name
            ofType { kind name } } } } } }
}`

const (
	// maxSelectionDepth bounds how far a generated selection set descends
	// into the object types a field returns. Three levels is enough to be
	// useful and shallow enough that the response stays readable.
	maxSelectionDepth = 3

	// maxSelectionFields bounds one selection set, so a type with two
	// hundred fields does not become a document no one can read and a
	// response no model can hold.
	maxSelectionFields = 40

	// maxInputDepth bounds how far an input object argument is expanded
	// into a schema.
	maxInputDepth = 4
)

// GraphQLOptions are the choices an introspection response cannot make
// for itself. It embeds Options so the shared fields mean what they mean
// everywhere else.
type GraphQLOptions struct {
	Options

	// Headers are the headers the introspection request carried. An
	// introspection response says nothing about authentication, so the
	// headers that got one are the only evidence of how the endpoint is
	// reached, and an Authorization or API key header among them becomes
	// the connector's auth.
	Headers map[string]string
}

// FromGraphQL converts an introspection response into an adapter. The
// endpoint is not in the response, so it comes from Options.ServerURL;
// without it the adapter is returned with a blocker, so a caller can
// still see the tools an import would create.
func FromGraphQL(doc []byte, opts GraphQLOptions) (*adapter.Adapter, []ImportFinding, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if len(doc) > maxBytes {
		return nil, nil, fmt.Errorf("introspection response is %d bytes, over the %d byte limit", len(doc), maxBytes)
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
	if errs := mapGet(root, "errors"); errs != nil && errs.Kind == yaml.SequenceNode && len(errs.Content) > 0 {
		return nil, nil, fmt.Errorf("the endpoint refused to be introspected: %s", gqlErrorText(errs))
	}
	schemaNode := graphQLSchemaNode(root)
	if schemaNode == nil {
		return nil, nil, errors.New("this is not a GraphQL introspection response: it has no __schema")
	}
	var schema gqlSchema
	if err := schemaNode.Decode(&schema); err != nil {
		return nil, nil, fmt.Errorf("the introspection response does not decode: %w", err)
	}

	g := &gqlImporter{builder: newBuilder(opts.Options), types: map[string]*gqlType{}}
	for i := range schema.Types {
		t := &schema.Types[i]
		if t.Name != "" {
			g.types[t.Name] = t
		}
	}

	endpoint := strings.TrimSpace(opts.ServerURL)
	name, description := "graphql", "A GraphQL API."
	if endpoint == "" {
		g.add(Blocker, "transport.baseUrl", "an introspection response does not say where it came from; supply the endpoint URL with the import")
	} else if err := checkAbsolute(endpoint); err != nil {
		g.add(Blocker, "transport.baseUrl", "the endpoint URL is unusable: %v", err)
		endpoint = ""
	} else if u, err := url.Parse(endpoint); err == nil {
		name = hostName(u.Host)
		description = "The GraphQL API at " + u.Host + "."
	}
	g.identify(name, description)
	if opts.Name == "" && endpoint != "" {
		if u, err := url.Parse(endpoint); err == nil {
			g.out.Metadata.Name = u.Host
		}
	}
	g.out.Transport.Type = adapter.TransportGraphQL
	g.out.Transport.BaseURL = endpoint
	g.locate(endpoint)
	g.auth(opts.Headers)

	if schema.SubscriptionType != nil && schema.SubscriptionType.Name != "" {
		g.add(Info, "subscriptions", "the schema has subscriptions; a tool call is one request and one answer, so the %s fields are left out", schema.SubscriptionType.Name)
	}
	g.roots(&schema)
	return g.finish()
}

// gqlImporter carries the state of one introspection conversion.
type gqlImporter struct {
	*builder
	types map[string]*gqlType
}

// --- introspection model ---------------------------------------------------

type gqlSchema struct {
	QueryType        *gqlTypeName `yaml:"queryType"`
	MutationType     *gqlTypeName `yaml:"mutationType"`
	SubscriptionType *gqlTypeName `yaml:"subscriptionType"`
	Types            []gqlType    `yaml:"types"`
}

type gqlTypeName struct {
	Name string `yaml:"name"`
}

type gqlType struct {
	Kind        string     `yaml:"kind"`
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Fields      []gqlField `yaml:"fields"`
	InputFields []gqlInput `yaml:"inputFields"`
	EnumValues  []gqlEnum  `yaml:"enumValues"`
}

type gqlField struct {
	Name         string     `yaml:"name"`
	Description  string     `yaml:"description"`
	IsDeprecated bool       `yaml:"isDeprecated"`
	Args         []gqlInput `yaml:"args"`
	Type         gqlTypeRef `yaml:"type"`
}

type gqlInput struct {
	Name         string     `yaml:"name"`
	Description  string     `yaml:"description"`
	DefaultValue *string    `yaml:"defaultValue"`
	Type         gqlTypeRef `yaml:"type"`
}

type gqlEnum struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type gqlTypeRef struct {
	Kind   string      `yaml:"kind"`
	Name   string      `yaml:"name"`
	OfType *gqlTypeRef `yaml:"ofType"`
}

// --- auth ------------------------------------------------------------------

// auth reads the headers the introspection was made with. They are the
// only place an introspection response carries any evidence of how the
// endpoint is reached.
func (g *gqlImporter) auth(headers map[string]string) {
	for name, value := range headers {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		lower := strings.ToLower(name)
		switch {
		case lower == "authorization":
			scheme, _, found := strings.Cut(value, " ")
			if !found {
				scheme = "Bearer"
			}
			auth := adapter.Auth{Type: adapter.AuthBearer, Token: g.credential(credToken, "Sent in the Authorization header", true)}
			if !strings.EqualFold(scheme, "Bearer") {
				auth.Prefix = scheme
			}
			g.out.Auth = auth
			g.add(Review, "auth", "the endpoint was introspected with an Authorization header; the connector sends %s from the credential %s, whose value is not taken from the header", or(scheme, "Bearer"), credToken)
			return
		case looksSecretName(name):
			g.out.Auth = adapter.Auth{Type: adapter.AuthAPIKey, In: "header", Name: name, Value: g.credential(envName(name), "Sent as the "+name+" header", true)}
			g.add(Review, "auth", "the endpoint was introspected with a %s header; the connector sends it from the credential %s, whose value is not taken from the header", name, envName(name))
			return
		}
	}
	if len(headers) > 0 {
		for name, value := range headers {
			if strings.TrimSpace(value) != "" {
				g.out.Transport.Headers.Set(name, value)
			}
		}
	}
	if g.out.Auth.Type == adapter.AuthNone {
		g.add(Info, "auth", "an introspection response says nothing about how the endpoint is authenticated; the connector is created unauthenticated, so set its auth if the API needs one")
	}
}

// --- tools -----------------------------------------------------------------

func (g *gqlImporter) roots(schema *gqlSchema) {
	roots := []struct {
		kind string
		name string
	}{
		{"query", rootName(schema.QueryType, "Query")},
		{"mutation", rootName(schema.MutationType, "")},
	}
	for _, r := range roots {
		if r.name == "" {
			continue
		}
		root, ok := g.types[r.name]
		if !ok {
			g.add(Review, r.kind, "the schema names %q as its %s root but does not describe it; those fields are left out", r.name, r.kind)
			continue
		}
		for i := range root.Fields {
			field := &root.Fields[i]
			if strings.HasPrefix(field.Name, "__") {
				continue
			}
			if len(g.out.Tools) >= g.max {
				g.op = ""
				g.add(Blocker, r.kind, "the schema has more than %d root fields; the import stops there, so narrow the schema or raise the limit", g.max)
				return
			}
			if t, ok := g.tool(field, r.kind); ok {
				g.out.Tools = append(g.out.Tools, t)
			}
		}
	}
}

func rootName(t *gqlTypeName, fallback string) string {
	if t != nil && t.Name != "" {
		return t.Name
	}
	return fallback
}

func (g *gqlImporter) tool(field *gqlField, kind string) (adapter.Tool, bool) {
	g.op = kind + " " + field.Name
	loc := kind + "." + field.Name

	// A query and a mutation may share a name; when they do, the kind is
	// what tells the two tools apart, which reads better than a number.
	name := field.Name
	if g.names[g.prefix+snake(name)] {
		name = kind + "_" + field.Name
	}
	t := adapter.Tool{Name: g.toolName(name, loc)}
	if field.IsDeprecated {
		g.add(Info, loc, "the schema marks this field deprecated; it is imported anyway, so disable the tool if you do not want it offered")
	}
	if kind == "query" {
		t.Annotations = &adapter.Annotations{ReadOnlyHint: ptr(true)}
	}

	in := newParams(g.builder, loc)
	variables := mapping()
	declarations := make([]string, 0, len(field.Args))
	arguments := make([]string, 0, len(field.Args))
	for i := range field.Args {
		arg := &field.Args[i]
		if arg.Name == "" {
			continue
		}
		schema := g.argSchema(&arg.Type, 0, nil, loc)
		if arg.Description != "" {
			mapSet(schema, "description", str(firstLine(arg.Description)))
		}
		if def := gqlDefault(arg.DefaultValue, &arg.Type); def != nil {
			mapSet(schema, "default", def)
		}
		// An argument with a default is not one a caller has to supply,
		// whatever its nullability says.
		required := arg.Type.Kind == "NON_NULL" && arg.DefaultValue == nil
		placeholder := in.declare(arg.Name, "argument", "", schema, required)
		mapSet(variables, arg.Name, str(placeholder))
		declarations = append(declarations, "$"+arg.Name+": "+gqlTypeString(&arg.Type))
		arguments = append(arguments, arg.Name+": $"+arg.Name)
	}

	selection := g.selection(&field.Type, 0, map[string]bool{}, loc)
	t.Operation.Kind = kind
	t.Operation.Document = gqlDocument(kind, field.Name, declarations, arguments, selection)
	if len(variables.Content) > 0 {
		t.Operation.Variables = &adapter.Node{N: variables}
	}
	t.Input = in.schema()
	t.Description = g.description(field, kind)
	return t, true
}

// description writes what a model reads before choosing the tool. The
// schema's own description comes first; what the field returns is added
// because it is the fact a model most often needs and the one a GraphQL
// description most often leaves out.
func (g *gqlImporter) description(field *gqlField, kind string) string {
	var parts []string
	if d := strings.TrimSpace(field.Description); d != "" {
		parts = append(parts, ensureStop(d))
	}
	returns := gqlTypeString(&field.Type)
	parts = append(parts, fmt.Sprintf("The GraphQL %s %s, which returns %s.", kind, field.Name, returns))
	if len(field.Args) > 0 {
		names := make([]string, 0, len(field.Args))
		for _, a := range field.Args {
			names = append(names, a.Name)
		}
		parts = append(parts, "It takes "+strings.Join(names, ", ")+".")
	}
	return strings.Join(parts, " ")
}

func ensureStop(s string) string {
	s = firstParagraph(s)
	if s == "" {
		return ""
	}
	switch s[len(s)-1] {
	case '.', '!', '?', ':':
		return s
	default:
		return s + "."
	}
}

func firstParagraph(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n\n"); i >= 0 {
		s = s[:i]
	}
	return strings.Join(strings.Fields(s), " ")
}

// gqlDocument assembles the operation. The field name is the operation
// name, which is what shows in a server's logs and traces.
func gqlDocument(kind, field string, declarations, arguments []string, selection string) string {
	var sb strings.Builder
	sb.WriteString(kind + " " + field)
	if len(declarations) > 0 {
		sb.WriteString("(" + strings.Join(declarations, ", ") + ")")
	}
	sb.WriteString(" {\n  " + field)
	if len(arguments) > 0 {
		sb.WriteString("(" + strings.Join(arguments, ", ") + ")")
	}
	if selection != "" {
		sb.WriteString(" " + selection)
	}
	sb.WriteString("\n}")
	return sb.String()
}

// --- selection sets --------------------------------------------------------

// selection builds the selection set for what a field returns, or "" when
// the type is a leaf and must not have one.
//
// This is where the format this replaces was wrong: it emitted no
// selection set at all, so every field returning an object produced a
// document the server rejected.
func (g *gqlImporter) selection(ref *gqlTypeRef, depth int, seen map[string]bool, loc string) string {
	named := gqlNamedType(ref)
	if named == nil || named.Name == "" {
		return ""
	}
	t, ok := g.types[named.Name]
	if !ok {
		return ""
	}
	switch t.Kind {
	case "SCALAR", "ENUM":
		return ""
	case "UNION":
		// Selecting a union's members needs an inline fragment per member
		// and a judgement about which are worth having. __typename is
		// always legal and says which member came back.
		g.add(Review, loc, "the field returns the union %s; the document selects only __typename, so add the inline fragments you want by hand", t.Name)
		return "{ __typename }"
	case "OBJECT", "INTERFACE":
	default:
		return ""
	}
	if seen[t.Name] || depth >= maxSelectionDepth {
		return "{ __typename }"
	}
	seen[t.Name] = true
	defer delete(seen, t.Name)

	indent := strings.Repeat("  ", depth+2)
	var lines []string
	truncated := false
	for i := range t.Fields {
		f := &t.Fields[i]
		if strings.HasPrefix(f.Name, "__") || f.IsDeprecated {
			continue
		}
		if gqlHasRequiredArgs(f) {
			// A field needing arguments needs a caller to choose them, and
			// nothing here can.
			continue
		}
		if len(lines) >= maxSelectionFields {
			truncated = true
			break
		}
		sub := g.selection(&f.Type, depth+1, seen, loc)
		if sub == "" {
			lines = append(lines, indent+f.Name)
			continue
		}
		if depth+1 >= maxSelectionDepth {
			// One more level would be cut off anyway; leaving the field out
			// keeps the document smaller than selecting __typename for it.
			continue
		}
		lines = append(lines, indent+f.Name+" "+sub)
	}
	if truncated {
		g.add(Info, loc, "the type %s has more than %d fields worth selecting; the document takes the first %d, so widen it by hand if you need the rest", t.Name, maxSelectionFields, maxSelectionFields)
	}
	if len(lines) == 0 {
		g.add(Review, loc, "nothing in %s can be selected without arguments; the document asks only for __typename, so refine it by hand", t.Name)
		return "{ __typename }"
	}
	closing := strings.Repeat("  ", depth+1)
	return "{\n" + strings.Join(lines, "\n") + "\n" + closing + "}"
}

func gqlHasRequiredArgs(f *gqlField) bool {
	for i := range f.Args {
		if f.Args[i].Type.Kind == "NON_NULL" && f.Args[i].DefaultValue == nil {
			return true
		}
	}
	return false
}

// --- argument schemas ------------------------------------------------------

// argSchema turns an argument's GraphQL type into the JSON Schema subset a
// tool input may use. An input object becomes an object with its fields,
// which is the difference between a model that can fill the argument in
// and one that guesses at a string.
func (g *gqlImporter) argSchema(ref *gqlTypeRef, depth int, seen map[string]bool, loc string) *yaml.Node {
	if seen == nil {
		seen = map[string]bool{}
	}
	out := mapping()
	if ref == nil {
		mapSet(out, "type", str("string"))
		return out
	}
	switch ref.Kind {
	case "NON_NULL":
		return g.argSchema(ref.OfType, depth, seen, loc)
	case "LIST":
		mapSet(out, "type", str("array"))
		mapSet(out, "items", g.argSchema(ref.OfType, depth, seen, loc))
		return out
	}
	t, ok := g.types[ref.Name]
	if !ok {
		mapSet(out, "type", str(gqlScalarType(ref.Name)))
		return out
	}
	switch t.Kind {
	case "ENUM":
		mapSet(out, "type", str("string"))
		values := make([]string, 0, len(t.EnumValues))
		for _, v := range t.EnumValues {
			values = append(values, v.Name)
		}
		if len(values) > 0 {
			mapSet(out, "enum", strSeq(values))
		}
	case "INPUT_OBJECT":
		mapSet(out, "type", str("object"))
		if seen[t.Name] || depth >= maxInputDepth {
			// A recursive input (a filter that nests itself) is legal;
			// stopping keeps the schema finite and the rest of it useful.
			g.add(Info, loc, "the input type %s nests itself; the schema stops there and the value is unconstrained below that point", t.Name)
			return out
		}
		seen[t.Name] = true
		defer delete(seen, t.Name)
		props := mapping()
		var required []string
		for i := range t.InputFields {
			f := &t.InputFields[i]
			field := g.argSchema(&f.Type, depth+1, seen, loc)
			if f.Description != "" {
				mapSet(field, "description", str(firstLine(f.Description)))
			}
			if def := gqlDefault(f.DefaultValue, &f.Type); def != nil {
				mapSet(field, "default", def)
			}
			mapSet(props, f.Name, field)
			if f.Type.Kind == "NON_NULL" && f.DefaultValue == nil {
				required = append(required, f.Name)
			}
		}
		mapSet(out, "properties", props)
		if len(required) > 0 {
			mapSet(out, "required", strSeq(required))
		}
		if t.Description != "" {
			mapSet(out, "description", str(firstLine(t.Description)))
		}
	default:
		mapSet(out, "type", str(gqlScalarType(t.Name)))
		if t.Kind == "SCALAR" && gqlScalarType(t.Name) == "string" && !gqlBuiltinScalar(t.Name) {
			mapSet(out, "description", str("A "+t.Name+" value, sent as a string"))
		}
	}
	return out
}

func gqlBuiltinScalar(name string) bool {
	switch name {
	case "Int", "Float", "String", "Boolean", "ID":
		return true
	}
	return false
}

// gqlScalarType maps a GraphQL scalar onto a JSON type. A custom scalar
// is a string: the schema says nothing else about it.
func gqlScalarType(name string) string {
	switch name {
	case "Int":
		return "integer"
	case "Float":
		return "number"
	case "Boolean":
		return "boolean"
	default:
		return "string"
	}
}

// gqlTypeString renders a type reference the way SDL writes it, which is
// what a variable declaration needs.
func gqlTypeString(ref *gqlTypeRef) string {
	if ref == nil {
		return "String"
	}
	switch ref.Kind {
	case "NON_NULL":
		return gqlTypeString(ref.OfType) + "!"
	case "LIST":
		return "[" + gqlTypeString(ref.OfType) + "]"
	default:
		if ref.Name == "" {
			return "String"
		}
		return ref.Name
	}
}

// gqlNamedType unwraps the list and non-null shells around a type.
func gqlNamedType(ref *gqlTypeRef) *gqlTypeRef {
	for ref != nil && ref.OfType != nil && (ref.Kind == "NON_NULL" || ref.Kind == "LIST") {
		ref = ref.OfType
	}
	return ref
}

// gqlDefault reads an argument's default, which introspection returns as
// the GraphQL literal it was written as. Only the literals that map onto
// a JSON Schema default are taken; a list or an object default is left
// out rather than half-translated.
func gqlDefault(literal *string, ref *gqlTypeRef) *yaml.Node {
	if literal == nil {
		return nil
	}
	v := strings.TrimSpace(*literal)
	switch {
	case v == "" || v == "null":
		return nil
	case strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") && len(v) >= 2:
		return str(strings.Trim(v, "\""))
	case v == "true" || v == "false":
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: v}
	case strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{"):
		return nil
	}
	named := gqlNamedType(ref)
	if named != nil && (named.Name == "Int" || named.Name == "Float") {
		tag := "!!int"
		if strings.ContainsAny(v, ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: v}
	}
	// An enum value is a bare name, which is a string as far as the tool
	// input is concerned.
	return str(v)
}

// gqlErrorText renders the errors a server returned instead of a schema.
func gqlErrorText(errs *yaml.Node) string {
	var messages []string
	for _, e := range errs.Content {
		if m := scalar(mapGet(e, "message")); m != "" {
			messages = append(messages, m)
		}
	}
	if len(messages) == 0 {
		return "it gave no reason"
	}
	return strings.Join(messages, "; ")
}
