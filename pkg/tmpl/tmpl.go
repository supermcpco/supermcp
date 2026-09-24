// Package tmpl resolves {{namespace.path | filter}} placeholders in adapter
// and tool definitions. It is the only place placeholder syntax is
// interpreted; engines, the validator and the CLI all use it.
//
// Namespaces:
//
//	params.x     tool call arguments (typed)
//	env.X        connector credentials / environment
//	caller.f     identity of the MCP caller (email, sub, org, server, authMethod)
//	auth.k       values produced by the upstream auth flow (token, username, ...)
//	req.f        request facts for signing (method, url, path, body, timestamp)
//
// A string that is exactly one placeholder yields the referenced value with
// its type preserved (a number stays a number, an object stays an object)
// and reports "unset" when the value is missing so the caller can drop the
// key. Any other string is interpolated: every placeholder must resolve or
// the string is unset (mapping context) or an error (strict context).
package tmpl

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Vars are the values placeholders resolve against. Nil maps are fine.
type Vars struct {
	Params map[string]any
	Env    map[string]string
	Caller map[string]string
	Auth   map[string]string
	Req    map[string]string
}

// Mode selects how a string with placeholders is rendered.
type Mode int

const (
	// Value: a whole-string placeholder is typed; an interpolated string with
	// a missing reference is reported unset (the caller drops the key).
	Value Mode = iota
	// Path: values are URL path-escaped per segment unless |raw; a missing
	// reference is an error.
	Path
	// Strict: no escaping; a missing reference is an error. For SQL text,
	// GraphQL documents, headers that must be complete, signing strings.
	Strict
)

// ErrUnset is returned when a Strict/Path render references an unset value.
var ErrUnset = errors.New("unset placeholder")

// Ref is one parsed placeholder.
type Ref struct {
	NS      string   // params | env | caller | auth | req
	Path    []string // dotted path
	Filters []Filter
	raw     string
}

// Filter is a pipe stage.
type Filter struct {
	Name string
	Arg  string
}

func (r Ref) String() string { return r.raw }

// Refs returns every placeholder in s, in order. Malformed placeholders are
// returned as an error.
func Refs(s string) ([]Ref, error) {
	var refs []Ref
	for i := 0; i < len(s); {
		start := strings.Index(s[i:], "{{")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(s[start:], "}}")
		if end < 0 {
			return nil, fmt.Errorf("unterminated placeholder at %d in %q", start, truncate(s))
		}
		end += start
		ref, err := parseRef(s[start : end+2])
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
		i = end + 2
	}
	return refs, nil
}

func parseRef(raw string) (Ref, error) {
	body := strings.TrimSpace(raw[2 : len(raw)-2])
	// Literal escape: {{ "{{" }} renders as "{{".
	if strings.HasPrefix(body, `"`) && strings.HasSuffix(body, `"`) {
		return Ref{NS: "literal", Path: []string{body[1 : len(body)-1]}, raw: raw}, nil
	}
	parts := strings.Split(body, "|")
	head := strings.TrimSpace(parts[0])
	ns, path, ok := strings.Cut(head, ".")
	if !ok || ns == "" || path == "" {
		return Ref{}, fmt.Errorf("placeholder %q must be <namespace>.<path>", raw)
	}
	switch ns {
	case "params", "env", "caller", "auth", "req":
	default:
		return Ref{}, fmt.Errorf("placeholder %q: unknown namespace %q", raw, ns)
	}
	ref := Ref{NS: ns, Path: strings.Split(path, "."), raw: raw}
	for _, f := range parts[1:] {
		f = strings.TrimSpace(f)
		name, arg, _ := strings.Cut(f, ":")
		switch name {
		case "raw", "json", "urlencode", "base64", "upper", "lower":
			if arg != "" {
				return Ref{}, fmt.Errorf("placeholder %q: filter %s takes no argument", raw, name)
			}
		case "default", "join":
		default:
			return Ref{}, fmt.Errorf("placeholder %q: unknown filter %q", raw, name)
		}
		ref.Filters = append(ref.Filters, Filter{Name: name, Arg: arg})
	}
	return ref, nil
}

// lookup resolves a ref to a value. ok=false means unset.
func (v Vars) lookup(r Ref) (val any, ok bool) {
	switch r.NS {
	case "literal":
		return r.Path[0], true
	case "params":
		return walk(v.Params, r.Path)
	case "env":
		return strMap(v.Env, r.Path)
	case "caller":
		return strMap(v.Caller, r.Path)
	case "auth":
		return strMap(v.Auth, r.Path)
	case "req":
		return strMap(v.Req, r.Path)
	}
	return nil, false
}

func strMap(m map[string]string, path []string) (any, bool) {
	if len(path) != 1 || m == nil {
		return nil, false
	}
	s, ok := m[path[0]]
	if !ok {
		return nil, false
	}
	return s, true
}

func walk(m map[string]any, path []string) (any, bool) {
	if m == nil {
		return nil, false
	}
	var cur any = m
	for _, p := range path {
		switch c := cur.(type) {
		case map[string]any:
			next, ok := c[p]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	if cur == nil {
		return nil, false
	}
	return cur, true
}

// applyFilters runs the pipe on a resolved value. raw reports whether |raw
// was present (disables path escaping).
func applyFilters(val any, ok bool, filters []Filter) (out any, present bool, raw bool, err error) {
	for _, f := range filters {
		switch f.Name {
		case "default":
			if !ok {
				var d any
				if err := json.Unmarshal([]byte(f.Arg), &d); err != nil {
					d = f.Arg // bare word default
				}
				val, ok = d, true
			}
		case "raw":
			raw = true
		case "json":
			if ok {
				b, err := json.Marshal(val)
				if err != nil {
					return nil, false, raw, err
				}
				val = string(b)
			}
		case "urlencode":
			if ok {
				val = url.QueryEscape(Stringify(val))
			}
		case "base64":
			if ok {
				val = base64.StdEncoding.EncodeToString([]byte(Stringify(val)))
			}
		case "upper":
			if ok {
				val = strings.ToUpper(Stringify(val))
			}
		case "lower":
			if ok {
				val = strings.ToLower(Stringify(val))
			}
		case "join":
			if ok {
				sep := f.Arg
				if sep == "" {
					sep = ","
				}
				if list, isList := val.([]any); isList {
					parts := make([]string, len(list))
					for i, e := range list {
						parts[i] = Stringify(e)
					}
					val = strings.Join(parts, sep)
				}
			}
		}
	}
	return val, ok, raw, nil
}

// Stringify renders a value the way it should appear inside a string:
// strings verbatim, numbers without exponent noise, booleans as true/false,
// objects and arrays as JSON.
func Stringify(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case json.Number:
		return x.String()
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// Render resolves s. For a whole-string placeholder the typed value is
// returned. ok=false means the result is unset and the caller should drop
// the key (Value mode); Path and Strict modes return ErrUnset instead.
func Render(s string, vars Vars, mode Mode) (result any, ok bool, err error) {
	refs, err := Refs(s)
	if err != nil {
		return nil, false, err
	}
	if len(refs) == 0 {
		return s, true, nil
	}
	if len(refs) == 1 && refs[0].raw == s {
		val, present := vars.lookup(refs[0])
		val, present, raw, err := applyFilters(val, present, refs[0].Filters)
		if err != nil {
			return nil, false, err
		}
		if !present {
			if mode != Value {
				return nil, false, fmt.Errorf("%w: %s", ErrUnset, refs[0].raw)
			}
			return nil, false, nil
		}
		if mode == Path && !raw {
			return escapeSegment(Stringify(val)), true, nil
		}
		if mode == Path {
			return Stringify(val), true, nil
		}
		return val, true, nil
	}
	var sb strings.Builder
	var missing []string
	i := 0
	for _, r := range refs {
		at := strings.Index(s[i:], r.raw) + i
		sb.WriteString(s[i:at])
		val, present := vars.lookup(r)
		val, present, raw, err := applyFilters(val, present, r.Filters)
		if err != nil {
			return nil, false, err
		}
		if !present {
			missing = append(missing, r.raw)
		} else if mode == Path && !raw {
			sb.WriteString(escapeSegment(Stringify(val)))
		} else {
			sb.WriteString(Stringify(val))
		}
		i = at + len(r.raw)
	}
	sb.WriteString(s[i:])
	if len(missing) > 0 {
		if mode != Value {
			return nil, false, fmt.Errorf("%w: %s", ErrUnset, strings.Join(missing, ", "))
		}
		return nil, false, nil
	}
	return sb.String(), true, nil
}

// RenderString is Render for callers that need a string in Strict or Path
// mode.
func RenderString(s string, vars Vars, mode Mode) (string, error) {
	v, ok, err := Render(s, vars, mode)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrUnset
	}
	return Stringify(v), nil
}

// escapeSegment escapes a value for use inside a URL path segment. Slashes
// are escaped too: a parameter never introduces new segments.
func escapeSegment(s string) string {
	return url.PathEscape(s)
}

// RenderValue walks a decoded JSON/YAML value (maps, slices, scalars) and
// renders every string in Value mode. Map entries and slice elements whose
// rendered value is unset are dropped.
func RenderValue(v any, vars Vars) (any, error) {
	switch x := v.(type) {
	case string:
		out, ok, err := Render(x, vars, Value)
		if err != nil {
			return nil, err
		}
		if !ok {
			return unsetMarker{}, nil
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			r, err := RenderValue(e, vars)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			if _, drop := r.(unsetMarker); drop {
				continue
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			r, err := RenderValue(e, vars)
			if err != nil {
				return nil, err
			}
			if _, drop := r.(unsetMarker); drop {
				continue
			}
			out = append(out, r)
		}
		return out, nil
	default:
		return v, nil
	}
}

type unsetMarker struct{}

// Dialect selects SQL bind placeholder syntax.
type Dialect int

const (
	Postgres Dialect = iota // $1
	MySQL                   // ?
	MSSQL                   // @p0
	Oracle                  // :b0
	SQLite                  // ?
)

// SQL renders a statement, replacing every params.* placeholder with a bind
// placeholder for the dialect and collecting the values. Placeholders with
// |raw are spliced as text (for operator-provided full statements). Other
// namespaces (env, caller) are interpolated as text since they are not user
// input. An unset param binds NULL.
func SQL(stmt string, vars Vars, d Dialect) (string, []any, error) {
	refs, err := Refs(stmt)
	if err != nil {
		return "", nil, err
	}
	var sb strings.Builder
	var args []any
	i := 0
	for _, r := range refs {
		at := strings.Index(stmt[i:], r.raw) + i
		sb.WriteString(stmt[i:at])
		i = at + len(r.raw)
		val, present := vars.lookup(r)
		val, present, raw, err := applyFilters(val, present, r.Filters)
		if err != nil {
			return "", nil, err
		}
		if r.NS != "params" || raw {
			if !present {
				return "", nil, fmt.Errorf("%w: %s", ErrUnset, r.raw)
			}
			sb.WriteString(Stringify(val))
			continue
		}
		if !present {
			val = nil
		}
		args = append(args, val)
		sb.WriteString(bind(d, len(args)))
	}
	sb.WriteString(stmt[i:])
	return sb.String(), args, nil
}

func bind(d Dialect, n int) string {
	switch d {
	case Postgres:
		return "$" + strconv.Itoa(n)
	case MSSQL:
		return "@p" + strconv.Itoa(n-1)
	case Oracle:
		return ":b" + strconv.Itoa(n-1)
	default:
		return "?"
	}
}

// Names returns the distinct <ns>.<path> references in s, sorted.
func Names(s string) []string {
	refs, _ := Refs(s)
	seen := map[string]bool{}
	for _, r := range refs {
		if r.NS == "literal" {
			continue
		}
		seen[r.NS+"."+strings.Join(r.Path, ".")] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}
