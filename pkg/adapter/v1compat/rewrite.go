package v1compat

import (
	"regexp"
	"strings"
)

// Placeholder rewriting from the five v1 syntaxes to the single v2 syntax.
//
//	{{ENV}}      -> {{env.ENV}}
//	{{amcp.x}}   -> {{caller.x}}
//	${x}         -> {{<ns>.x}}      ns = params | auth | req, by context
//	"$x"         -> "{{params.x}}"  whole-value only
//	{x}          -> {{params.x}}    http path only, and only for declared params

var (
	reEnv = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}`)
	// OData parameters are named $expand, $filter, $top; v1 wrote them as
	// ${$expand} and "$$expand", so '$' is part of a name, not only its
	// marker.
	reInline  = regexp.MustCompile(`\$\{([A-Za-z_$][A-Za-z0-9_$]*)\}`)
	reWhole   = regexp.MustCompile(`^\$([A-Za-z_$][A-Za-z0-9_$]*)$`)
	reEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// rewriter carries the context for one adapter.
type rewriter struct {
	envUsed    map[string]bool // env vars referenced anywhere in the document
	credNames  map[string]bool // declared requiredEnvVars + optionalEnvVars
	unknownEnv []string
}

func newRewriter(credNames []string) *rewriter {
	r := &rewriter{envUsed: map[string]bool{}, credNames: map[string]bool{}}
	for _, n := range credNames {
		r.credNames[n] = true
	}
	return r
}

// ref resolves a bare name from ${x} / $x / {x}. v1 merged connector env
// vars into tool params, so a name that is a declared credential means the
// env namespace, otherwise the given one.
func (r *rewriter) ref(name, ns string) string {
	if r.credNames[name] {
		r.envUsed[name] = true
		return "{{env." + name + "}}"
	}
	return "{{" + ns + "." + name + "}}"
}

// env rewrites {{ENV}} and {{amcp.*}}. Anything else in double braces is
// left alone and reported by the caller through unknownEnv.
func (r *rewriter) env(s string) string {
	return reEnv.ReplaceAllStringFunc(s, func(m string) string {
		name := reEnv.FindStringSubmatch(m)[1]
		switch {
		case strings.HasPrefix(name, "amcp."):
			return "{{caller." + strings.TrimPrefix(name, "amcp.") + "}}"
		case strings.HasPrefix(name, "env."), strings.HasPrefix(name, "params."),
			strings.HasPrefix(name, "auth."), strings.HasPrefix(name, "caller."), strings.HasPrefix(name, "req."):
			return m // already v2
		case reEnvName.MatchString(name):
			r.envUsed[name] = true
			return "{{env." + name + "}}"
		default:
			r.unknownEnv = append(r.unknownEnv, name)
			return m
		}
	})
}

// inline rewrites ${x} into the given namespace.
func (r *rewriter) inline(s, ns string) string {
	return unglue(reInline.ReplaceAllStringFunc(s, func(m string) string {
		return r.ref(reInline.FindStringSubmatch(m)[1], ns)
	}))
}

// unglue separates a placeholder from a literal brace in front of it. A
// mongo filter written {${sortField}: -1} becomes {{{params.sortField}}:
// -1}, where the reader sees a placeholder opening one character early
// and a namespace called "{params". The brace belongs to the document and
// the space is insignificant in every format that reaches this.
func unglue(s string) string {
	for strings.Contains(s, "{{{") {
		s = strings.ReplaceAll(s, "{{{", "{ {{")
	}
	return s
}

// whole rewrites a value that is exactly "$x".
func (r *rewriter) whole(s string) (string, bool) {
	if m := reWhole.FindStringSubmatch(s); m != nil {
		return r.ref(m[1], "params"), true
	}
	return s, false
}

// value rewrites a mapping value (query/body/header): env, then whole
// "$x", then inline ${x}.
func (r *rewriter) value(s string) string {
	s = r.env(s)
	if v, ok := r.whole(s); ok {
		return v
	}
	return r.inline(s, "params")
}

// path rewrites an HTTP path: env, inline ${x}, then {x} for declared
// params. Returns the names of {x} segments that are not declared so the
// caller can report them.
func (r *rewriter) path(s string, declared map[string]bool) (string, []string) {
	s = r.env(s)
	s = r.inline(s, "params")
	var undeclared []string
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '{' {
			out.WriteByte(c)
			continue
		}
		// skip {{...}} verbatim
		if i+1 < len(s) && s[i+1] == '{' {
			end := strings.Index(s[i:], "}}")
			if end < 0 {
				out.WriteString(s[i:])
				break
			}
			out.WriteString(s[i : i+end+2])
			i += end + 1
			continue
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			out.WriteString(s[i:])
			break
		}
		name := s[i+1 : i+end]
		if isIdent(name) && (declared[name] || r.credNames[name]) {
			out.WriteString(r.ref(name, "params"))
		} else {
			if isIdent(name) {
				undeclared = append(undeclared, name)
			}
			out.WriteString(s[i : i+end+1])
		}
		i += end
	}
	return out.String(), undeclared
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		switch {
		case c == '_', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
