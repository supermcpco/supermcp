package adapter

import "strings"

// readVerbs are the leading words of a tool name that say it only reads.
// The web console keeps the same list (web/src/lib/connector.ts).
var readVerbs = []string{"get", "list", "search", "find", "read", "fetch", "describe"}

// ReadShapedName reports whether a tool's name says it reads:
// bexio_search_contacts, after the adapter's own prefix. A name that does
// not carry the slug is judged whole and after its first word.
//
// A name is a claim, not a fact. Nothing served to an MCP client is
// decided by it: the catalog converter uses it to write an explicit
// readOnlyHint into a reviewed adapter, and the validator to ask the author
// of a tool for a hint.
func ReadShapedName(name, slug string) bool {
	n := strings.ToLower(name)
	rests := []string{n}
	prefix := strings.ReplaceAll(strings.ToLower(slug), "-", "_") + "_"
	if slug != "" && strings.HasPrefix(n, prefix) {
		rests = append(rests, n[len(prefix):])
	} else if i := strings.Index(n, "_"); i >= 0 {
		rests = append(rests, n[i+1:])
	}
	for _, r := range rests {
		for _, v := range readVerbs {
			if r == v || strings.HasPrefix(r, v+"_") {
				return true
			}
		}
	}
	return false
}
