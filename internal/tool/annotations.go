// Package tool derives MCP tool metadata from adapter definitions.
package tool

import (
	"strings"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

// Annotations are the MCP hints served with a tool.
type Annotations struct {
	Title           string
	ReadOnlyHint    bool
	DestructiveHint bool
	IdempotentHint  bool
	OpenWorldHint   bool
}

var additiveVerbs = []string{"create", "add", "insert", "post", "send", "register", "submit", "upload", "start", "new"}

// Derive computes annotations from the operation, then applies any
// explicit overrides from the tool definition. Read-only is never guessed
// from the name; explicit readOnly implies not destructive and idempotent.
func Derive(t *adapter.Tool, transport adapter.TransportType, connectorReadOnly bool) Annotations {
	a := Annotations{OpenWorldHint: true}
	op := t.Operation
	switch {
	case op.Kind == "static":
		a.ReadOnlyHint, a.IdempotentHint, a.OpenWorldHint = true, true, false
	case transport == adapter.TransportGraphQL:
		if op.Kind == "mutation" {
			a.DestructiveHint = !hasAdditiveVerb(t.Name)
		} else {
			a.ReadOnlyHint, a.IdempotentHint = true, true
		}
	case transport == adapter.TransportDatabase:
		if op.Kind == "schema" || connectorReadOnly || looksSelect(op.Statement) {
			a.ReadOnlyHint, a.IdempotentHint = true, true
		} else {
			a.DestructiveHint = true
		}
	default:
		switch strings.ToUpper(op.Method) {
		case "GET", "HEAD", "OPTIONS", "":
			a.ReadOnlyHint, a.IdempotentHint = true, true
		case "PUT":
			a.DestructiveHint, a.IdempotentHint = true, true
		case "DELETE":
			a.DestructiveHint, a.IdempotentHint = true, true
		case "PATCH":
			a.DestructiveHint = true
		case "POST":
			a.DestructiveHint = !hasAdditiveVerb(t.Name)
		}
	}
	if t.Annotations != nil {
		o := t.Annotations
		a.Title = o.Title
		if o.ReadOnlyHint != nil {
			a.ReadOnlyHint = *o.ReadOnlyHint
		}
		if o.DestructiveHint != nil {
			a.DestructiveHint = *o.DestructiveHint
		}
		if o.IdempotentHint != nil {
			a.IdempotentHint = *o.IdempotentHint
		}
		if o.OpenWorldHint != nil {
			a.OpenWorldHint = *o.OpenWorldHint
		}
	}
	if a.ReadOnlyHint {
		a.DestructiveHint = false
		a.IdempotentHint = true
	}
	return a
}

func hasAdditiveVerb(name string) bool {
	for _, part := range strings.Split(name, "_") {
		for _, v := range additiveVerbs {
			if part == v {
				return true
			}
		}
	}
	return false
}

func looksSelect(stmt string) bool {
	s := strings.ToUpper(strings.TrimSpace(stmt))
	return strings.HasPrefix(s, "SELECT") || strings.HasPrefix(s, "WITH") || strings.HasPrefix(s, "{") || strings.HasPrefix(s, "{{")
}

// Signature is a cheap fingerprint of the served shape, used to detect
// changes for tools/list_changed notifications.
func Signature(t *adapter.Tool, a Annotations) string {
	var sb strings.Builder
	sb.WriteString(t.Name)
	sb.WriteByte(0)
	sb.WriteString(t.Description)
	sb.WriteByte(0)
	if t.Input != nil && t.Input.N != nil {
		if b, err := t.Input.MarshalJSON(); err == nil {
			sb.Write(b)
		}
	}
	sb.WriteByte(0)
	if a.ReadOnlyHint {
		sb.WriteByte('r')
	}
	if a.DestructiveHint {
		sb.WriteByte('d')
	}
	if a.IdempotentHint {
		sb.WriteByte('i')
	}
	return sb.String()
}
