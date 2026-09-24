package tool

import (
	"testing"

	"github.com/supermcpco/supermcp/pkg/adapter"
)

func ptr(b bool) *bool { return &b }

func httpTool(name, method string, hints *adapter.Annotations) *adapter.Tool {
	return &adapter.Tool{Name: name, Operation: adapter.Operation{Method: method, Path: "/x"}, Annotations: hints}
}

func TestDeriveOperationIgnoresHints(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		tool        *adapter.Tool
		transport   adapter.TransportType
		readOnly    bool
		destructive bool
	}{
		{"delete with false hint", httpTool("remove_x", "DELETE", &adapter.Annotations{DestructiveHint: ptr(false)}), adapter.TransportHTTP, false, true},
		{"delete with read-only hint", httpTool("remove_x", "DELETE", &adapter.Annotations{ReadOnlyHint: ptr(true)}), adapter.TransportHTTP, false, true},
		{"get with destructive hint", httpTool("get_x", "GET", &adapter.Annotations{DestructiveHint: ptr(true)}), adapter.TransportHTTP, false, false},
		{"post additive", httpTool("create_x", "POST", nil), adapter.TransportHTTP, false, false},
		{"sql write on read-only connector", &adapter.Tool{Name: "w", Operation: adapter.Operation{Kind: "sql", Statement: "DELETE FROM t"}}, adapter.TransportDatabase, true, false},
		{"sql write", &adapter.Tool{Name: "w", Operation: adapter.Operation{Kind: "sql", Statement: "DELETE FROM t"}}, adapter.TransportDatabase, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := DeriveOperation(tc.tool, tc.transport, tc.readOnly).DestructiveHint; got != tc.destructive {
				t.Errorf("DeriveOperation destructive = %v, want %v", got, tc.destructive)
			}
		})
	}
}

func TestDeclassifies(t *testing.T) {
	t.Parallel()
	notDestructive := &adapter.Annotations{DestructiveHint: ptr(false)}
	readOnly := &adapter.Annotations{ReadOnlyHint: ptr(true)}
	cases := []struct {
		name          string
		before, after *adapter.Tool
		readOnly      bool
		want          bool
	}{
		{"create destructive, no hint", nil, httpTool("remove_x", "DELETE", nil), false, false},
		{"create destructive, hint false", nil, httpTool("remove_x", "DELETE", notDestructive), false, true},
		{"create destructive, read-only hint", nil, httpTool("remove_x", "DELETE", readOnly), false, true},
		{"create safe, hint false", nil, httpTool("get_x", "GET", notDestructive), false, false},
		{"add hint false", httpTool("remove_x", "DELETE", nil), httpTool("remove_x", "DELETE", notDestructive), false, true},
		{"keep hint false, edit nothing that runs", httpTool("remove_x", "DELETE", notDestructive), httpTool("remove_x", "DELETE", notDestructive), false, false},
		{"keep hint false, change operation", httpTool("get_x", "PATCH", notDestructive), httpTool("get_x", "DELETE", notDestructive), false, true},
		{"keep hint false, rename away from additive verb", httpTool("create_x", "POST", notDestructive), httpTool("run_x", "POST", notDestructive), false, true},
		{"operation becomes destructive with hint false", httpTool("get_x", "GET", notDestructive), httpTool("get_x", "DELETE", notDestructive), false, true},
		{"remove hint", httpTool("remove_x", "DELETE", notDestructive), httpTool("remove_x", "DELETE", nil), false, false},
		{"hint true", nil, httpTool("remove_x", "DELETE", &adapter.Annotations{DestructiveHint: ptr(true)}), false, false},
		{"sql write on read-only connector", nil, &adapter.Tool{Name: "w", Operation: adapter.Operation{Kind: "sql", Statement: "DELETE FROM t"}, Annotations: notDestructive}, true, false},
		{"nil after", httpTool("remove_x", "DELETE", nil), nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tt := adapter.TransportHTTP
			if tc.after != nil && tc.after.Operation.Kind == "sql" {
				tt = adapter.TransportDatabase
			}
			if got := Declassifies(tc.before, tc.after, tt, tc.readOnly); got != tc.want {
				t.Errorf("Declassifies = %v, want %v", got, tc.want)
			}
		})
	}
}
