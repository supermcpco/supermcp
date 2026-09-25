package mcp

import (
	"context"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/supermcpco/supermcp/internal/mcpserver"
)

// The system tools pass the hidden-tool guard on a server that does not
// list them, in both modes, and anything else outside the surface still
// does not.
func TestSystemToolsPassTheGuardUnlisted(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{mcpserver.SessionsStateless, mcpserver.SessionsStateful} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r := newRig(t, mode, SessionOptions{})
			ctx := context.Background()
			cs := r.connect(ctx)

			list, err := cs.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, tl := range list.Tools {
				if isSystemTool(tl.Name) {
					t.Errorf("%s is listed on a server nothing holds calls on", tl.Name)
				}
			}
			for _, name := range []string{ToolApprovalStatus, ToolApprovalCancel} {
				res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: map[string]any{"requestId": "r_1"}})
				if err != nil {
					t.Fatalf("%s was refused: %v", name, err)
				}
				// This endpoint has no approvals behind it, which is the
				// answer that proves the call reached the tool.
				if text := res.Content[0].(*sdk.TextContent).Text; !res.IsError || !strings.Contains(text, "not configured") {
					t.Errorf("%s: %q", name, text)
				}
			}
			if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "supermcp_something_else"}); err == nil ||
				!strings.Contains(err.Error(), "not available") {
				t.Errorf("a made-up supermcp_ name got past the guard: %v", err)
			}
		})
	}
}
