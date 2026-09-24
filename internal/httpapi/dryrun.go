package httpapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/invoke"
)

// Seeing the request a tool would send is how somebody decides whether to
// trust it with a real argument, and it is the fastest way to find a
// mapping that is wrong. Nothing here reaches the network.

type dryRunInput struct {
	ID     string `path:"id" doc:"The connector"`
	ToolID string `path:"toolId"`
	Body   struct {
		Arguments map[string]any `json:"arguments,omitempty" doc:"What the model would send"`
	}
}

type dryRunOutput struct{ Body *engine.Preview }

func (d Deps) dryRunRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "tools-dry-run", Method: http.MethodPost,
		Path:    "/api/v1/connectors/{id}/tools/{toolId}/dry-run",
		Summary: "Render the request a tool call would send, without sending it",
		Tags:    []string{"tools"}, Security: sessionSecurity},
		func(ctx context.Context, in *dryRunInput) (*dryRunOutput, error) {
			// A preview shows how the credential is used and what the
			// arguments render to, so it asks for the permission to make
			// the call rather than the permission to read the tool.
			p, err := d.require(ctx, authz.ToolsInvoke, authz.Resource{ConnectorID: in.ID, ToolID: in.ToolID})
			if err != nil {
				return nil, err
			}
			if d.Connectors == nil || d.Executor == nil {
				return nil, huma.Error503ServiceUnavailable("tool calls are not configured")
			}
			conn, err := d.Connectors.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, huma.Error404NotFound("no such connector")
			}
			tools, err := d.Connectors.Tools(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, err
			}
			for _, t := range tools {
				if t.ID != in.ToolID {
					continue
				}
				preview, err := d.Executor.DryRun(ctx, invoke.Call{
					Principal: p, Tool: t, Connector: conn, Args: in.Body.Arguments,
				})
				if err != nil {
					return nil, huma.Error422UnprocessableEntity("the request could not be rendered: " + err.Error())
				}
				return &dryRunOutput{Body: preview}, nil
			}
			return nil, huma.Error404NotFound("no such tool on this connector")
		})
}
