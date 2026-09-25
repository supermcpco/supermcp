package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/engine"
	"github.com/supermcpco/supermcp/internal/engine/database"
	"github.com/supermcpco/supermcp/internal/invoke"
	"github.com/supermcpco/supermcp/pkg/tmpl"
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
					return nil, dryRunErr(err)
				}
				return &dryRunOutput{Body: preview}, nil
			}
			return nil, huma.Error404NotFound("no such tool on this connector")
		})
}

// dryRunErr is the answer for a dry run that failed: 422 when the
// renderer refused, else humaErr's.
func dryRunErr(err error) error {
	if msg, ok := renderRefusal(err); ok {
		return huma.Error422UnprocessableEntity(msg)
	}
	return humaErr(err)
}

// renderRefusal is what the caller is told when the renderer itself
// refused a preview: a placeholder with no value, a credential that is not
// stored, a write statement on a read-only connector, or a transport or
// auth type it cannot render. ok is false for anything else. A dry run
// also reads the connector and opens its credentials, and those errors
// name the database or the key service; they go through humaErr.
func renderRefusal(err error) (msg string, ok bool) {
	switch {
	case errors.Is(err, tmpl.ErrUnset), errors.Is(err, connector.ErrMissingCredential),
		errors.Is(err, database.ErrNotReadOnly), errors.Is(err, engine.ErrUnsupported):
		return "the request could not be rendered: " + err.Error(), true
	}
	return "", false
}
