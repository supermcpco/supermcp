package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/connector"
	"github.com/supermcpco/supermcp/internal/tool"
	"github.com/supermcpco/supermcp/pkg/adapter"
)

// resyncDTO is what a catalog re-sync changes, or changed.
type resyncDTO struct {
	ConnectorID        string           `json:"connectorId"`
	CatalogSlug        string           `json:"catalogSlug"`
	InstalledHash      string           `json:"installedHash" doc:"The catalog hash the connector was installed or last re-synced from"`
	BundledHash        string           `json:"bundledHash" doc:"The content hash of the adapter this server carries; send it back as catalogHash to apply"`
	Outdated           bool             `json:"outdated" doc:"The bundled adapter differs from the one the connector came from"`
	Version            int64            `json:"version" doc:"The connector version the plan was made against; send it back as expectedVersion to apply"`
	Add                []resyncToolDTO  `json:"add" nullable:"false"`
	Update             []resyncToolDTO  `json:"update" nullable:"false"`
	Remove             []resyncToolDTO  `json:"remove" nullable:"false"`
	Skipped            []resyncSkipDTO  `json:"skipped" nullable:"false" doc:"Tools the catalog would change but a person owns; they are left alone"`
	Fields             []resyncFieldDTO `json:"fields" nullable:"false" doc:"Connector settings the re-sync replaces"`
	MissingCredentials []string         `json:"missingCredentials" nullable:"false" doc:"Credentials the bundled adapter requires that the connector does not have; set them separately"`
}

// resyncToolDTO is one tool a re-sync adds, rewrites or removes.
type resyncToolDTO struct {
	Name        string   `json:"name"`
	ToolID      string   `json:"toolId,omitempty" doc:"Empty for a tool not yet added"`
	Description string   `json:"description,omitempty"`
	Changed     []string `json:"changed,omitempty" doc:"For an update: the top-level definition fields that change"`
}

// resyncSkipDTO is one tool a re-sync leaves alone.
type resyncSkipDTO struct {
	Name   string `json:"name"`
	ToolID string `json:"toolId"`
	Reason string `json:"reason" enum:"edited,custom" doc:"edited: someone changed the tool by hand; custom: a tool made in the editor has this name"`
	Change string `json:"change" enum:"add,update,remove" doc:"What the re-sync would otherwise have done"`
}

// resyncFieldDTO is one connector setting a re-sync replaces.
type resyncFieldDTO struct {
	Field  string `json:"field" enum:"instructions,transport,auth"`
	Before string `json:"before" doc:"The current value: text for instructions, JSON for transport and auth"`
	After  string `json:"after" doc:"The bundled value, in the same form"`
}

type resyncApplyInput struct {
	ID   string `path:"id" doc:"The connector"`
	Body struct {
		CatalogHash     string `json:"catalogHash" minLength:"1" doc:"The bundledHash of the plan that was reviewed"`
		ExpectedVersion int64  `json:"expectedVersion" minimum:"1" doc:"The version of the plan that was reviewed"`
	}
}

type resyncApplyOutput struct {
	Body struct {
		Connector connectorDTO `json:"connector"`
		Applied   resyncDTO    `json:"applied" doc:"What the re-sync changed"`
	}
}

// Re-syncing rewrites a connector's settings and its tools, so it takes
// both connectors:update and tools:update, as creating or deleting a tool
// does; one that takes the destructive hint off a tool whose operation
// implies it also takes tools:invoke:destructive, as the editor does.

func (d Deps) resyncRoutes(api huma.API) {
	huma.Register(api, huma.Operation{OperationID: "connectors-resync-preview", Method: http.MethodGet, Path: "/api/v1/connectors/{id}/resync",
		Summary: "Compare a catalog connector with the adapter this server carries", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ID string `path:"id" doc:"The connector"`
		}) (*struct{ Body resyncDTO }, error) {
			r := authz.Resource{ConnectorID: in.ID}
			p, err := d.require(ctx, authz.ConnectorsRead, r)
			if err != nil {
				return nil, err
			}
			if _, err := d.require(ctx, authz.ToolsRead, r); err != nil {
				return nil, err
			}
			plan, err := d.Connectors.PlanResync(ctx, p.OrgID, in.ID, d.Catalog.Bundled)
			if err != nil {
				return nil, humaErr(err)
			}
			return &struct{ Body resyncDTO }{Body: resyncToDTO(plan)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "connectors-resync", Method: http.MethodPost, Path: "/api/v1/connectors/{id}/resync",
		Summary: "Re-sync a catalog connector with the adapter this server carries", Tags: []string{"connectors"}, Security: sessionSecurity},
		func(ctx context.Context, in *resyncApplyInput) (*resyncApplyOutput, error) {
			r := authz.Resource{ConnectorID: in.ID}
			p, err := d.require(ctx, authz.ConnectorsUpdate, r)
			if err != nil {
				return nil, err
			}
			if _, err := d.require(ctx, authz.ToolsUpdate, r); err != nil {
				return nil, err
			}
			// The escalation is decided on the plan read here. Apply
			// refuses unless the connector is still at the version the
			// caller reviewed, and the plan is a function of that version
			// and the bundled adapter, so this is the plan that is applied.
			plan, err := d.Connectors.PlanResync(ctx, p.OrgID, in.ID, d.Catalog.Bundled)
			if err != nil {
				return nil, humaErr(err)
			}
			declassified := resyncDeclassifies(plan)
			if declassified {
				if _, err := d.require(ctx, authz.ToolsInvokeDestr, authz.Resource{ConnectorID: in.ID, Destructive: true}); err != nil {
					return nil, err
				}
			}
			applied, err := d.Connectors.ApplyResync(ctx, p.OrgID, in.ID, d.Catalog.Bundled, connector.ResyncInput{
				CatalogHash: in.Body.CatalogHash, ExpectedVersion: in.Body.ExpectedVersion, ActorID: p.ID,
			})
			if err != nil {
				d.adminFailed(ctx, "connector.resync", "connector", in.ID, err)
				return nil, humaErr(err)
			}
			c, err := d.Connectors.Get(ctx, p.OrgID, in.ID)
			if err != nil {
				return nil, humaErr(err)
			}
			if !applied.Empty() || applied.Outdated() {
				d.resynced(ctx, c, applied, declassified)
			}
			out := &resyncApplyOutput{}
			out.Body.Connector = d.connectorDTO(c)
			out.Body.Applied = resyncToDTO(applied)
			return out, nil
		})
}

// resyncDeclassifies reports whether any tool the plan adds or rewrites
// loses a destructive hint its operation implies.
func resyncDeclassifies(p *connector.ResyncPlan) bool {
	for _, t := range p.Add {
		if tool.Declassifies(nil, t.After, p.Transport.Type, p.Connector.ReadOnly) {
			return true
		}
	}
	for _, t := range p.Update {
		if tool.Declassifies(t.Before.Definition, t.After, p.Transport.Type, p.Connector.ReadOnly) {
			return true
		}
	}
	return false
}

// resynced records an applied re-sync: the connector settings and tool
// definitions it replaced, before and after, and what it skipped.
func (d Deps) resynced(ctx context.Context, c *connector.Connector, p *connector.ResyncPlan, declassified bool) {
	before := map[string]any{"catalogHash": p.Connector.CatalogHash}
	after := map[string]any{"catalogHash": p.BundledHash}
	for _, f := range p.Fields {
		if f.Field == "instructions" {
			before[f.Field], after[f.Field] = f.Before, f.After
			continue
		}
		before[f.Field], after[f.Field] = json.RawMessage(f.Before), json.RawMessage(f.After)
	}
	was, now := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	for _, t := range p.Update {
		was[t.Name], now[t.Name] = definitionRaw(t.Before.Definition), definitionRaw(t.After)
	}
	for _, t := range p.Remove {
		was[t.Name] = definitionRaw(t.Before.Definition)
	}
	for _, t := range p.Add {
		now[t.Name] = definitionRaw(t.After)
	}
	if len(was) > 0 {
		before["tools"] = was
	}
	if len(now) > 0 {
		after["tools"] = now
	}
	skipped := make([]string, 0, len(p.Skipped))
	for _, s := range p.Skipped {
		skipped = append(skipped, s.Name)
	}
	meta := map[string]any{"added": len(p.Add), "updated": len(p.Update), "removed": len(p.Remove), "skipped": skipped}
	if declassified {
		meta["declassified"] = true
	}
	d.emit(ctx, audit.Event{Category: audit.CategoryAdmin, Action: "connector.resync", Outcome: audit.Success,
		TargetKind: "connector", TargetID: c.ID, TargetDisplay: c.Name, Diff: audit.Changes(before, after), Meta: meta})
}

// definitionRaw is a definition's storage form for the audit diff, or
// null in the unlikely case it does not encode.
func definitionRaw(t *adapter.Tool) json.RawMessage {
	raw, err := connector.DefinitionJSON(t)
	if err != nil {
		return json.RawMessage("null")
	}
	return raw
}

func resyncToDTO(p *connector.ResyncPlan) resyncDTO {
	out := resyncDTO{
		ConnectorID: p.Connector.ID, CatalogSlug: p.Connector.CatalogSlug, InstalledHash: p.Connector.CatalogHash,
		BundledHash: p.BundledHash, Outdated: p.Outdated(), Version: p.Connector.Version,
		Add: resyncToolsToDTO(p.Add), Update: resyncToolsToDTO(p.Update), Remove: resyncToolsToDTO(p.Remove),
		Skipped: make([]resyncSkipDTO, 0, len(p.Skipped)), Fields: make([]resyncFieldDTO, 0, len(p.Fields)),
		MissingCredentials: append([]string{}, p.MissingCredentials...),
	}
	for _, s := range p.Skipped {
		out.Skipped = append(out.Skipped, resyncSkipDTO{Name: s.Name, ToolID: s.ToolID, Reason: s.Reason, Change: s.Change})
	}
	for _, f := range p.Fields {
		out.Fields = append(out.Fields, resyncFieldDTO{Field: f.Field, Before: f.Before, After: f.After})
	}
	return out
}

func resyncToolsToDTO(ts []connector.ResyncTool) []resyncToolDTO {
	out := make([]resyncToolDTO, 0, len(ts))
	for _, t := range ts {
		dto := resyncToolDTO{Name: t.Name, ToolID: t.ToolID, Changed: t.Changed}
		switch {
		case t.After != nil:
			dto.Description = t.After.Description
		case t.Before != nil && t.Before.Definition != nil:
			dto.Description = t.Before.Definition.Description
		}
		out = append(out, dto)
	}
	return out
}

// catalogOutdated reports whether the adapter this server carries differs
// from the one c was installed or last re-synced from. It reads the
// embedded index only, so a list costs no query per connector. A
// connector whose adapter the catalog no longer has is not outdated:
// there is nothing to re-sync it with.
func (d Deps) catalogOutdated(c *connector.Connector) bool {
	if c.CatalogSlug == "" || d.Catalog == nil {
		return false
	}
	e, ok := d.Catalog.Entry(c.CatalogSlug)
	return ok && e.ContentHash != c.CatalogHash
}

// connectorDTO is the wire shape of c, with whether it is outdated.
func (d Deps) connectorDTO(c *connector.Connector) connectorDTO {
	dto := connectorToDTO(c)
	dto.CatalogOutdated = d.catalogOutdated(c)
	return dto
}

func (d Deps) connectorsDTO(list []*connector.Connector) []connectorDTO {
	out := make([]connectorDTO, 0, len(list))
	for _, c := range list {
		out = append(out, d.connectorDTO(c))
	}
	return out
}
