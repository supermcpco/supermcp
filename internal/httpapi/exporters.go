package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Shipping the trail somewhere else, and stopping it being deleted, are
// the two things a compliance team asks for that the schema has always
// been able to do and nothing could reach: the exporter table was only
// writable with SQL, and the legal-hold column was only ever read.

// exporterDTO is one destination. Its credentials are write-only: they
// are sealed on the way in and never come back out, because an endpoint a
// reader can forge deliveries to, or read a token out of, is not evidence
// of anything.
type exporterDTO struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind" doc:"webhook, syslog, splunk or otlp"`
	URL        string     `json:"url" doc:"Where deliveries go, with any credential in it redacted"`
	Enabled    bool       `json:"enabled"`
	CursorSeq  int64      `json:"cursorSeq" doc:"The sequence number already delivered"`
	LastOkAt   *time.Time `json:"lastOkAt,omitempty"`
	LastError  string     `json:"lastError,omitempty"`
	Failures   int        `json:"consecutiveFailures"`
	CreatedAt  time.Time  `json:"createdAt"`
	Deliveries string     `json:"deliveries" doc:"How a batch is framed and authenticated, so a receiver knows what to expect"`
}

// exporterInput describes a destination of any kind. The fields a kind
// does not use are left out, and what is written is checked against the
// kind rather than against the union: a Splunk token in a webhook is a
// mistake worth saying out loud.
//
// Every credential here is write-only. They are sealed on the way in and
// never come back out, because a destination a reader can forge deliveries
// to, or read a token out of, is not evidence of anything.
type exporterInput struct {
	Body struct {
		Kind    string            `json:"kind,omitempty" enum:"webhook,syslog,splunk,otlp" default:"webhook" doc:"What is at the other end"`
		URL     string            `json:"url,omitempty" format:"uri" doc:"The receiver for a webhook, the collector for Splunk HEC, the logs endpoint for OTLP"`
		Secret  string            `json:"secret,omitempty" minLength:"16" maxLength:"256" doc:"Shared secret a webhook delivery's HMAC signature is computed with"`
		Token   string            `json:"token,omitempty" minLength:"8" maxLength:"512" doc:"Splunk HEC token, sent as the Authorization header"`
		Index   string            `json:"index,omitempty" maxLength:"128" doc:"Splunk index a batch lands in; the collector's default otherwise"`
		Headers map[string]string `json:"headers,omitempty" doc:"Extra headers for OTLP, for a collector behind an authenticating proxy"`

		Host     string `json:"host,omitempty" maxLength:"255" doc:"Syslog collector host"`
		Port     int    `json:"port,omitempty" minimum:"1" maximum:"65535" doc:"Syslog port; 514, or 6514 with TLS"`
		TLS      bool   `json:"tls,omitempty" doc:"Wrap the syslog connection in TLS and verify the collector's certificate"`
		Facility int    `json:"facility,omitempty" minimum:"0" maximum:"23" doc:"Syslog facility; 10 (security) by default"`
		Format   string `json:"format,omitempty" enum:"rfc5424,cef" doc:"Syslog payload: the record as JSON, or a CEF line"`

		Enabled bool `json:"enabled,omitempty" default:"true"`
	}
}

type exporterListOutput struct {
	Body struct {
		Exporters []exporterDTO `json:"exporters" nullable:"false"`
	}
}

type exporterOutput struct{ Body exporterDTO }

type legalHoldInput struct {
	Body struct {
		From   time.Time  `json:"from" doc:"Hold events at or after this time"`
		To     *time.Time `json:"to,omitempty" doc:"Hold events at or before this time; omit for everything since 'from'"`
		Reason string     `json:"reason,omitempty" maxLength:"2000" doc:"Why, for the record"`
	}
}

type legalHoldOutput struct {
	Body struct {
		Held int64 `json:"held" doc:"How many events the hold now covers"`
	}
}

var errExportersUnconfigured = huma.Error503ServiceUnavailable("shipping the audit trail is not configured")

// sealerAndID is what the exporter routes need beyond the database: the
// configuration is sealed, and a new row needs an identifier. They are
// resolved per request rather than at registration, so the routes are in
// the published document whether or not this build has them.
func (d Deps) sealerAndID() (*secrets.Sealer, func() string, bool) {
	if d.DB == nil || d.Connectors == nil || d.Connectors.Sealer == nil || d.Connectors.NewID == nil {
		return nil, nil, false
	}
	return d.Connectors.Sealer, d.Connectors.NewID, true
}

func (d Deps) exporterRoutes(api huma.API) {

	huma.Register(api, huma.Operation{OperationID: "audit-exporters-list", Method: http.MethodGet,
		Path: "/api/v1/audit/exporters", Summary: "List where the audit trail is being shipped",
		Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*exporterListOutput, error) {
			p, err := d.require(ctx, authz.AuditExport, authz.Resource{})
			if err != nil {
				return nil, err
			}
			sealer, _, ok := d.sealerAndID()
			if !ok {
				return nil, errExportersUnconfigured
			}
			out := &exporterListOutput{}
			out.Body.Exporters = []exporterDTO{}
			err = d.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
				rows, err := tx.Query(ctx, `SELECT id, kind, config_enc, enabled, cursor_seq, last_ok_at,
					COALESCE(last_error,''), consecutive_failures, created_at
					FROM audit_exporters WHERE organization_id = $1 ORDER BY created_at`, p.OrgID)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var e exporterDTO
					var sealed []byte
					if err := rows.Scan(&e.ID, &e.Kind, &sealed, &e.Enabled, &e.CursorSeq, &e.LastOkAt,
						&e.LastError, &e.Failures, &e.CreatedAt); err != nil {
						return err
					}
					e.URL, e.Deliveries = exporterDisplay(ctx, sealer, e.ID, e.Kind, p.OrgID, sealed)
					out.Body.Exporters = append(out.Body.Exporters, e)
				}
				return rows.Err()
			})
			if err != nil {
				return nil, err
			}
			return out, nil
		})

	huma.Register(api, huma.Operation{OperationID: "audit-exporters-create", Method: http.MethodPost,
		Path: "/api/v1/audit/exporters", Summary: "Ship the audit trail to a destination",
		Tags: []string{"audit"}, Security: sessionSecurity, DefaultStatus: http.StatusCreated},
		func(ctx context.Context, in *exporterInput) (*exporterOutput, error) {
			// Configuring where the record goes is not the same as reading
			// it, and it outlives whoever set it up, so it asks for the
			// permission that governs the organisation's own settings.
			p, err := d.require(ctx, authz.OrgSettingsManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			sealer, newID, ok := d.sealerAndID()
			if !ok {
				return nil, errExportersUnconfigured
			}
			ep := audit.Endpoint{
				Kind: in.Body.Kind, URL: in.Body.URL, Secret: in.Body.Secret,
				Token: in.Body.Token, Index: in.Body.Index, Headers: in.Body.Headers,
				Host: in.Body.Host, Port: in.Body.Port, TLS: in.Body.TLS,
				Facility: in.Body.Facility, Format: in.Body.Format,
			}
			// Normalising before sealing means the stored configuration
			// says plainly what the sweep will do, rather than leaving a
			// zero value to be read the same way by every later build.
			ep.Normalise()
			if err := ep.Validate(); err != nil {
				return nil, huma.Error422UnprocessableEntity(err.Error())
			}
			id := newID()
			// The secret is marshalled to be sealed, which is the one
			// place it is meant to go.
			cfg, _ := json.Marshal(ep) //nolint:gosec // sealed immediately below, never returned
			sealed, err := sealer.Seal(ctx, secrets.ScopeOrg(p.OrgID), cfg, secrets.AAD{
				Table: "audit_exporters", Column: "config_enc", RowID: id, OrgID: p.OrgID})
			if err != nil {
				return nil, err
			}
			err = d.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO audit_exporters (id, organization_id, kind, config_enc, enabled,
					cursor_seq) VALUES ($1,$2,$3,$4,$5, COALESCE((SELECT max(seq) FROM audit_events),0))`,
					id, p.OrgID, ep.Kind, sealed, in.Body.Enabled)
				return err
			})
			if err != nil {
				return nil, err
			}
			// The destination is recorded, never the credential that
			// reaches it: the trail is read by more people than the
			// configuration is.
			where := ep.Destination()
			d.emit(ctx, audit.Event{Category: audit.CategoryAdmin, Action: "audit.exporter.created",
				Outcome: audit.Success, TargetKind: "audit_exporter", TargetID: id, TargetDisplay: where,
				Meta: map[string]any{"kind": ep.Kind, "url": where, "enabled": in.Body.Enabled}})
			return &exporterOutput{Body: exporterDTO{ID: id, Kind: ep.Kind, URL: where,
				Enabled: in.Body.Enabled, CreatedAt: time.Now(), Deliveries: ep.Deliveries()}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "audit-exporters-delete", Method: http.MethodDelete,
		Path: "/api/v1/audit/exporters/{id}", Summary: "Stop shipping to a destination",
		Tags: []string{"audit"}, Security: sessionSecurity, DefaultStatus: http.StatusNoContent},
		func(ctx context.Context, in *struct {
			ID string `path:"id"`
		}) (*struct{}, error) {
			p, err := d.require(ctx, authz.OrgSettingsManage, authz.Resource{})
			if err != nil {
				return nil, err
			}
			if d.DB == nil {
				return nil, errExportersUnconfigured
			}
			var found bool
			err = d.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
				tag, err := tx.Exec(ctx, `DELETE FROM audit_exporters WHERE id = $1 AND organization_id = $2`, in.ID, p.OrgID)
				found = tag.RowsAffected() > 0
				return err
			})
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, huma.Error404NotFound("no such exporter")
			}
			d.admin(ctx, "audit.exporter.deleted", "audit_exporter", in.ID, "", nil)
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "audit-legal-hold", Method: http.MethodPost,
		Path: "/api/v1/audit/legal-hold", Summary: "Hold events against deletion",
		Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, in *legalHoldInput) (*legalHoldOutput, error) {
			return d.setHold(ctx, in.Body.From, in.Body.To, in.Body.Reason, true)
		})

	huma.Register(api, huma.Operation{OperationID: "audit-legal-hold-release", Method: http.MethodDelete,
		Path: "/api/v1/audit/legal-hold", Summary: "Release a hold",
		Tags: []string{"audit"}, Security: sessionSecurity},
		func(ctx context.Context, in *legalHoldInput) (*legalHoldOutput, error) {
			return d.setHold(ctx, in.Body.From, in.Body.To, in.Body.Reason, false)
		})
}

// setHold marks a window of one organisation's events. It runs as the
// maintenance role because the application role may not write to the
// stream at all, which is what makes the stream append-only; the
// organisation is therefore named in the statement rather than left to a
// row-level policy.
func (d Deps) setHold(ctx context.Context, from time.Time, until *time.Time, reason string, hold bool) (*legalHoldOutput, error) {
	p, err := d.require(ctx, authz.AuditExport, authz.Resource{})
	if err != nil {
		return nil, err
	}
	if d.DB == nil {
		return nil, errExportersUnconfigured
	}
	if from.IsZero() {
		return nil, huma.Error422UnprocessableEntity("a hold needs a time to start from")
	}
	to := time.Now().Add(100 * 365 * 24 * time.Hour)
	if until != nil {
		to = *until
	}
	if to.Before(from) {
		return nil, huma.Error422UnprocessableEntity("the hold ends before it starts")
	}
	var held int64
	err = d.DB.Bypass(ctx, "audit legal hold", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE audit_events SET legal_hold = $4
			WHERE organization_id = $1 AND ts >= $2 AND ts <= $3 AND legal_hold <> $4`, p.OrgID, from, to, hold)
		if err != nil {
			return err
		}
		held = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return nil, err
	}
	action := "audit.legal_hold.released"
	if hold {
		action = "audit.legal_hold.placed"
	}
	d.emit(ctx, audit.Event{Category: audit.CategoryAdmin, Action: action, Outcome: audit.Success,
		TargetKind: "organization", TargetID: p.OrgID,
		Meta: map[string]any{"from": from, "to": to, "events": held, "reason": reason}})
	out := &legalHoldOutput{}
	out.Body.Held = held
	return out, nil
}

// exporterDisplay opens just enough of the sealed configuration to show
// where deliveries go and how they are framed. A destination nobody can
// see is a destination nobody can check; the credentials stay sealed
// either way, and a password written into a URL is redacted with them.
func exporterDisplay(ctx context.Context, sealer *secrets.Sealer, id, kind, orgID string, sealed []byte) (where, deliveries string) {
	pt, err := sealer.Open(ctx, sealed, secrets.AAD{
		Table: "audit_exporters", Column: "config_enc", RowID: id, OrgID: orgID})
	if err != nil {
		return "", ""
	}
	var ep audit.Endpoint
	if err := json.Unmarshal(pt, &ep); err != nil {
		return "", ""
	}
	// The column is what the sweep ships by, so it is what is described
	// here too, whatever an older sealed blob happens to say.
	ep.Kind = kind
	ep.Normalise()
	return ep.Destination(), ep.Deliveries()
}
