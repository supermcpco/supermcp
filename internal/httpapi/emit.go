package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/mcpauth"
	"github.com/supermcpco/supermcp/internal/reqid"
)

// Every handler that changes something, and every sign-in attempt, records
// what happened here. The helpers below exist so a handler adds one line
// rather than five, because an audit call that is tedious to write is one
// that gets left out.

// emit records an event, filling in the actor from the request context.
func (d Deps) emit(ctx context.Context, e audit.Event) {
	p, _ := authz.From(ctx)
	d.emitAs(ctx, audit.FromPrincipal(e, p))
}

// emitAs records an event whose actor the caller has already named. The
// token endpoint needs it: the client calling it has no session, and the
// actor worth recording is the person or account the token was for.
func (d Deps) emitAs(ctx context.Context, e audit.Event) {
	if d.Audit == nil {
		return
	}
	if ip, ok := ctx.Value(ipKey).(string); ok {
		e.IP = ip
	}
	if ua, ok := ctx.Value(uaKey).(string); ok {
		e.UserAgent = ua
	}
	if e.RequestID == "" {
		e.RequestID = middleware.GetReqID(ctx)
	}
	d.Audit.Emit(ctx, e)
}

// admin records a change an administrator made, with what it changed.
func (d Deps) admin(ctx context.Context, action, targetKind, targetID, display string, diff *audit.Diff) {
	d.emit(ctx, audit.Event{
		Category: audit.CategoryAdmin, Action: action, Outcome: audit.Success,
		TargetKind: targetKind, TargetID: targetID, TargetDisplay: display, Diff: diff,
	})
}

// adminFailed records an attempt that did not take effect. A rejected
// change is as interesting as an accepted one when reconstructing what
// someone tried to do. What it says about err is errorMeta's, less the
// message for an action whose refusals quote what the caller sent.
func (d Deps) adminFailed(ctx context.Context, action, targetKind, targetID string, err error) {
	if err == nil {
		return
	}
	meta := errorMeta(ctx, nil, "error", err)
	if quotesInput(action) {
		delete(meta, "message")
	}
	d.emit(ctx, audit.Event{
		Category: audit.CategoryAdmin, Action: action, Outcome: audit.Failure,
		TargetKind: targetKind, TargetID: targetID, Meta: meta,
	})
}

// quotesInput reports whether an action's refusals can quote the body the
// caller sent: an imported document, a tool definition, a pattern, a
// policy, identity provider metadata. The caller saw that message in the
// response; the audit trail, which outlives it and is exported, keeps
// only the code.
func quotesInput(action string) bool {
	switch action {
	case "connector.import", "connector.install", "connector.update",
		"tool.create", "tool.update",
		"dlp.policy.create", "dlp.policy.update",
		"approval.policy.create", "approval.policy.update",
		"saml.create", "saml.update", "idp.create", "idp.update":
		return true
	}
	return false
}

// maxAuditMessage bounds meta.message. A message the API words itself is
// a sentence; anything longer is quoting something.
const maxAuditMessage = 200

// errorMeta adds to meta what an audit event may say about err, and
// returns it. The audit trail is hash-chained, readable by workspace
// administrators and shipped by every exporter, and a driver or upstream
// error can name a host, a DSN fragment or the SQL, so the text of an
// error is never recorded as it is:
//
//   - An error the API answers with a status of its own (a 4xx, or a
//     503 for something unavailable) is recorded under key as a stable
//     code, with the message the caller was given under "message", cut
//     to maxAuditMessage characters.
//   - Anything else is recorded under key as reqid.Message, the text
//     the caller got. The error itself is in the log under the same
//     request id, written once by whoever answered the request.
//
// "requestId" is set whenever the request has one.
func errorMeta(ctx context.Context, meta map[string]any, key string, err error) map[string]any {
	if meta == nil {
		meta = map[string]any{}
	}
	id := middleware.GetReqID(ctx)
	if code, msg, ok := errorCode(err); ok {
		meta[key] = code
		if r := []rune(msg); len(r) > maxAuditMessage {
			msg = string(r[:maxAuditMessage]) + "…"
		}
		meta["message"] = msg
	} else {
		meta[key] = reqid.Message(id)
	}
	if id != "" {
		meta["requestId"] = id
	}
	return meta
}

// errorCode is the stable code and client message for an error the API
// answers with a status of its own. err is either that answer already
// (a huma.StatusError, an OAuth error) or a service error, which is run
// through the mappers the admin handlers answer with: they are pure and
// their sentinels do not overlap, so the first that gives it a status
// other than 500 is the one the caller saw.
func errorCode(err error) (code, msg string, ok bool) {
	var oe *mcpauth.OAuthError
	if errors.As(err, &oe) {
		return oe.Code, oe.Description, true
	}
	var se huma.StatusError
	if errors.As(err, &se) {
		return statusCode(se)
	}
	for _, m := range []func(error) error{roleErr, bindingErr, approvalErr, dlpErr, revisionErr, samlErr, inviteErr, reauthErr, ssoErr, humaErr} {
		if errors.As(m(err), &se) {
			if code, msg, ok := statusCode(se); ok {
				return code, msg, true
			}
		}
	}
	return "", "", false
}

// statusCode is the code for an answered error: the code in its details
// when it carries one (conflict codes such as last_owner), else its
// status in words ("not_found"). A 500 has none.
func statusCode(se huma.StatusError) (code, msg string, ok bool) {
	status := se.GetStatus()
	if status == http.StatusInternalServerError || status < 400 {
		return "", "", false
	}
	var model *huma.ErrorModel
	if errors.As(se, &model) {
		for _, d := range model.Errors {
			if v, isStr := d.Value.(string); isStr && isCode(v) {
				return v, se.Error(), true
			}
		}
	}
	return strings.ReplaceAll(strings.ToLower(http.StatusText(status)), " ", "_"), se.Error(), true
}

// isCode reports whether s looks like a code the API defines rather than
// a value a caller sent.
func isCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

// authEvent records a sign-in, a sign-out or anything else about who the
// caller is. The subject is named by address rather than id, because a
// failed attempt may not correspond to an account at all.
func (d Deps) authEvent(ctx context.Context, action, outcome, email string, meta map[string]any) {
	e := audit.Event{
		Category: audit.CategoryAuth, Action: action, Outcome: outcome,
		TargetKind: "user", TargetDisplay: email, Meta: meta,
	}
	d.emit(ctx, e)
}

// denied records an authorisation decision that went against the caller.
// A list endpoint can produce these in bulk, so only the categories worth
// alerting on reach the stream: anything that would have changed state, or
// touched a secret, or run a tool.
func (d Deps) denied(ctx context.Context, perm authz.Permission, r authz.Resource, reason string) {
	if !worthRecording(perm) {
		return
	}
	d.emit(ctx, audit.Event{
		Category: audit.CategoryAuthz, Action: "access.denied", Outcome: audit.Denied,
		TargetKind: targetKindFor(r), TargetID: targetIDFor(r),
		Meta: map[string]any{"permission": string(perm), "reason": reason},
	})
}

// worthRecording keeps read-only refusals out of the stream. Someone
// browsing a screen they cannot see produces one of these per page load,
// and drowning the record is its own kind of failure.
func worthRecording(p authz.Permission) bool {
	switch p {
	case authz.ConnectorsRead, authz.ToolsRead, authz.ServersRead, authz.RolesRead, authz.OrgRead:
		return false
	}
	return true
}

func targetKindFor(r authz.Resource) string {
	switch {
	case r.ToolID != "":
		return "tool"
	case r.ConnectorID != "":
		return "connector"
	case r.ServerID != "":
		return "server"
	}
	return "organization"
}

func targetIDFor(r authz.Resource) string {
	switch {
	case r.ToolID != "":
		return r.ToolID
	case r.ConnectorID != "":
		return r.ConnectorID
	case r.ServerID != "":
		return r.ServerID
	}
	return r.OrgID
}
