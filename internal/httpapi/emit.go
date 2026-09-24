package httpapi

import (
	"context"

	"github.com/supermcpco/supermcp/internal/audit"
	"github.com/supermcpco/supermcp/internal/authz"
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
// someone tried to do.
func (d Deps) adminFailed(ctx context.Context, action, targetKind, targetID string, err error) {
	if err == nil {
		return
	}
	d.emit(ctx, audit.Event{
		Category: audit.CategoryAdmin, Action: action, Outcome: audit.Failure,
		TargetKind: targetKind, TargetID: targetID,
		Meta: map[string]any{"error": err.Error()},
	})
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
