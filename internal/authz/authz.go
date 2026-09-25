// Package authz decides what a principal may do. Decisions fail closed:
// no binding, no permission.
package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// Permission is a "resource:action" string from the closed set below.
type Permission string

// The closed permission set. A role referencing anything else fails
// validation.
const (
	OrgRead           Permission = "org:read"
	OrgUpdate         Permission = "org:update"
	OrgDelete         Permission = "org:delete"
	OrgMembersManage  Permission = "org:members:manage"
	OrgSettingsManage Permission = "org:settings:manage"
	OrgBillingManage  Permission = "org:billing:manage"
	ConnectorsRead    Permission = "connectors:read"
	ConnectorsCreate  Permission = "connectors:create"
	ConnectorsUpdate  Permission = "connectors:update"
	ConnectorsDelete  Permission = "connectors:delete"
	ConnectorsAuth    Permission = "connectors:auth:update"
	ConnectorsTest    Permission = "connectors:test"
	ToolsRead         Permission = "tools:read"
	ToolsUpdate       Permission = "tools:update"
	ToolsInvoke       Permission = "tools:invoke"
	ToolsInvokeDestr  Permission = "tools:invoke:destructive"
	ServersRead       Permission = "servers:read"
	ServersCreate     Permission = "servers:create"
	ServersUpdate     Permission = "servers:update"
	ServersDelete     Permission = "servers:delete"
	RolesRead         Permission = "roles:read"
	RolesManage       Permission = "roles:manage"
	APIKeysSelf       Permission = "apikeys:self:manage"
	APIKeysOrg        Permission = "apikeys:org:manage" //nolint:gosec // permission name, not a credential
	ServiceAccounts   Permission = "serviceaccounts:manage"
	IdpManage         Permission = "idp:manage"
	ScimManage        Permission = "scim:manage"
	AuditRead         Permission = "audit:read"
	AuditExport       Permission = "audit:export"
	AuditPolicy       Permission = "audit:policy:manage"
	ApprovalsRequest  Permission = "approvals:request"
	ApprovalsDecide   Permission = "approvals:decide"
	DLPManage         Permission = "dlp:manage"
	RevisionsRollback Permission = "revisions:rollback"
	SecretsRotate     Permission = "secrets:rotate"
	Wildcard          Permission = "*"
)

// All lists every permission (excluding the wildcard).
func All() []Permission {
	return []Permission{OrgRead, OrgUpdate, OrgDelete, OrgMembersManage, OrgSettingsManage, OrgBillingManage,
		ConnectorsRead, ConnectorsCreate, ConnectorsUpdate, ConnectorsDelete, ConnectorsAuth, ConnectorsTest,
		ToolsRead, ToolsUpdate, ToolsInvoke, ToolsInvokeDestr, ServersRead, ServersCreate, ServersUpdate, ServersDelete,
		RolesRead, RolesManage, APIKeysSelf, APIKeysOrg, ServiceAccounts, IdpManage, ScimManage,
		AuditRead, AuditExport, AuditPolicy, ApprovalsRequest, ApprovalsDecide, DLPManage, RevisionsRollback, SecretsRotate}
}

var known = func() map[Permission]bool {
	m := map[Permission]bool{Wildcard: true}
	for _, p := range All() {
		m[p] = true
	}
	return m
}()

// Valid reports whether p is in the closed set.
func Valid(p Permission) bool { return known[p] }

// MCP token scopes map to permissions.
const (
	ScopeToolsRead   = "mcp:tools:read"
	ScopeToolsInvoke = "mcp:tools:invoke"
	ScopeOrg         = "mcp:org" // org-wide admin-issued keys
	// ScopeSCIM is the provisioning credential's scope: it reaches the
	// SCIM endpoints and nothing else, so the key an identity provider
	// holds cannot also call tools or change settings.
	ScopeSCIM = "scim:write"
)

// PrincipalKind enumerates who is acting.
type PrincipalKind string

const (
	KindUser           PrincipalKind = "user"
	KindServiceAccount PrincipalKind = "service_account"
	KindAPIKey         PrincipalKind = "api_key"
	KindAnonymous      PrincipalKind = "anonymous"
)

// Principal is the authenticated caller, set in the request context.
type Principal struct {
	Kind       PrincipalKind
	ID         string // user or service account id
	OrgID      string
	SessionID  string
	APIKeyID   string
	ServerID   string   // audience-bound server for MCP tokens/keys; "" = org-wide
	Scopes     []string // MCP tokens and API keys only
	MFA        bool
	AuthMethod string // session | api_key | oauth_at | client_credentials
	Email      string
	// PasswordExpired marks a password session whose password is past the
	// workspace's maximum age. It may change the password, read the
	// session and sign out; everything else is refused until it does.
	PasswordExpired bool
	// SignIn says how and when a browser session last proved who is
	// using it. It is zero for API keys, OAuth access tokens and service
	// accounts, which are not signed in by a person and cannot be asked
	// to sign in again.
	SignIn SignIn
}

// SignIn is the sign-in behind a browser session.
type SignIn struct {
	// At is the last time the holder authenticated: the sign-in, or the
	// latest re-authentication since.
	At time.Time
	// Method is password, sso or saml.
	Method string
	// ProviderID is the single sign-on provider for sso and saml.
	ProviderID string
	// Methods are the authentication methods the provider reported for
	// sso and saml, as it spelled them; nil for a password.
	Methods []string
}

// BindingPrincipal is the (kind, id) a binding refers to. API keys act as
// their owning principal.
func (p Principal) BindingPrincipal() (string, string) {
	switch p.Kind {
	case KindAPIKey:
		return "user", p.ID
	case KindServiceAccount:
		return "service_account", p.ID
	default:
		return "user", p.ID
	}
}

type ctxKey int

const principalKey ctxKey = iota

// WithPrincipal stores the principal in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// From returns the principal from ctx.
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok && p != nil
}

// Resource is what a permission applies to. Empty fields widen the scope.
type Resource struct {
	OrgID       string
	ServerID    string
	ConnectorID string
	ToolID      string
	Destructive bool
}

// Decision explains an allow/deny.
type Decision struct {
	Allow  bool
	Reason string
}

// ErrDenied is returned by Require.
var ErrDenied = errors.New("permission denied")

// binding is a role binding joined with its permissions.
type binding struct {
	roleID      string
	scopeKind   string
	scopeID     string
	permissions map[Permission]bool
	expiresAt   *time.Time
}

type cacheEntry struct {
	bindings []binding
	deny     map[string]map[string]bool // toolID -> roleID -> denied
	allow    map[string]map[string]bool // toolID -> roleID -> allowed
	at       time.Time
}

// Evaluator loads bindings and evaluates requests.
//
// Each principal's bindings and the organisation's tool access rules are
// cached for TTL. A write on this replica calls Invalidate; a write on any
// replica reaches InvalidateOrg through the invalidation listener, which
// the database notifies on commit. TTL is the backstop for when the
// listener is not connected.
type Evaluator struct {
	DB  *tenant.DB
	TTL time.Duration
	// OnInvalidate, when set, is told of each local invalidation (source
	// "local"), for the invalidation counter.
	OnInvalidate func(source string)

	// mu guards cache, gen and orgGen.
	mu    sync.Mutex
	cache map[string]*cacheEntry
	// gen counts full flushes and orgGen each organisation's
	// invalidations. A load that started before either moved must not
	// store what it read, or the entry the invalidation meant to drop
	// would come back for a whole TTL. orgGen is emptied by a full flush,
	// so it holds at most the organisations invalidated since the last.
	gen    uint64
	orgGen map[string]uint64
	now    func() time.Time
}

// New builds an evaluator with a 30s cache.
func New(db *tenant.DB) *Evaluator {
	return &Evaluator{DB: db, TTL: 30 * time.Second, cache: map[string]*cacheEntry{},
		orgGen: map[string]uint64{}, now: time.Now}
}

// Invalidate drops cached bindings after a write on this replica: one
// principal's, the organisation's when id is "", or everything when orgID
// is "" too.
func (e *Evaluator) Invalidate(orgID, kind, id string) {
	switch {
	case orgID == "":
		e.InvalidateAll()
	case id == "":
		e.InvalidateOrg(orgID)
	default:
		e.mu.Lock()
		delete(e.cache, cacheKey(orgID, kind, id))
		e.orgGen[orgID]++
		e.mu.Unlock()
	}
	if e.OnInvalidate != nil {
		e.OnInvalidate("local")
	}
}

// InvalidateOrg drops every cached entry of one organisation.
func (e *Evaluator) InvalidateOrg(orgID string) {
	prefix := orgID + "|"
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.cache {
		if strings.HasPrefix(k, prefix) {
			delete(e.cache, k)
		}
	}
	e.orgGen[orgID]++
}

// InvalidateAll drops every cached entry.
func (e *Evaluator) InvalidateAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	clear(e.cache)
	clear(e.orgGen)
	e.gen++
}

// Evaluate decides whether p holds perm on r.
func (e *Evaluator) Evaluate(ctx context.Context, p *Principal, perm Permission, r Resource) (Decision, error) {
	if p == nil || p.Kind == KindAnonymous {
		return Decision{Reason: "anonymous"}, nil
	}
	if r.OrgID == "" {
		r.OrgID = p.OrgID
	}
	if p.OrgID == "" || r.OrgID != p.OrgID {
		return Decision{Reason: "org mismatch"}, nil
	}
	if p.ServerID != "" && r.ServerID != "" && r.ServerID != p.ServerID {
		return Decision{Reason: "token is bound to another server"}, nil
	}
	// Scoped tokens must carry the matching MCP scope.
	if len(p.Scopes) > 0 && !hasScope(p.Scopes, ScopeOrg) {
		switch perm {
		case ToolsRead:
			if !hasScope(p.Scopes, ScopeToolsRead) && !hasScope(p.Scopes, ScopeToolsInvoke) {
				return Decision{Reason: "missing scope " + ScopeToolsRead}, nil
			}
		case ToolsInvoke, ToolsInvokeDestr:
			if !hasScope(p.Scopes, ScopeToolsInvoke) {
				return Decision{Reason: "missing scope " + ScopeToolsInvoke}, nil
			}
		case ScimManage:
			if !hasScope(p.Scopes, ScopeSCIM) {
				return Decision{Reason: "missing scope " + ScopeSCIM}, nil
			}
		default:
			return Decision{Reason: "scoped credential cannot " + string(perm)}, nil
		}
	}
	entry, err := e.load(ctx, p)
	if err != nil {
		return Decision{}, err
	}
	now := e.now()
	var matched []binding
	for _, b := range entry.bindings {
		if b.expiresAt != nil && b.expiresAt.Before(now) {
			continue
		}
		if !scopeContains(b, r) {
			continue
		}
		matched = append(matched, b)
	}
	if len(matched) == 0 {
		return Decision{Reason: "no binding"}, nil
	}
	// Explicit deny wins.
	if r.ToolID != "" {
		for _, b := range matched {
			if entry.deny[r.ToolID][b.roleID] {
				return Decision{Reason: "explicitly denied for role " + b.roleID}, nil
			}
		}
	}
	has := func(want Permission) bool {
		for _, b := range matched {
			if b.permissions[Wildcard] || b.permissions[want] {
				return true
			}
		}
		return false
	}
	if !has(perm) {
		return Decision{Reason: "no role grants " + string(perm)}, nil
	}
	// Whitelist semantics: when a tool has allow rules, the principal must
	// hold one of those roles.
	if (perm == ToolsInvoke || perm == ToolsInvokeDestr) && r.ToolID != "" {
		if allowRoles := entry.allow[r.ToolID]; len(allowRoles) > 0 {
			ok := false
			for _, b := range matched {
				if allowRoles[b.roleID] {
					ok = true
				}
			}
			if !ok {
				return Decision{Reason: "tool is restricted to specific roles"}, nil
			}
		}
	}
	if r.Destructive && perm == ToolsInvoke && !has(ToolsInvokeDestr) {
		return Decision{Reason: "destructive tools need tools:invoke:destructive"}, nil
	}
	return Decision{Allow: true}, nil
}

// Require is Evaluate that returns ErrDenied.
func (e *Evaluator) Require(ctx context.Context, perm Permission, r Resource) error {
	p, _ := From(ctx)
	d, err := e.Evaluate(ctx, p, perm, r)
	if err != nil {
		return err
	}
	if !d.Allow {
		return fmt.Errorf("%w: %s (%s)", ErrDenied, perm, d.Reason)
	}
	return nil
}

func hasScope(scopes []string, s string) bool {
	for _, x := range scopes {
		if x == s {
			return true
		}
	}
	return false
}

func scopeContains(b binding, r Resource) bool {
	switch b.scopeKind {
	case "org":
		return true
	case "server":
		return r.ServerID != "" && r.ServerID == b.scopeID
	case "connector":
		return r.ConnectorID != "" && r.ConnectorID == b.scopeID
	case "tool":
		return r.ToolID != "" && r.ToolID == b.scopeID
	}
	return false
}

func (e *Evaluator) load(ctx context.Context, p *Principal) (*cacheEntry, error) {
	kind, id := p.BindingPrincipal()
	key := cacheKey(p.OrgID, kind, id)
	e.mu.Lock()
	if c, ok := e.cache[key]; ok && e.now().Sub(c.at) < e.TTL {
		e.mu.Unlock()
		return c, nil
	}
	gen, orgGen := e.gen, e.orgGen[p.OrgID]
	e.mu.Unlock()

	entry := &cacheEntry{deny: map[string]map[string]bool{}, allow: map[string]map[string]bool{}, at: e.now()}
	err := e.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
		// A person's bindings count only while they are an active member:
		// a deactivated or removed member's credential fails closed here
		// even if it outlives the revocation that should have ended it.
		rows, err := tx.Query(ctx, `
SELECT b.role_id, b.scope_kind, COALESCE(b.scope_id, ''), b.expires_at, r.permissions
FROM role_bindings b JOIN roles r ON r.id = b.role_id
WHERE b.organization_id = $1 AND b.principal_kind = $2 AND b.principal_id = $3
  AND ($2 <> 'user' OR EXISTS (SELECT 1 FROM organization_members m
       WHERE m.organization_id = $1 AND m.user_id = $3 AND m.deactivated_at IS NULL))`, p.OrgID, kind, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b binding
			var perms []string
			if err := rows.Scan(&b.roleID, &b.scopeKind, &b.scopeID, &b.expiresAt, &perms); err != nil {
				return err
			}
			b.permissions = map[Permission]bool{}
			for _, s := range perms {
				b.permissions[Permission(s)] = true
			}
			entry.bindings = append(entry.bindings, b)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rules, err := tx.Query(ctx, `SELECT tool_id, role_id, effect FROM tool_access_rules WHERE organization_id = $1`, p.OrgID)
		if err != nil {
			return err
		}
		defer rules.Close()
		for rules.Next() {
			var toolID, roleID, effect string
			if err := rules.Scan(&toolID, &roleID, &effect); err != nil {
				return err
			}
			m := entry.allow
			if effect == "deny" {
				m = entry.deny
			}
			if m[toolID] == nil {
				m[toolID] = map[string]bool{}
			}
			m[toolID][roleID] = true
		}
		return rules.Err()
	})
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	// An invalidation landed while this read was in flight, so what it
	// read may be what the invalidation was about. Answer this request
	// with it, but do not keep it.
	if e.gen == gen && e.orgGen[p.OrgID] == orgGen {
		e.cache[key] = entry
	}
	e.mu.Unlock()
	return entry, nil
}

func cacheKey(orgID, kind, id string) string {
	return orgID + "|" + kind + "|" + id
}

// EffectivePermissions lists what a principal holds at org scope (for the
// UI and session bootstrap).
func (e *Evaluator) EffectivePermissions(ctx context.Context, p *Principal) ([]Permission, error) {
	entry, err := e.load(ctx, p)
	if err != nil {
		return nil, err
	}
	set := map[Permission]bool{}
	for _, b := range entry.bindings {
		if b.scopeKind != "org" {
			continue
		}
		if b.permissions[Wildcard] {
			return append([]Permission{Wildcard}, All()...), nil
		}
		for perm := range b.permissions {
			set[perm] = true
		}
	}
	out := make([]Permission, 0, len(set))
	for perm := range set {
		out = append(out, perm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// ValidatePermissions checks a role definition.
func ValidatePermissions(perms []string) error {
	var bad []string
	for _, s := range perms {
		if !Valid(Permission(s)) {
			bad = append(bad, s)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("unknown permissions: %s", strings.Join(bad, ", "))
	}
	return nil
}
