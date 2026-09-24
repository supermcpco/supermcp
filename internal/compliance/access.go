package compliance

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/authz"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// AccessOptions tunes an access review.
type AccessOptions struct {
	// OrgID limits the review to one workspace. Empty reviews every one.
	OrgID string
	// DormantDays is how long a principal may go unused before the review
	// says so. Zero takes DefaultDormantDays.
	DormantDays int
}

// DefaultDormantDays is the window a principal has to be used within
// before the review calls it dormant. Ninety days is the usual quarterly
// review period: an account nobody touched between two reviews is the one
// worth asking about.
const DefaultDormantDays = 90

// Finding codes. They are stable strings so that a reviewer can filter on
// them and a second run can be diffed against the first.
const (
	FindingNoBinding          = "no-binding"
	FindingPrivilegedForever  = "privileged-binding-never-expires"
	FindingExpiredBinding     = "expired-binding"
	FindingDormant            = "dormant"
	FindingNeverUsed          = "never-used"
	FindingDisabledWithAccess = "disabled-principal-still-bound"
	FindingSecretNotRotated   = "secret-never-rotated"
	FindingKeyNeverExpires    = "credential-never-expires"
	FindingPrivilegedKey      = "privileged-credential"
	FindingUnknownPrincipal   = "binding-for-a-principal-that-is-not-there"
)

// privileged names the permissions a reviewer has to look at twice. They
// are the ones that change who can do what (the role and credential
// permissions), that change what is recorded or who may read it, that
// decide what leaves the instance, or that destroy something. A binding
// carrying one of these and no expiry is the single most common finding
// of a real access review, which is why it has a code of its own.
var privileged = map[authz.Permission]bool{
	authz.Wildcard:          true,
	authz.OrgDelete:         true,
	authz.OrgMembersManage:  true,
	authz.OrgSettingsManage: true,
	authz.OrgBillingManage:  true,
	authz.RolesManage:       true,
	authz.APIKeysOrg:        true,
	authz.ServiceAccounts:   true,
	authz.IdpManage:         true,
	authz.ScimManage:        true,
	authz.AuditExport:       true,
	authz.AuditPolicy:       true,
	authz.ApprovalsDecide:   true,
	authz.DLPManage:         true,
	authz.RevisionsRollback: true,
	authz.SecretsRotate:     true,
	authz.ToolsInvokeDestr:  true,
	authz.ConnectorsAuth:    true,
	authz.ConnectorsDelete:  true,
	authz.ServersDelete:     true,
}

// Review is one access review, across one workspace or all of them.
type Review struct {
	GeneratedAt time.Time   `json:"generatedAt"`
	DormantDays int         `json:"dormantDays"`
	Workspaces  []Workspace `json:"workspaces"`
	// Limits records what this report cannot see, in the report itself
	// rather than in a document beside it.
	Limits []string `json:"limits"`
}

// Workspace is one organisation's principals.
type Workspace struct {
	OrgID      string      `json:"orgId"`
	Slug       string      `json:"slug"`
	Name       string      `json:"name"`
	Principals []Principal `json:"principals"`
}

// Principal is one thing that can hold a role binding, or one credential
// that acts as something that can.
type Principal struct {
	Kind string `json:"kind"` // user | service_account | idp_group | api_key
	ID   string `json:"id"`
	// Display is what a reviewer recognises the principal by: an email
	// address for a person, a name for everything else.
	Display   string     `json:"display"`
	Status    string     `json:"status"` // active | disabled | deactivated | revoked | expired
	CreatedAt time.Time  `json:"createdAt"`
	LastUsed  *time.Time `json:"lastUsed,omitempty"`
	// LastUsedFrom says which record the last use came from, because "a
	// session two days ago" and "a tool call two days ago" are different
	// kinds of evidence that an account is live.
	LastUsedFrom string `json:"lastUsedFrom,omitempty"`
	// ActsAs is set on a credential: the principal whose bindings decide
	// what the credential may do.
	ActsAs string `json:"actsAs,omitempty"`
	// Scopes and ServerID narrow a credential below its owner's roles.
	Scopes    []string   `json:"scopes,omitempty"`
	ServerID  string     `json:"serverId,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// Members lists the people a group binding reaches, as this instance
	// records them. It is empty for every other kind.
	Members  []string  `json:"members,omitempty"`
	Bindings []Binding `json:"bindings"`
	// Effective is the permission set this principal holds at workspace
	// scope right now, computed the way authz.Evaluate computes it:
	// expired bindings excluded, the wildcard expanded, a credential's
	// scopes applied on top.
	Effective []string  `json:"effective"`
	Findings  []Finding `json:"findings,omitempty"`
}

// Binding is one role binding as a reviewer needs to see it.
type Binding struct {
	ID        string     `json:"id"`
	RoleID    string     `json:"roleId"`
	RoleName  string     `json:"roleName"`
	ScopeKind string     `json:"scopeKind"`
	ScopeID   string     `json:"scopeId,omitempty"`
	Source    string     `json:"source"`
	CreatedAt time.Time  `json:"createdAt"`
	CreatedBy string     `json:"createdBy,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Expired   bool       `json:"expired,omitempty"`
	// Permissions is the role's whole set; Privileged is the subset a
	// reviewer is asked to justify.
	Permissions []string `json:"permissions"`
	Privileged  []string `json:"privileged,omitempty"`
}

// Finding is something the review wants a human to look at. It is never a
// failure on its own: every one of these is lawful in some instance and
// wrong in most.
type Finding struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// AccessReview builds the review.
//
// Listing the workspaces is the only part that crosses tenants; once a
// workspace is known, everything about it is read inside that tenant's
// transaction, under the same row-level security a request would face. A
// review that read through the maintenance pool throughout would be
// easier to write and would no longer be evidence that the policies work.
func AccessReview(ctx context.Context, d Deps, opts AccessOptions) (*Review, error) {
	if opts.DormantDays <= 0 {
		opts.DormantDays = DefaultDormantDays
	}
	now := d.now()
	rev := &Review{
		GeneratedAt: now,
		DormantDays: opts.DormantDays,
		Workspaces:  []Workspace{},
		Limits: []string{
			"A permission granted by a group binding reaches whoever the identity provider puts in that group. " +
				"This report lists the group's members as SCIM last provisioned them, which is this instance's copy, not the provider's.",
			"Last use is the newest of a session, an API key's last use, a service account's last use and a tool call. " +
				"A principal that only ever read through the admin API without a session leaves none of those.",
			"Secret rotation is read from the audit stream. Retention cuts that stream, so " +
				FindingSecretNotRotated + " means no rotation is recorded in the window this instance still holds.",
			"Nothing here is an attestation. The review says what the grants are; a reviewer has to say whether they are right.",
		},
	}

	orgs, err := workspaces(ctx, d, opts.OrgID)
	if err != nil {
		return nil, err
	}
	for _, ws := range orgs {
		w, err := reviewWorkspace(ctx, d, ws, opts, now)
		if err != nil {
			return nil, fmt.Errorf("review workspace %s: %w", ws.OrgID, err)
		}
		rev.Workspaces = append(rev.Workspaces, *w)
	}
	return rev, nil
}

// workspaces lists the organisations to review. This is the cross-tenant
// step and the only one: no policy can express "every tenant", and a
// review that quietly covered only the workspace it happened to be given
// would be worse than one that refused.
func workspaces(ctx context.Context, d Deps, orgID string) ([]Workspace, error) {
	var out []Workspace
	err := d.DB.Bypass(ctx, "compliance:access-review lists every workspace, which no tenant policy can express", func(tx pgx.Tx) error {
		out = nil
		rows, err := tx.Query(ctx, `SELECT id, slug, name FROM organizations
			WHERE ($1 = '' OR id = $1 OR slug = $1) ORDER BY slug`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var w Workspace
			if err := rows.Scan(&w.OrgID, &w.Slug, &w.Name); err != nil {
				return err
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list workspaces: %w", err)
	}
	if orgID != "" && len(out) == 0 {
		return nil, fmt.Errorf("no workspace with id or slug %q", orgID)
	}
	return out, nil
}

// rawBinding is a binding as the table holds it, before it is attached to
// the principal it names.
type rawBinding struct {
	Binding
	principalKind string
	principalID   string
}

func reviewWorkspace(ctx context.Context, d Deps, ws Workspace, opts AccessOptions, now time.Time) (*Workspace, error) {
	var (
		bindings []rawBinding
		users    []Principal
		accounts []Principal
		keys     []Principal
		groups   []Principal
		rotated  map[string]time.Time
	)
	err := d.DB.Tx(tenant.WithOrg(ctx, ws.OrgID), func(tx pgx.Tx) error {
		var err error
		if bindings, err = readBindings(ctx, tx, now); err != nil {
			return fmt.Errorf("read role bindings: %w", err)
		}
		lastUse, err := readLastUse(ctx, tx)
		if err != nil {
			return fmt.Errorf("read last use: %w", err)
		}
		if users, err = readUsers(ctx, tx, ws.OrgID, lastUse); err != nil {
			return fmt.Errorf("read members: %w", err)
		}
		if accounts, err = readServiceAccounts(ctx, tx, lastUse); err != nil {
			return fmt.Errorf("read service accounts: %w", err)
		}
		if keys, err = readAPIKeys(ctx, tx, now); err != nil {
			return fmt.Errorf("read api keys: %w", err)
		}
		if groups, err = readGroups(ctx, tx); err != nil {
			return fmt.Errorf("read groups: %w", err)
		}
		if rotated, err = readSecretRotations(ctx, tx); err != nil {
			return fmt.Errorf("read secret rotations: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := Workspace{OrgID: ws.OrgID, Slug: ws.Slug, Name: ws.Name, Principals: []Principal{}}
	owner := map[string][]string{} // "kind|id" -> effective permissions, for the credentials that act as it

	for _, group := range [][]Principal{users, accounts, groups} {
		for _, p := range group {
			attach(&p, bindings)
			p.Effective = effective(p.Bindings, now)
			owner[p.Kind+"|"+p.ID] = p.Effective
			p.Findings = principalFindings(p, opts, now, rotated)
			out.Principals = append(out.Principals, p)
		}
	}
	// A credential is listed after the principals, because what it may do
	// is decided by the one it acts as, which has to be computed first.
	for _, k := range keys {
		k.Effective = narrowByScopes(owner[k.ActsAs], k.Scopes)
		k.Findings = credentialFindings(k, opts, now, owner)
		out.Principals = append(out.Principals, k)
	}
	// A binding naming a principal that is not there grants nothing, and is
	// the residue of a deletion that did not finish. It is reported as a
	// principal of its own so it cannot be missed.
	out.Principals = append(out.Principals, orphanBindings(bindings, out.Principals)...)

	sort.SliceStable(out.Principals, func(i, j int) bool {
		a, b := out.Principals[i], out.Principals[j]
		if a.Kind != b.Kind {
			return kindOrder(a.Kind) < kindOrder(b.Kind)
		}
		if a.Display != b.Display {
			return a.Display < b.Display
		}
		return a.ID < b.ID
	})
	return &out, nil
}

func kindOrder(kind string) int {
	switch kind {
	case "user":
		return 0
	case "service_account":
		return 1
	case "idp_group":
		return 2
	case "api_key":
		return 3
	default:
		return 4
	}
}

// attach moves the bindings that name this principal onto it.
func attach(p *Principal, all []rawBinding) {
	p.Bindings = []Binding{}
	for _, b := range all {
		if b.principalKind != p.Kind || b.principalID != p.ID {
			continue
		}
		p.Bindings = append(p.Bindings, b.Binding)
	}
	sort.SliceStable(p.Bindings, func(i, j int) bool {
		if p.Bindings[i].RoleName != p.Bindings[j].RoleName {
			return p.Bindings[i].RoleName < p.Bindings[j].RoleName
		}
		return p.Bindings[i].ScopeKind < p.Bindings[j].ScopeKind
	})
}

// effective computes the permission set a principal holds at workspace
// scope, the way authz.Evaluate does: an expired binding grants nothing,
// a binding scoped to one server or tool does not widen the workspace,
// and the wildcard expands to the whole closed set.
//
// It deliberately does not call authz.Evaluator.EffectivePermissions,
// which serves the session bootstrap: that method does not filter expired
// bindings, so it reports permissions the evaluator itself would refuse.
// A review has to agree with the decision, not with the screen.
func effective(bindings []Binding, now time.Time) []string {
	set := map[string]bool{}
	for _, b := range bindings {
		if b.ScopeKind != "org" {
			continue
		}
		if b.ExpiresAt != nil && b.ExpiresAt.Before(now) {
			continue
		}
		for _, perm := range b.Permissions {
			if authz.Permission(perm) == authz.Wildcard {
				out := []string{string(authz.Wildcard)}
				for _, all := range authz.All() {
					out = append(out, string(all))
				}
				return out
			}
			set[perm] = true
		}
	}
	out := make([]string, 0, len(set))
	for perm := range set {
		out = append(out, perm)
	}
	sort.Strings(out)
	return out
}

// narrowByScopes applies the ceiling a scoped credential carries, exactly
// as authz.Evaluate applies it: a credential with any scope and without
// the org scope can only read and invoke tools, whatever its owner holds.
func narrowByScopes(ownerPerms, scopes []string) []string {
	if len(scopes) == 0 || hasScope(scopes, authz.ScopeOrg) {
		return append([]string(nil), ownerPerms...)
	}
	allowed := map[authz.Permission]bool{}
	if hasScope(scopes, authz.ScopeToolsRead) || hasScope(scopes, authz.ScopeToolsInvoke) {
		allowed[authz.ToolsRead] = true
	}
	if hasScope(scopes, authz.ScopeToolsInvoke) {
		allowed[authz.ToolsInvoke] = true
		allowed[authz.ToolsInvokeDestr] = true
	}
	out := []string{}
	for _, perm := range ownerPerms {
		if allowed[authz.Permission(perm)] {
			out = append(out, perm)
		}
	}
	return out
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func principalFindings(p Principal, opts AccessOptions, now time.Time, rotated map[string]time.Time) []Finding {
	var out []Finding
	live := 0
	for _, b := range p.Bindings {
		switch {
		case b.Expired:
			out = append(out, Finding{FindingExpiredBinding, fmt.Sprintf(
				"the binding to %s expired %s and grants nothing; it is still on the record", b.RoleName, ago(b.ExpiresAt, now))})
		default:
			live++
			if b.ExpiresAt == nil && len(b.Privileged) > 0 {
				out = append(out, Finding{FindingPrivilegedForever, fmt.Sprintf(
					"%s carries %s and the binding has no expiry", b.RoleName, joinMax(b.Privileged, 6))})
			}
		}
	}
	if live == 0 && p.Kind != "api_key" {
		out = append(out, Finding{FindingNoBinding, "holds no role binding, so it can do nothing in this workspace; " +
			"an account in this state is usually one somebody forgot to remove"})
	}
	if live > 0 && (p.Status == "disabled" || p.Status == "deactivated") {
		out = append(out, Finding{FindingDisabledWithAccess, fmt.Sprintf(
			"the principal is %s but still holds %d binding(s); the grants come back with the account", p.Status, live)})
	}
	if p.Kind == "service_account" {
		if when, ok := rotated[p.ID]; ok {
			_ = when
		} else {
			out = append(out, Finding{FindingSecretNotRotated, fmt.Sprintf(
				"no secret rotation for this service account appears in the audit stream; it was created %s", ago(&p.CreatedAt, now))})
		}
	}
	out = append(out, useFindings(p, opts, now)...)
	return out
}

// useFindings reports on a principal nobody has used. A group is exempt:
// nothing is recorded against the group itself, only against the people
// in it, so calling one dormant would be an invention.
func useFindings(p Principal, opts AccessOptions, now time.Time) []Finding {
	if p.Kind == "idp_group" {
		return nil
	}
	cutoff := now.AddDate(0, 0, -opts.DormantDays)
	switch {
	case p.LastUsed == nil && p.CreatedAt.Before(cutoff):
		return []Finding{{FindingNeverUsed, fmt.Sprintf(
			"created %s and never used; nothing this instance records has been done with it", ago(&p.CreatedAt, now))}}
	case p.LastUsed != nil && p.LastUsed.Before(cutoff):
		return []Finding{{FindingDormant, fmt.Sprintf(
			"last used %s, which is beyond the %d-day window", ago(p.LastUsed, now), opts.DormantDays)}}
	}
	return nil
}

func credentialFindings(k Principal, opts AccessOptions, now time.Time, owner map[string][]string) []Finding {
	var out []Finding
	if k.Status == "revoked" {
		return nil
	}
	if k.ExpiresAt == nil {
		out = append(out, Finding{FindingKeyNeverExpires,
			"the credential has no expiry, so it stays valid until somebody revokes it"})
	}
	if _, ok := owner[k.ActsAs]; !ok {
		out = append(out, Finding{FindingUnknownPrincipal, fmt.Sprintf(
			"it acts as %s, which is not a principal of this workspace; the key outlived its owner", k.ActsAs)})
	}
	for _, perm := range k.Effective {
		if privileged[authz.Permission(perm)] {
			out = append(out, Finding{FindingPrivilegedKey, fmt.Sprintf(
				"the credential carries %s through the principal it acts as", perm)})
			break
		}
	}
	out = append(out, useFindings(k, opts, now)...)
	return out
}

// orphanBindings reports bindings whose principal no longer exists.
func orphanBindings(all []rawBinding, known []Principal) []Principal {
	seen := map[string]bool{}
	for _, p := range known {
		seen[p.Kind+"|"+p.ID] = true
	}
	byPrincipal := map[string][]Binding{}
	var order []string
	for _, b := range all {
		key := b.principalKind + "|" + b.principalID
		if seen[key] {
			continue
		}
		if _, ok := byPrincipal[key]; !ok {
			order = append(order, key)
		}
		byPrincipal[key] = append(byPrincipal[key], b.Binding)
	}
	sort.Strings(order)
	out := make([]Principal, 0, len(order))
	for _, key := range order {
		kind, id, _ := strings.Cut(key, "|")
		out = append(out, Principal{
			Kind: kind, ID: id, Display: id, Status: "not found",
			Bindings: byPrincipal[key], Effective: []string{},
			Findings: []Finding{{FindingUnknownPrincipal,
				"there is no such principal in this workspace; the binding grants nothing and is the residue of a deletion that did not finish"}},
		})
	}
	return out
}

// joinMax lists a few items and counts the rest, so one over-permissive
// role does not push everything else off the line.
func joinMax(in []string, most int) string {
	if len(in) <= most {
		return strings.Join(in, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(in[:most], ", "), len(in)-most)
}
