package saml

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	crewjam "github.com/crewjam/saml"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/tenant"
)

// Begin starts a sign-in and returns the URL to send the browser to. The
// request is recorded before the redirect, so the assertion that comes
// back can be tied to a sign-in someone here actually started.
//
// replaces names the session a re-authentication would replace, and is
// empty for an ordinary sign-in. It is kept on the request row, so only
// the assertion answering this request reads it back. A re-authentication
// sets ForceAuthn, asking the provider to authenticate the person again
// rather than answer from a session it already holds; whether it did is
// judged from the AuthnInstant it returns, not from having asked.
func (s *Service) Begin(ctx context.Context, providerID, redirectAfter, binding, replaces string) (string, error) {
	p, err := s.load(ctx, providerID)
	if err != nil {
		return "", err
	}
	if !p.Enabled {
		return "", ErrDisabled
	}
	m, err := s.materialFor(ctx, p)
	if err != nil {
		return "", err
	}
	sp, err := s.serviceProvider(p, m)
	if err != nil {
		return "", err
	}
	if replaces != "" {
		force := true
		sp.ForceAuthn = &force
	}
	// The redirect binding carries the request in the URL; the response
	// comes back over POST, which is the only binding whose size is not
	// capped by what a browser will put in a query string.
	req, err := sp.MakeAuthenticationRequest(p.IDPSSOURL, crewjam.HTTPRedirectBinding, crewjam.HTTPPostBinding)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotConfigured, err)
	}
	err = s.DB.Pre(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT auth_saml_request_open($1,$2,$3,$4,$5,NULLIF($6,''))`,
			req.ID, p.ID, safeRedirect(redirectAfter), s.now().Add(requestTTL), BindingDigest(binding), replaces)
		return err
	})
	if err != nil {
		return "", err
	}
	// RelayState is echoed back untouched by the identity provider and is
	// not authenticated, so nothing is carried in it: where to go next is
	// on the request row, found through the assertion's InResponseTo.
	u, err := req.Redirect("", sp)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// Consume accepts an assertion posted to the consumer endpoint. In
// order: find the sign-in it answers, verify the signature and the
// conditions, spend the assertion id so it can never be used again, and
// only then match it to an account.
func (s *Service) Consume(ctx context.Context, providerID, samlResponse, binding string) (*Result, error) {
	if samlResponse == "" {
		return nil, fmt.Errorf("%w: the response was empty", ErrAssertionInvalid)
	}
	p, err := s.load(ctx, providerID)
	if err != nil {
		return nil, err
	}
	if !p.Enabled {
		return nil, ErrDisabled
	}
	requestID, err := responseRequestID(samlResponse)
	if err != nil {
		return nil, err
	}
	redirectAfter, replaces, err := s.pendingRequest(ctx, p.ID, requestID, binding)
	if err != nil {
		return nil, err
	}
	m, err := s.materialFor(ctx, p)
	if err != nil {
		return nil, err
	}
	acs, meta, err := s.endpoints(p.ID)
	if err != nil {
		return nil, err
	}
	v, err := newVerifier(p, m.key, m.cert, acs, meta)
	if err != nil {
		return nil, err
	}
	claims, err := v.verify(samlResponse, requestID)
	if err != nil {
		return nil, err
	}
	// Spending the id comes after verification on purpose: an unverified
	// document must not be able to fill this table with ids of its
	// choosing, and so burn sign-ins that have not happened yet.
	if err := s.spend(ctx, p, claims); err != nil {
		return nil, err
	}
	if !domainAllowed(claims.Email, p.AllowedDomains) {
		return nil, ErrDomainRefused
	}
	res, err := s.link(ctx, p, claims)
	if err != nil {
		return nil, err
	}
	res.RedirectAfter = redirectAfter
	res.Replaces = replaces
	res.AuthnInstant = claims.AuthnInstant
	return res, nil
}

// pendingRequest finds the sign-in an assertion answers and returns where
// to send the browser afterwards, and the session it re-authenticates.
func (s *Service) pendingRequest(ctx context.Context, providerID, requestID, binding string) (string, string, error) {
	var redirectAfter, wantBinding string
	var replaces *string
	var expires time.Time
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT redirect_after, expires_at, binding, replaces_session FROM auth_saml_request_load($1,$2)`,
			requestID, providerID).Scan(&redirectAfter, &expires, &wantBinding, &replaces)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrRequestInvalid
	}
	if err != nil {
		return "", "", err
	}
	if s.now().After(expires) {
		return "", "", ErrRequestInvalid
	}
	// The assertion has to come back to the browser that asked for it.
	// An identity provider will happily issue one to anybody who asks, so
	// without this somebody signs in as themselves, posts the answer into
	// another person's browser, and that person is signed in as them.
	if wantBinding != "" && subtle.ConstantTimeCompare([]byte(wantBinding), []byte(BindingDigest(binding))) != 1 {
		return "", "", ErrRequestInvalid
	}
	if replaces == nil {
		return redirectAfter, "", nil
	}
	return redirectAfter, *replaces, nil
}

// BindingDigest is what the request row holds for a browser's cookie:
// the digest, not the value, so a reader of the table cannot forge the
// cookie that would let them finish somebody else's sign-in.
func BindingDigest(binding string) string {
	if binding == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(binding))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// spend records the assertion id, and refuses it if it was already there.
func (s *Service) spend(ctx context.Context, p *Provider, c *Claims) error {
	until := c.NotOnOrAfter
	if until.IsZero() {
		// An assertion with no expiry on its conditions is unusual but
		// legal. Keep the record for as long as the library would have
		// accepted the assertion, so the replay window is never shorter
		// than the acceptance window.
		until = s.now().Add(crewjam.MaxIssueDelay)
	}
	var first bool
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT auth_saml_assertion_use($1,$2,$3)`,
			p.ID, c.AssertionID, until).Scan(&first)
	})
	if err != nil {
		return err
	}
	if !first {
		return ErrReplayed
	}
	return nil
}

// link finds or creates the account behind the claims and syncs the roles
// the provider's groups map to.
func (s *Service) link(ctx context.Context, p *Provider, c *Claims) (*Result, error) {
	var userID *string
	err := s.DB.Pre(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT auth_saml_link($1,$2,$3,$4,$5,$6,$7)`,
			p.ID, p.OrgID, c.Subject, c.Email, c.Name, s.NewID(), p.JITProvisioning).Scan(&userID)
	})
	if err != nil {
		return nil, err
	}
	if userID == nil {
		return nil, ErrNoAccount
	}
	res := &Result{UserID: *userID, OrgID: p.OrgID, Email: c.Email, Name: c.Name, Groups: c.Groups,
		ProviderID: p.ID, ProviderName: p.Name, MultiFactor: c.MultiFactor}
	if err := s.syncRoles(ctx, p, *userID, c.Groups); err != nil {
		return nil, err
	}
	return res, nil
}

// syncRoles makes the user's provider-sourced bindings match the groups
// the assertion carried. Bindings an administrator made by hand are left
// alone: the provider owns what it granted and nothing else.
func (s *Service) syncRoles(ctx context.Context, p *Provider, userID string, groups []string) error {
	return s.DB.Tx(tenant.WithOrg(ctx, p.OrgID), func(tx pgx.Tx) error {
		want := map[string]bool{}
		if len(groups) > 0 {
			rows, err := tx.Query(ctx, `SELECT DISTINCT role_id FROM role_bindings
				WHERE organization_id = $1 AND principal_kind = 'idp_group' AND principal_id = ANY($2)`,
				p.OrgID, groups)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				want[id] = true
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		// A default role covers the case where no group maps to anything,
		// so a first sign-in is not an account that can do nothing.
		if len(want) == 0 && p.DefaultRoleID != "" {
			want[p.DefaultRoleID] = true
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_bindings
			WHERE organization_id = $1 AND principal_kind = 'user' AND principal_id = $2
			  AND source = 'saml' AND NOT (role_id = ANY($3))`, p.OrgID, userID, keys(want)); err != nil {
			return err
		}
		for roleID := range want {
			if _, err := tx.Exec(ctx, `INSERT INTO role_bindings
				(id, organization_id, principal_kind, principal_id, role_id, source, external_ref)
				VALUES ($1,$2,'user',$3,$4,'saml',$5)
				ON CONFLICT (organization_id, principal_kind, principal_id, role_id, scope_kind, scope_id, source)
				DO NOTHING`, s.NewID(), p.OrgID, userID, roleID, p.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// Sweep drops the sign-ins nobody finished and the spent assertion ids
// that are past the point where the validity check would refuse them
// anyway. It is the background job for this package.
func (s *Service) Sweep(ctx context.Context) error {
	return s.DB.Bypass(ctx, "saml-sweep", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM saml_requests WHERE expires_at < now()`); err != nil {
			return err
		}
		// The grace period is the clock skew the verifier allows, so a
		// record is never dropped while the assertion it names could
		// still be accepted.
		_, err := tx.Exec(ctx, `DELETE FROM saml_assertions WHERE not_on_or_after < now() - $1::interval`,
			crewjam.MaxClockSkew.String())
		return err
	})
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
