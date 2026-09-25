package saml

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	crewjam "github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/supermcpco/supermcp/internal/secrets"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/tenant"
)

// Replay protection is a property of the statement that records an
// assertion id, not of anything in Go, so it is checked against a real
// database. The same fixture carries the rest of the round trip: a
// provider configured from metadata, a sign-in started, an assertion
// consumed, an account linked. Requires DATABASE_URL, and skips without
// it, like the rest.

type dbFixture struct {
	t        *testing.T
	db       *tenant.DB
	svc      *Service
	orgID    string
	provider *Provider
	idp      *crewjam.IdentityProvider
	email    string
}

func newDBFixture(t *testing.T) *dbFixture {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	maint, err := store.Open(ctx, dsn, dsn, log, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := maint.Migrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	maint.Close()

	st, err := store.Open(ctx, dsn, dsn, log, store.Options{AppRole: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := &tenant.DB{App: st.App, Maint: st.Maint, Log: log}

	// An organisation of its own per test, so tests can run together and
	// so dropping it at the end takes the providers with it.
	orgID := "saml_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if err := db.Bypass(ctx, "test seed", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (id, slug, name) VALUES ($1,$1,$1)`, orgID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	email := "amara-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12] + "@example.com"
	t.Cleanup(func() {
		_ = db.Bypass(context.Background(), "test cleanup", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(),
				`DELETE FROM organizations WHERE id = $1; DELETE FROM users WHERE email = $2`, orgID, email)
			return err
		})
	})

	kek, err := secrets.NewLocal(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "test")
	if err != nil {
		t.Fatal(err)
	}
	f := &dbFixture{t: t, db: db, orgID: orgID, email: email}
	f.svc = New(db, secrets.New(kek, &store.KeyStore{DB: db}), nil, uuid.NewString,
		mustURL(t, gatewayBase))

	// A working identity provider, described to us the way an
	// administrator would: by pasting its metadata.
	idpKey, idpCert := selfSigned(t, idpBase)
	f.idp = &crewjam.IdentityProvider{
		Key: idpKey, Certificate: idpCert, SignatureMethod: signatureMethod,
		MetadataURL: *mustURL(t, idpBase+"/metadata"), SSOURL: *mustURL(t, idpBase+"/sso"),
		ServiceProviderProvider: spProviderFunc(func(*http.Request, string) (*crewjam.EntityDescriptor, error) {
			doc, err := f.svc.Metadata(ctx, f.provider.ID)
			if err != nil {
				return nil, err
			}
			var md crewjam.EntityDescriptor
			if err := xml.Unmarshal(doc, &md); err != nil {
				return nil, err
			}
			return signingOnly(&md), nil
		}),
	}
	idpMetadata, err := xml.Marshal(f.idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	f.provider, err = f.svc.Create(ctx, orgID, "user_actor", Input{
		Name: "Test provider", MetadataXML: string(idpMetadata),
		JITProvisioning: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// testBinding stands in for the cookie a browser carries through a
// sign-in. The service only ever sees its digest.
const testBinding = "a-browser"

// signIn starts a sign-in and returns the assertion the identity
// provider would post back for it.
func (f *dbFixture) signIn(mutate func(*crewjam.Assertion)) string {
	f.t.Helper()
	return f.signInReplacing("", nil, mutate)
}

// signInReplacing starts a sign-in as a re-authentication of the session
// named by replaces, and reports whether the request asked the provider to
// authenticate the person again.
func (f *dbFixture) signInReplacing(replaces string, forced *bool, mutate func(*crewjam.Assertion)) string {
	f.t.Helper()
	ctx := f.t.Context()
	authnURL, err := f.svc.Begin(ctx, f.provider.ID, "/dashboard", testBinding, replaces)
	if err != nil {
		f.t.Fatal(err)
	}
	req, err := crewjam.NewIdpAuthnRequest(f.idp, httptest.NewRequest(http.MethodGet, authnURL, nil))
	if err != nil {
		f.t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		f.t.Fatal(err)
	}
	if forced != nil {
		*forced = req.Request.ForceAuthn != nil && *req.Request.ForceAuthn
	}
	now := time.Now()
	acs := f.svc.ACSURL(f.provider.ID)
	a := &crewjam.Assertion{
		ID:           "id-" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		IssueInstant: now,
		Version:      "2.0",
		Issuer: crewjam.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value: f.provider.IDPEntityID},
		Subject: &crewjam.Subject{
			NameID: &crewjam.NameID{Format: string(crewjam.EmailAddressNameIDFormat), Value: f.email},
			SubjectConfirmations: []crewjam.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &crewjam.SubjectConfirmationData{
					InResponseTo: req.Request.ID, NotOnOrAfter: now.Add(time.Hour), Recipient: acs,
				},
			}},
		},
		Conditions: &crewjam.Conditions{
			NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Hour),
			AudienceRestrictions: []crewjam.AudienceRestriction{
				{Audience: crewjam.Audience{Value: f.provider.EntityID}},
			},
		},
		AuthnStatements: []crewjam.AuthnStatement{{
			AuthnInstant: now, SessionIndex: "session-1",
			AuthnContext: crewjam.AuthnContext{AuthnContextClassRef: &crewjam.AuthnContextClassRef{
				Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication"}},
		}},
		AttributeStatements: []crewjam.AttributeStatement{{Attributes: []crewjam.Attribute{
			attribute("email", f.email),
			attribute("displayName", "Amara Okafor"),
		}}},
	}
	if mutate != nil {
		mutate(a)
	}
	req.Assertion = a
	if err := req.MakeResponse(); err != nil {
		f.t.Fatal(err)
	}
	form, err := req.PostBinding()
	if err != nil {
		f.t.Fatal(err)
	}
	return form.SAMLResponse
}

// TestConsumeReportsReauthentication checks what the web layer judges a
// re-authentication by: the session it replaces comes back from the
// request row, the provider was asked to authenticate afresh, and the
// assertion's AuthnInstant is reported rather than the time it arrived.
func TestConsumeReportsReauthentication(t *testing.T) {
	f := newDBFixture(t)
	var forced bool
	earlier := time.Now().Add(-time.Hour).Truncate(time.Second)
	doc := f.signInReplacing("the-old-session", &forced, func(a *crewjam.Assertion) {
		a.AuthnStatements[0].AuthnInstant = earlier
	})
	if !forced {
		t.Error("a re-authentication did not set ForceAuthn")
	}
	res, err := f.svc.Consume(t.Context(), f.provider.ID, doc, testBinding)
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaces != "the-old-session" {
		t.Errorf("replaces = %q, want the session named when the sign-in began", res.Replaces)
	}
	if res.AuthnInstant == nil || !res.AuthnInstant.Equal(earlier) {
		t.Errorf("AuthnInstant = %v, want %v", res.AuthnInstant, earlier)
	}

	var plain bool
	res, err = f.svc.Consume(t.Context(), f.provider.ID, f.signInReplacing("", &plain, nil), testBinding)
	if err != nil {
		t.Fatal(err)
	}
	if plain || res.Replaces != "" {
		t.Errorf("an ordinary sign-in: ForceAuthn %v, replaces %q", plain, res.Replaces)
	}
}

func TestConsumeLinksAnAccount(t *testing.T) {
	f := newDBFixture(t)
	res, err := f.svc.Consume(t.Context(), f.provider.ID, f.signIn(nil), testBinding)
	if err != nil {
		t.Fatalf("a correct assertion was refused: %v", err)
	}
	if res.OrgID != f.orgID {
		t.Errorf("organisation = %q, want %q", res.OrgID, f.orgID)
	}
	if res.Email != f.email {
		t.Errorf("email = %q, want %q", res.Email, f.email)
	}
	if res.Name != "Amara Okafor" {
		t.Errorf("name = %q", res.Name)
	}
	if !res.MultiFactor {
		t.Error("the assertion stated multi-factor authentication and the result does not")
	}
	if res.RedirectAfter != "/dashboard" {
		t.Errorf("redirect = %q, want the page the sign-in started from", res.RedirectAfter)
	}
	if res.UserID == "" {
		t.Fatal("no user was linked")
	}

	// Signing in again reaches the same account rather than making a
	// second one, and the identity row records the visit.
	again, err := f.svc.Consume(t.Context(), f.provider.ID, f.signIn(nil), testBinding)
	if err != nil {
		t.Fatal(err)
	}
	if again.UserID != res.UserID {
		t.Errorf("a second sign-in made a second account: %q then %q", res.UserID, again.UserID)
	}
}

// TestReplayedAssertionIsRefused is the case the table exists for: the
// very same signed document, posted twice.
func TestReplayedAssertionIsRefused(t *testing.T) {
	f := newDBFixture(t)
	doc := f.signIn(nil)
	if _, err := f.svc.Consume(t.Context(), f.provider.ID, doc, testBinding); err != nil {
		t.Fatalf("the first use was refused: %v", err)
	}
	_, err := f.svc.Consume(t.Context(), f.provider.ID, doc, testBinding)
	if !errors.Is(err, ErrReplayed) {
		t.Fatalf("the second use gave %v, want it to be refused as already used", err)
	}
}

// TestUnverifiedAssertionSpendsNothing: a document that fails
// verification must not consume the id it names, or anyone able to post
// to the consumer endpoint could burn sign-ins that have not happened.
func TestUnverifiedAssertionSpendsNothing(t *testing.T) {
	f := newDBFixture(t)
	var spent string
	good := f.signIn(func(a *crewjam.Assertion) { spent = a.ID })
	tampered := edit(t, good, func(d string) string {
		return strings.Replace(d, "Amara Okafor", "Someone Else", 1)
	})
	if _, err := f.svc.Consume(t.Context(), f.provider.ID, tampered, testBinding); !errors.Is(err, ErrAssertionInvalid) {
		t.Fatalf("a tampered assertion gave %v", err)
	}
	if n := f.countAssertions(spent); n != 0 {
		t.Errorf("a refused assertion left %d replay records behind", n)
	}
	// ...and the genuine one still works afterwards.
	if _, err := f.svc.Consume(t.Context(), f.provider.ID, good, testBinding); err != nil {
		t.Errorf("the genuine assertion was refused after a tampered one: %v", err)
	}
}

// TestJITProvisioningOff: with account creation off, an unknown person is
// told to ask for an invitation rather than quietly given an account.
func TestJITProvisioningOff(t *testing.T) {
	f := newDBFixture(t)
	if _, err := f.svc.Update(t.Context(), f.orgID, f.provider.ID, "", Input{
		Name: "Test provider", MetadataXML: f.idpMetadataXML(), JITProvisioning: false, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Consume(t.Context(), f.provider.ID, f.signIn(nil), testBinding)
	if !errors.Is(err, ErrNoAccount) {
		t.Fatalf("got %v, want it to say there is no account", err)
	}
}

// TestAllowedDomains keeps a federation from admitting whoever the
// identity provider happens to trust.
func TestAllowedDomains(t *testing.T) {
	f := newDBFixture(t)
	if _, err := f.svc.Update(t.Context(), f.orgID, f.provider.ID, "", Input{
		Name: "Test provider", MetadataXML: f.idpMetadataXML(),
		AllowedDomains: []string{"corp.example"}, JITProvisioning: true, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Consume(t.Context(), f.provider.ID, f.signIn(nil), testBinding)
	if !errors.Is(err, ErrDomainRefused) {
		t.Fatalf("got %v, want the email domain to be refused", err)
	}
}

// TestSweepKeepsRecordsWhileTheyMatter: a replay record dropped too early
// would reopen the window it exists to close.
func TestSweepKeepsRecordsWhileTheyMatter(t *testing.T) {
	f := newDBFixture(t)
	doc := f.signIn(nil)
	if _, err := f.svc.Consume(t.Context(), f.provider.ID, doc, testBinding); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Consume(t.Context(), f.provider.ID, doc, testBinding); !errors.Is(err, ErrReplayed) {
		t.Fatalf("after a sweep the replay gave %v, want it still refused", err)
	}
	// Once the assertion could no longer be accepted anyway, the record
	// has done its job and goes.
	f.ageAssertions()
	if err := f.svc.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.countAssertions(""); n != 0 {
		t.Errorf("%d spent assertions survived a sweep long after their expiry", n)
	}
}

// TestMetadataCarriesOurCertificate: the document an administrator
// uploads has to name us and carry the key we sign with, or the
// federation cannot be set up at all.
func TestMetadataCarriesOurCertificate(t *testing.T) {
	f := newDBFixture(t)
	doc, err := f.svc.Metadata(t.Context(), f.provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	var md crewjam.EntityDescriptor
	if err := xml.Unmarshal(doc, &md); err != nil {
		t.Fatalf("our own metadata does not parse: %v", err)
	}
	if md.EntityID != f.provider.EntityID {
		t.Errorf("entity id = %q, want %q", md.EntityID, f.provider.EntityID)
	}
	if len(md.SPSSODescriptors) != 1 {
		t.Fatalf("%d service provider descriptors", len(md.SPSSODescriptors))
	}
	acs := md.SPSSODescriptors[0].AssertionConsumerServices
	if len(acs) == 0 || acs[0].Location != f.svc.ACSURL(f.provider.ID) {
		t.Errorf("consumer service = %+v, want %s", acs, f.svc.ACSURL(f.provider.ID))
	}
	var found bool
	for _, kd := range md.SPSSODescriptors[0].KeyDescriptors {
		for _, c := range kd.KeyInfo.X509Data.X509Certificates {
			if strings.Contains(f.provider.CertificatePEM, strings.TrimSpace(c.Data)[:40]) {
				found = true
			}
		}
	}
	if !found {
		t.Error("the metadata does not carry the certificate the provider row holds")
	}
}

// TestRotateKeepsTheProviderWorking: rotation replaces the key pair and
// nothing else, so the federation still points at the same places.
func TestRotateKeepsTheProviderWorking(t *testing.T) {
	f := newDBFixture(t)
	before := f.provider.CertificatePEM
	after, err := f.svc.Rotate(t.Context(), f.orgID, f.provider.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if after.CertificatePEM == before || after.CertificatePEM == "" {
		t.Error("rotation did not produce a new certificate")
	}
	if after.EntityID != f.provider.EntityID || after.IDPSSOURL != f.provider.IDPSSOURL {
		t.Error("rotation changed something other than the key pair")
	}
	if _, err := f.svc.Metadata(t.Context(), f.provider.ID); err != nil {
		t.Errorf("metadata broke after rotation: %v", err)
	}
}

// --- fixture helpers -------------------------------------------------------

func (f *dbFixture) idpMetadataXML() string {
	f.t.Helper()
	raw, err := xml.Marshal(f.idp.Metadata())
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

func (f *dbFixture) countAssertions(id string) int {
	f.t.Helper()
	var n int
	err := f.db.Bypass(f.t.Context(), "test: count spent assertions", func(tx pgx.Tx) error {
		if id == "" {
			return tx.QueryRow(f.t.Context(),
				`SELECT count(*) FROM saml_assertions WHERE provider_id = $1`, f.provider.ID).Scan(&n)
		}
		return tx.QueryRow(f.t.Context(),
			`SELECT count(*) FROM saml_assertions WHERE provider_id = $1 AND assertion_id = $2`,
			f.provider.ID, id).Scan(&n)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// ageAssertions pushes the records past the point where the assertions
// they name could still be accepted, which is the only honest way to test
// the sweep without waiting an hour.
func (f *dbFixture) ageAssertions() {
	f.t.Helper()
	err := f.db.Bypass(f.t.Context(), "test: age spent assertions", func(tx pgx.Tx) error {
		_, err := tx.Exec(f.t.Context(),
			`UPDATE saml_assertions SET not_on_or_after = now() - interval '1 day' WHERE provider_id = $1`,
			f.provider.ID)
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

// An identity provider issues an assertion to whoever asks. Without the
// browser binding, somebody signs in as themselves, posts the answer into
// another person's browser, and that person is signed in as them — and
// everything they do next lands in the attacker's account.
func TestAnAssertionOnlyFinishesTheSignInThatStartedIt(t *testing.T) {
	f := newDBFixture(t)
	doc := f.signIn(nil)

	if _, err := f.svc.Consume(t.Context(), f.provider.ID, doc, "another-browser"); !errors.Is(err, ErrRequestInvalid) {
		t.Fatalf("an assertion was accepted in a browser that did not start the sign-in: %v", err)
	}
	// And the genuine browser can still finish: a refused attempt must not
	// spend the sign-in.
	if _, err := f.svc.Consume(t.Context(), f.provider.ID, doc, testBinding); err != nil {
		t.Fatalf("the browser that started the sign-in could not finish it: %v", err)
	}
}

func TestBindingDigestHidesTheCookie(t *testing.T) {
	if BindingDigest("") != "" {
		t.Error("an absent binding should digest to nothing, so an old row stays readable")
	}
	d := BindingDigest("a-browser")
	if d == "a-browser" || len(d) < 40 {
		t.Errorf("the digest looks like the value it should hide: %q", d)
	}
	if d != BindingDigest("a-browser") {
		t.Error("the digest is not stable")
	}
}
