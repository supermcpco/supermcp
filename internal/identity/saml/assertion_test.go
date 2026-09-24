package saml

import (
	"errors"
	"strings"
	"testing"
	"time"

	crewjam "github.com/crewjam/saml"
)

// TestVerifyRefuses is the whole point of the package: an assertion is a
// bearer token, so every way of presenting one that should not work has
// to be shown not to work. Each case starts from an assertion that does
// work and changes one thing.
func TestVerifyRefuses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// assertion changes what the identity provider signs.
		assertion func(h *harness, a *crewjam.Assertion)
		// document changes the signed bytes afterwards.
		document func(string) string
		// requestID overrides which sign-in we believe is in flight.
		requestID string
		want      string
	}{
		{
			name:     "a tampered assertion is refused",
			document: func(d string) string { return strings.ReplaceAll(d, "amara@", "attacker@") },
			want:     "cannot validate signature",
		},
		{
			name: "an assertion with no signature at all is refused",
			// Removing the signature leaves a document that claims
			// everything the real one claimed and proves none of it.
			document: stripSignatures,
			want:     "signature",
		},
		{
			name: "an expired assertion is refused",
			assertion: func(h *harness, a *crewjam.Assertion) {
				old := time.Now().Add(-24 * time.Hour)
				a.IssueInstant = old
				a.Conditions.NotBefore = old.Add(-time.Minute)
				a.Conditions.NotOnOrAfter = old.Add(time.Hour)
				a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = old.Add(time.Hour)
			},
			want: "expired",
		},
		{
			name: "an assertion that is not yet valid is refused",
			assertion: func(h *harness, a *crewjam.Assertion) {
				a.Conditions.NotBefore = time.Now().Add(24 * time.Hour)
				a.Conditions.NotOnOrAfter = time.Now().Add(48 * time.Hour)
			},
			want: "not yet valid",
		},
		{
			name: "an assertion for another audience is refused",
			assertion: func(h *harness, a *crewjam.Assertion) {
				a.Conditions.AudienceRestrictions = []crewjam.AudienceRestriction{
					{Audience: crewjam.Audience{Value: "https://someone-else.example/metadata"}},
				}
			},
			want: "AudienceRestriction",
		},
		{
			name: "an assertion answering a different sign-in is refused",
			assertion: func(h *harness, a *crewjam.Assertion) {
				a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "id-somebody-elses"
			},
			want: "request ID",
		},
		{
			name:      "an assertion is refused when we are not expecting that request",
			requestID: "id-not-in-flight",
			want:      "InResponseTo",
		},
		{
			name: "an assertion posted to another consumer is refused",
			assertion: func(h *harness, a *crewjam.Assertion) {
				a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient =
					"https://elsewhere.example/acs"
			},
			want: "Recipient",
		},
		{
			name: "an assertion with no email address anywhere is refused",
			assertion: func(h *harness, a *crewjam.Assertion) {
				a.AttributeStatements = nil
				a.Subject.NameID.Format = string(crewjam.PersistentNameIDFormat)
				a.Subject.NameID.Value = "8f14e45fceea167a"
			},
			want: "email address",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			a := h.assertion(time.Now())
			if tc.assertion != nil {
				tc.assertion(h, a)
			}
			doc := h.respond(a)
			if tc.document != nil {
				doc = edit(t, doc, tc.document)
			}
			requestID := h.requestID
			if tc.requestID != "" {
				requestID = tc.requestID
			}
			claims, err := h.verifier.verify(doc, requestID)
			if err == nil {
				t.Fatalf("the assertion was accepted, and returned %+v", claims)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason\n got: %v\nwant it to mention: %s", err, tc.want)
			}
		})
	}
}

// TestVerifyAccepts checks the other half: the assertion a correctly
// configured provider sends is accepted, and says what we think it says.
func TestVerifyAccepts(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	claims, err := h.verifier.verify(h.respond(h.assertion(time.Now())), h.requestID)
	if err != nil {
		t.Fatalf("a correct assertion was refused: %v", err)
	}
	if claims.Email != "amara@example.com" {
		t.Errorf("email = %q", claims.Email)
	}
	if claims.Name != "Amara Okafor" {
		t.Errorf("name = %q", claims.Name)
	}
	if claims.Subject != "amara@example.com" {
		t.Errorf("subject = %q", claims.Subject)
	}
	if got := strings.Join(claims.Groups, ","); got != "platform-engineering,on-call" {
		t.Errorf("groups = %q", got)
	}
	if claims.AssertionID == "" {
		t.Error("no assertion id, so the assertion could not be spent once")
	}
	if claims.NotOnOrAfter.IsZero() {
		t.Error("no expiry recorded, so replay protection would have no window")
	}
	if claims.MultiFactor {
		t.Error("a password-protected transport was read as a second factor")
	}
}

// TestMultiFactorIsOnlyWhatTheAssertionSaid covers the one claim that
// changes what a policy will allow: we issue no second factor ourselves,
// so this flag may only ever repeat what the provider stated.
func TestMultiFactorIsOnlyWhatTheAssertionSaid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		apply func(a *crewjam.Assertion)
		want  bool
	}{
		{
			name:  "a password alone is not a second factor",
			apply: func(*crewjam.Assertion) {},
			want:  false,
		},
		{
			name: "the multi-factor authentication context is",
			apply: func(a *crewjam.Assertion) {
				a.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value =
					"urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication"
			},
			want: true,
		},
		{
			name: "so is the Entra ID spelling of it",
			apply: func(a *crewjam.Assertion) {
				a.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value =
					"http://schemas.microsoft.com/claims/multipleauthn"
			},
			want: true,
		},
		{
			name: "an amr claim naming mfa is",
			apply: func(a *crewjam.Assertion) {
				a.AttributeStatements[0].Attributes = append(a.AttributeStatements[0].Attributes,
					attribute("http://schemas.microsoft.com/claims/authnmethodsreferences", "pwd", "mfa"))
			},
			want: true,
		},
		{
			name: "an amr claim naming only a password is not",
			apply: func(a *crewjam.Assertion) {
				a.AttributeStatements[0].Attributes = append(a.AttributeStatements[0].Attributes,
					attribute("amr", "pwd"))
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			a := h.assertion(time.Now())
			tc.apply(a)
			claims, err := h.verifier.verify(h.respond(a), h.requestID)
			if err != nil {
				t.Fatal(err)
			}
			if claims.MultiFactor != tc.want {
				t.Errorf("MultiFactor = %v, want %v", claims.MultiFactor, tc.want)
			}
		})
	}
}

// TestAttributeMapping covers the names identity providers actually use
// and the one an administrator can override them with.
func TestAttributeMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		configured attributeMapping
		attrs      []crewjam.Attribute
		nameID     string
		nameFormat string
		wantEmail  string
		wantName   string
		wantGroups string
	}{
		{
			name:       "the bare names Okta and Google send",
			attrs:      []crewjam.Attribute{attribute("email", "ines@example.com"), attribute("displayName", "Ines Vega")},
			wantEmail:  "ines@example.com",
			wantName:   "Ines Vega",
			wantGroups: "",
		},
		{
			name: "a friendly name matches too",
			attrs: []crewjam.Attribute{
				{Name: "urn:oid:0.9.2342.19200300.100.1.3", FriendlyName: "mail",
					Values: []crewjam.AttributeValue{{Value: "ines@example.com"}}},
			},
			wantEmail: "ines@example.com",
		},
		{
			name:       "an email NameID stands in for a missing attribute",
			attrs:      nil,
			nameID:     "ines@example.com",
			nameFormat: string(crewjam.EmailAddressNameIDFormat),
			wantEmail:  "ines@example.com",
		},
		{
			name:       "a configured attribute is used on its own",
			configured: attributeMapping{email: "corporate_mail", groups: "team"},
			attrs: []crewjam.Attribute{
				attribute("corporate_mail", "ines@example.com"),
				attribute("email", "personal@example.net"),
				attribute("team", "payments"),
				attribute("groups", "everyone"),
			},
			wantEmail:  "ines@example.com",
			wantGroups: "payments",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.verifier.mapping = tc.configured
			a := h.assertion(time.Now())
			a.AttributeStatements = []crewjam.AttributeStatement{{Attributes: tc.attrs}}
			if tc.nameID != "" {
				a.Subject.NameID.Value, a.Subject.NameID.Format = tc.nameID, tc.nameFormat
			}
			claims, err := h.verifier.verify(h.respond(a), h.requestID)
			if err != nil {
				t.Fatal(err)
			}
			if claims.Email != tc.wantEmail {
				t.Errorf("email = %q, want %q", claims.Email, tc.wantEmail)
			}
			if tc.wantName != "" && claims.Name != tc.wantName {
				t.Errorf("name = %q, want %q", claims.Name, tc.wantName)
			}
			if got := strings.Join(claims.Groups, ","); got != tc.wantGroups {
				t.Errorf("groups = %q, want %q", got, tc.wantGroups)
			}
		})
	}
}

// TestResponseRequestID covers the lookup that happens before anything is
// verified. It decides only which sign-in to compare against, but a
// response that names none at all has nowhere to go.
func TestResponseRequestID(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	doc := h.respond(h.assertion(time.Now()))
	got, err := responseRequestID(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got != h.requestID {
		t.Errorf("InResponseTo = %q, want %q", got, h.requestID)
	}

	// An unsolicited assertion is refused rather than guessed at.
	unsolicited := edit(t, doc, func(d string) string {
		return strings.Replace(d, ` InResponseTo="`+h.requestID+`"`, "", 1)
	})
	if _, err := responseRequestID(unsolicited); !errors.Is(err, ErrAssertionInvalid) {
		t.Errorf("an unsolicited response gave %v", err)
	}
}

// TestVerifierNeedsACertificate: a provider with no identity provider
// certificate can never verify anything, and should say so at the point
// where it is configured rather than fail obscurely at sign-in.
func TestVerifierNeedsACertificate(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	bare := *h.provider
	bare.IDPCertificates = nil
	_, err := newVerifier(&bare, nil, nil, *mustURL(t, h.acsURL), *mustURL(t, h.provider.EntityID))
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("got %v, want it to report an unfinished setup", err)
	}
}
