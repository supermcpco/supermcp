package saml

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"testing"

	crewjam "github.com/crewjam/saml"
	"github.com/google/uuid"

	"github.com/supermcpco/supermcp/internal/governance"
)

// TestRestoreFromHistory: each change to a provider is a revision, and a
// restore puts the identity provider an earlier version trusted back from
// the history itself, leaving our key pair as it is, so a sign-in that
// version accepted is accepted again.
func TestRestoreFromHistory(t *testing.T) {
	f := newDBFixture(t)
	ctx := t.Context()
	history := governance.New(f.db, uuid.NewString)
	f.svc.Revisions = history
	id := f.provider.ID

	if _, _, err := f.svc.Update(ctx, f.orgID, id, "", Input{Name: "Version one", MetadataXML: f.idpMetadataXML(),
		JITProvisioning: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Point it at a different identity provider, then rotate our key.
	otherKey, otherCert := selfSigned(t, "https://other-idp.example")
	other := &crewjam.IdentityProvider{Key: otherKey, Certificate: otherCert, SignatureMethod: signatureMethod,
		MetadataURL: *mustURL(t, "https://other-idp.example/metadata"), SSOURL: *mustURL(t, "https://other-idp.example/sso")}
	otherXML, err := xml.Marshal(other.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Update(ctx, f.orgID, id, "", Input{Name: "Version two", MetadataXML: string(otherXML),
		JITProvisioning: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rotated, err := f.svc.Rotate(ctx, f.orgID, id, "")
	if err != nil {
		t.Fatal(err)
	}

	list, err := history.List(ctx, f.orgID, governance.KindSAMLProvider, id, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture made the provider before there was a history, so its
	// first change records it as it was first.
	if len(list) != 4 || list[3].Action != governance.ActionCreate || list[3].ActorID != "" {
		t.Fatalf("%d revisions after two edits and a rotation, want a baseline and three: %+v", len(list), list)
	}
	if d := list[1].Diff; d == nil || d.After["idpSsoUrl"] != "https://other-idp.example/sso" {
		t.Errorf("the second edit's diff does not show the new identity provider: %+v", d)
	}
	if d := list[0].Diff; d == nil || d.After["certificatePem"] != rotated.CertificatePEM {
		t.Errorf("the rotation's diff does not show the new certificate: %+v", d)
	}

	first, err := history.Get(ctx, f.orgID, governance.KindSAMLProvider, id, 2)
	if err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := json.Unmarshal(first.Snapshot, &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.IDPCertificates) == 0 {
		t.Fatal("the snapshot does not keep the identity provider's certificates")
	}
	// A version that names no signer would be put back broken.
	empty := snap
	empty.IDPCertificates = nil
	if _, _, err := f.svc.Restore(ctx, f.orgID, id, "", empty); !errors.Is(err, ErrMetadata) {
		t.Errorf("restoring a version with no identity provider certificate: %v, want ErrMetadata", err)
	}
	restored, replaced, err := f.svc.Restore(ctx, f.orgID, id, "", snap)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Name != "Version two" || replaced.IDPSSOURL != "https://other-idp.example/sso" {
		t.Errorf("the restore reports it replaced %q trusting %s", replaced.Name, replaced.IDPSSOURL)
	}
	if restored.Name != "Version one" || restored.IDPSSOURL != idpBase+"/sso" {
		t.Errorf("restored %q trusting %s", restored.Name, restored.IDPSSOURL)
	}
	if restored.CertificatePEM != rotated.CertificatePEM {
		t.Error("the restore replaced our signing certificate; it should leave the key pair alone")
	}
	if _, err := f.svc.Consume(ctx, id, f.signIn(nil), testBinding); err != nil {
		t.Errorf("a sign-in the restored version trusts is refused: %v", err)
	}
	list, err = history.List(ctx, f.orgID, governance.KindSAMLProvider, id, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 5 || list[0].Action != governance.ActionUpdate || list[0].Diff == nil ||
		list[0].Diff.After["name"] != "Version one" {
		t.Errorf("the restore is not recorded as a further change: %+v", list[0])
	}

	// A deleted provider keeps its history, but its key went with it.
	if err := f.svc.Delete(ctx, f.orgID, id, ""); err != nil {
		t.Fatal(err)
	}
	if list, err = history.List(ctx, f.orgID, governance.KindSAMLProvider, id, 0, 0); err != nil || list[0].Action != governance.ActionDelete {
		t.Fatalf("history after the delete: %v %+v", err, list)
	}
	if _, _, err := f.svc.Restore(ctx, f.orgID, id, "", snap); !errors.Is(err, ErrNotFound) {
		t.Errorf("restoring a deleted provider: %v, want not found", err)
	}
}
