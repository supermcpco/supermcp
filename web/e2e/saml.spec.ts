import { test, expect } from "./fixtures";

// SAML without an identity provider. A real federation cannot be stood up
// in CI, so what is checked here is everything on our side of it: that a
// provider can be configured from a metadata document, that the three
// addresses an administrator has to copy are shown and really answer, and
// that the assertion consumer refuses what it should refuse.
//
// The whole file skips when this instance serves no SAML API. That is a
// real state of the product — an instance can be built and run without
// the SAML service — and not only a state of a half-finished branch.

// A metadata document from an identity provider that does not exist,
// carrying a real self-signed certificate. Nothing here is a secret: the
// private half was thrown away when this was generated.
const IDP_METADATA = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2040-01-01T00:00:00Z" cacheDuration="PT48H" entityID="https://e2e.idp.example/metadata"><IDPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">MIICzzCCAbegAwIBAgIBKjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9lMmUuaWRwLmV4YW1wbGUwHhcNMjAwMTAxMDAwMDAwWhcNNDAwMTAxMDAwMDAwWjAaMRgwFgYDVQQDEw9lMmUuaWRwLmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtSRpZf+wezpDPBAGrb97dL7CGtmQrIP1t5iSq0XT4s1tz4exkYlQduXiuCRhRENTtNETITXV1XdDhQNHP6x+MkBEIL5iiFb87VHFVcLi+V8QbAYcVdYZV5vp/MDUrtw6cQB8CNx2NKm0XC2/Qq6YKqmLiQyBWBkHPBxDp8aMBxBcPTQMeIwUwPc8NQeM391NTcs/WT+sNVgwdAADWGW1k48IVgwc4FS4alDtCZJos7sqBm+fLgxlXOp2DAlscBfutifx5BVMe1Hbc90ms6pLeGO2tvIV4jD06RKCxx3+PH8KQIyctxNJxy+W11KmiVVgDN23nsVSwtlRk9CMlWwrPAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXHrepDQKHgqGAC/F5FJ0A0/iRoaNffiqWeRyOXWV/wjttdVo6koupE3g87XkyxlKn5N7YcRWPxYv3nzjDinEI1yknU68qyU94L2q0/jkvnp4uk/j0qTUQYAd4qN9mH9THS+AJRXeDNgvJxPQ+hUx3+ZLQiaCh0Ng9V6YrKu1bqbEgoknOuJ+WSDdxXv4Ze/YitMIpyY8niIGa9g19lMPBsLbrbjUJQu/LfBPM/4Ap1mgb9Kiite+yKIiYVxLl7OF4L8iMwgmtjuM5/uQoFhPTwavsuCEpXrG9OxGD9oBdJzCbWjvob+DHD9wd60EXDRxbDP9AxBBDBMDMwhi1QAKC</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use="encryption"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Certificate xmlns="http://www.w3.org/2000/09/xmldsig#">MIICzzCCAbegAwIBAgIBKjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9lMmUuaWRwLmV4YW1wbGUwHhcNMjAwMTAxMDAwMDAwWhcNNDAwMTAxMDAwMDAwWjAaMRgwFgYDVQQDEw9lMmUuaWRwLmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtSRpZf+wezpDPBAGrb97dL7CGtmQrIP1t5iSq0XT4s1tz4exkYlQduXiuCRhRENTtNETITXV1XdDhQNHP6x+MkBEIL5iiFb87VHFVcLi+V8QbAYcVdYZV5vp/MDUrtw6cQB8CNx2NKm0XC2/Qq6YKqmLiQyBWBkHPBxDp8aMBxBcPTQMeIwUwPc8NQeM391NTcs/WT+sNVgwdAADWGW1k48IVgwc4FS4alDtCZJos7sqBm+fLgxlXOp2DAlscBfutifx5BVMe1Hbc90ms6pLeGO2tvIV4jD06RKCxx3+PH8KQIyctxNJxy+W11KmiVVgDN23nsVSwtlRk9CMlWwrPAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXHrepDQKHgqGAC/F5FJ0A0/iRoaNffiqWeRyOXWV/wjttdVo6koupE3g87XkyxlKn5N7YcRWPxYv3nzjDinEI1yknU68qyU94L2q0/jkvnp4uk/j0qTUQYAd4qN9mH9THS+AJRXeDNgvJxPQ+hUx3+ZLQiaCh0Ng9V6YrKu1bqbEgoknOuJ+WSDdxXv4Ze/YitMIpyY8niIGa9g19lMPBsLbrbjUJQu/LfBPM/4Ap1mgb9Kiite+yKIiYVxLl7OF4L8iMwgmtjuM5/uQoFhPTwavsuCEpXrG9OxGD9oBdJzCbWjvob+DHD9wd60EXDRxbDP9AxBBDBMDMwhi1QAKC</X509Certificate></X509Data></KeyInfo><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc"></EncryptionMethod><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"></EncryptionMethod><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"></EncryptionMethod></KeyDescriptor><NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://e2e.idp.example/sso"></SingleSignOnService><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://e2e.idp.example/sso"></SingleSignOnService></IDPSSODescriptor></EntityDescriptor>`;

const IDP_ENTITY_ID = "https://e2e.idp.example/metadata";

test.beforeEach(async ({ request }) => {
  const probe = await request.get("/api/v1/auth/saml-providers");
  test.skip(probe.status() === 404, "this instance serves no SAML API");
});

test("a SAML provider can be configured, and publishes what the identity provider needs", async ({
  page,
  request,
  workspace,
}) => {
  expect(workspace.org).toBeTruthy();
  await page.goto("/settings/sso");

  await page.getByRole("heading", { name: "SAML 2.0" }).scrollIntoViewIfNeeded();
  await page.getByPlaceholder("Company SAML").fill("End to end SAML");
  await page.getByPlaceholder("<EntityDescriptor").fill(IDP_METADATA);

  // Reading the metadata before saving is what turns a typo into a
  // message here rather than a failed sign-in next week.
  await page.getByRole("button", { name: "Test this metadata" }).click();
  // The pasted XML contains the entity id too, so the assertion names the
  // sentence the screen writes rather than the substring.
  await expect(page.getByText(`Found ${IDP_ENTITY_ID}`, { exact: false })).toBeVisible();

  await page.getByRole("button", { name: "Add SAML provider" }).click();
  await expect(page.getByText("End to end SAML")).toBeVisible();

  // The addresses on the screen are the ones the identity provider is
  // given, so they have to be the ones that actually answer.
  const list = await page.request.get("/api/v1/saml-providers");
  expect(list.status(), await list.text()).toBe(200);
  const provider = (await list.json()).providers[0];
  expect(provider.acsUrl).toContain(`/api/v1/auth/saml/${provider.id}/acs`);
  expect(provider.entityId).toBeTruthy();
  expect(provider.certificatePem).toContain("BEGIN CERTIFICATE");
  expect(
    JSON.stringify(provider),
    "a signing key that comes back out is a key anyone can forge our requests with",
  ).not.toContain("PRIVATE KEY");

  const metadata = await request.get(new URL(provider.spMetadataUrl).pathname);
  expect(metadata.status(), await metadata.text()).toBe(200);
  expect(metadata.headers()["content-type"]).toContain("samlmetadata+xml");
  const doc = await metadata.text();
  expect(doc).toContain(`entityID="${provider.entityId}"`);
  expect(doc).toContain(provider.acsUrl);
  expect(doc, "metadata without our certificate cannot be uploaded anywhere").toContain("X509Certificate");

  // Starting a sign-in sends the browser to the identity provider with a
  // request it can read, rather than failing somewhere on our side.
  const start = await request.get(new URL(provider.loginUrl).pathname, { maxRedirects: 0 });
  expect(start.status()).toBe(302);
  const target = new URL(start.headers()["location"]);
  expect(target.origin + target.pathname).toBe("https://e2e.idp.example/sso");
  expect(target.searchParams.get("SAMLRequest"), "no request means nothing for the provider to answer").toBeTruthy();
});

test("the assertion consumer refuses a response nobody signed", async ({ page, request, workspace }) => {
  expect(workspace.org).toBeTruthy();
  await page.goto("/settings/sso");
  const created = await page.request.post("/api/v1/saml-providers", {
    data: { name: "Refusal", metadataXml: IDP_METADATA, jitProvisioning: true, enabled: true },
  });
  expect(created.status(), await created.text()).toBe(201);
  const provider = await created.json();

  // The identity provider posts across origins, which is what a browser
  // labels every real assertion with. Anything that turns this into a
  // blocked request also blocks every genuine sign-in.
  const res = await request.post(new URL(provider.acsUrl).pathname, {
    maxRedirects: 0,
    headers: {
      Origin: "https://e2e.idp.example",
      "Sec-Fetch-Site": "cross-site",
      "Sec-Fetch-Mode": "navigate",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    // Base64 of "<not-a-saml-response/>": well formed enough to reach
    // the parser, signed by nobody.
    form: { SAMLResponse: "PG5vdC1hLXNhbWwtcmVzcG9uc2UvPg==" },
  });
  expect(
    res.status(),
    "a cross-site POST is what an assertion always is; blocking it blocks every sign-in",
  ).toBe(302);
  expect(res.headers()["location"]).toContain("/login?saml_error=");
  expect(res.headers()["set-cookie"] ?? "", "a refused assertion must not leave a session behind").not.toContain(
    "sm_sess",
  );
});
