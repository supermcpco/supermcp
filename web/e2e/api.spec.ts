import { test, expect } from "./fixtures";

// The API as a client meets it: the documents an MCP client fetches
// before it can connect, and the rules the endpoints enforce on their own.

test("the authorization server publishes what a client needs", async ({ request }) => {
  const metadata = await request.get("/.well-known/oauth-authorization-server");
  expect(metadata.ok()).toBeTruthy();
  const doc = await metadata.json();
  expect(doc.issuer).toBeTruthy();
  expect(doc.code_challenge_methods_supported).toContain("S256");
  expect(doc.grant_types_supported).toContain("client_credentials");
  expect(doc.jwks_uri).toBeTruthy();

  const jwks = await request.get("/.well-known/jwks.json");
  expect(jwks.ok()).toBeTruthy();
  const keys = await jwks.json();
  expect(keys.keys.length, "an authorization server with no published key cannot be verified by anyone").toBeGreaterThan(0);
  expect(JSON.stringify(keys)).not.toContain("\"d\":"); // never the private part
});

test("the MCP endpoint refuses an unauthenticated call and says how to authenticate", async ({ request }) => {
  const res = await request.post("/mcp/does-not-exist", {
    headers: { Accept: "application/json, text/event-stream" },
    data: { jsonrpc: "2.0", id: 1, method: "tools/list" },
  });
  expect(res.status()).toBe(401);
  const header = res.headers()["www-authenticate"] ?? "";
  expect(header, "a 401 without resource metadata leaves a client no way to recover").toContain("resource_metadata");
});

test("the catalog is public, and the admin API is not", async ({ request }) => {
  const catalog = await request.get("/api/v1/catalog?limit=1");
  expect(catalog.ok()).toBeTruthy();
  expect((await catalog.json()).count).toBeGreaterThan(200);

  const connectors = await request.get("/api/v1/connectors", { headers: { Cookie: "" } });
  expect([401, 403]).toContain(connectors.status());
});

test("health and readiness answer without a session", async ({ request }) => {
  expect((await request.get("/healthz")).ok()).toBeTruthy();
  expect((await request.get("/readyz")).ok()).toBeTruthy();
});

test("the audit trail can be shipped elsewhere and held against deletion", async ({ page, request, workspace }) => {
  // A signed-in page shares its cookies with the request context, which is
  // what makes these admin calls the same calls the UI would make.
  await page.goto("/settings/audit");
  const api = page.request;

  const created = await api.post("/api/v1/audit/exporters", {
    data: { url: "https://siem.example/ingest", secret: "a-secret-of-sufficient-length", enabled: true },
  });
  expect(created.status(), await created.text()).toBe(201);
  const exporter = await created.json();
  expect(exporter.id).toBeTruthy();
  expect(JSON.stringify(exporter), "a secret that comes back out is a secret anyone can forge deliveries with").not.toContain(
    "a-secret-of-sufficient-length",
  );

  const list = await api.get("/api/v1/audit/exporters");
  expect(list.ok()).toBeTruthy();
  const body = await list.json();
  expect(body.exporters.map((e: { url: string }) => e.url)).toContain("https://siem.example/ingest");
  expect(JSON.stringify(body)).not.toContain("a-secret-of-sufficient-length");

  // Configuring a destination is itself an administrative change, so it is
  // in the trail it was configuring. The writer batches, so this is polled
  // rather than read once; it also puts events in the window the hold
  // below has to cover.
  const actions = async () => {
    const events = await api.get("/api/v1/audit?category=admin&limit=50");
    return (await events.json()).events.map((e: { action: string }) => e.action);
  };
  await expect.poll(actions, { timeout: 10_000 }).toContain("audit.exporter.created");

  const held = await api.post("/api/v1/audit/legal-hold", {
    data: { from: "2000-01-01T00:00:00Z", reason: "a test" },
  });
  expect(held.ok(), await held.text()).toBeTruthy();
  expect((await held.json()).held, "a hold that covers nothing protects nothing").toBeGreaterThan(0);

  const released = await api.delete("/api/v1/audit/legal-hold", {
    data: { from: "2000-01-01T00:00:00Z", reason: "the test is over" },
  });
  expect(released.ok()).toBeTruthy();
  expect((await released.json()).held).toBeGreaterThan(0);

  expect((await api.delete(`/api/v1/audit/exporters/${exporter.id}`)).status()).toBe(204);
  expect((await api.delete(`/api/v1/audit/exporters/${exporter.id}`)).status()).toBe(404);

  await expect.poll(actions, { timeout: 10_000 }).toContain("audit.legal_hold.placed");
});
