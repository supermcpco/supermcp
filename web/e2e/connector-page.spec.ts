import { test, expect, expectAccessible, createKey, createServer } from "./fixtures";
import type { Page } from "@playwright/test";

// A connector's own page: what it is, whether it can be called, the values
// it signs in with, and the way to remove it. Everything here is reached
// the way a person reaches it, from the catalog or the connectors list.

const bundesbank = "Deutsche Bundesbank Statistics";

/** Installs the keyless Bundesbank adapter and returns the new connector's id. */
async function installBundesbank(page: Page): Promise<string> {
  await page.goto("/catalog/bundesbank");
  const installed = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/connectors/install") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Install" }).click();
  const res = await installed;
  expect(res.status()).toBe(200);
  return ((await res.json()) as { id: string }).id;
}

// A document whose one credential the importer leaves for later: nothing
// is typed into it on the import screen, so the connector is made without
// it and says so.
const openapiDoc = JSON.stringify({
  openapi: "3.1.0",
  info: { title: "Allotment Register", version: "1.0.0" },
  servers: [{ url: "https://allotments.example.test/api" }],
  security: [{ apiKey: [] }],
  components: { securitySchemes: { apiKey: { type: "apiKey", in: "header", name: "X-Allotment-Key" } } },
  paths: {
    "/plots": {
      get: { operationId: "listPlots", summary: "List the plots on the site", responses: { "200": { description: "The plots" } } },
    },
  },
});

test("installing an adapter lands on its connector page", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const id = await installBundesbank(page);

  await expect(page).toHaveURL(new RegExp(`/connectors/${id}$`));
  await expect(page.getByText(`${bundesbank} installed`, { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: bundesbank, level: 1 })).toBeVisible();
  await expect(page.getByRole("link", { name: "bundesbank", exact: true })).toBeVisible();

  const status = page.getByRole("region", { name: "Status" });
  await expect(status.getByText("None needed.")).toBeVisible();
  await expect(status.getByText(/^http · /)).toBeVisible();
  await expect(status.getByText("None yet.")).toBeVisible();

  const tabs = page.getByRole("tablist", { name: "Connector" });
  await expect(tabs.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await expectAccessible(page);

  await tabs.getByRole("tab", { name: "Tools" }).click();
  await expect(page).toHaveURL(new RegExp(`/connectors/${id}/tools$`));
  await expect(tabs.getByRole("tab", { name: "Tools" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Tools", level: 2 })).toBeVisible();
  await expect(page.getByText("bundesbank_get_exchange_rates", { exact: true }).first()).toBeVisible();

  await tabs.getByRole("tab", { name: "History" }).click();
  await expect(page).toHaveURL(new RegExp(`/connectors/${id}/history$`));
  await expect(page.getByRole("heading", { name: "History", level: 2 })).toBeVisible();
  // The connector's name stays above every tab.
  await expect(page.getByRole("heading", { name: bundesbank, level: 1 })).toBeVisible();

  // And the list leads back to the same page.
  await page.getByRole("link", { name: "Connectors", exact: true }).first().click();
  await page.getByRole("link", { name: bundesbank, exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/connectors/${id}$`));
});

test("a connector can be switched off and on from its page", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await installBundesbank(page);
  const enabled = page.getByRole("switch", { name: "Enabled" });
  await expect(enabled).toBeChecked();

  const off = page.waitForResponse((r) => r.request().method() === "PATCH" && r.url().includes("/api/v1/connectors/"));
  await enabled.click();
  expect((await off).status()).toBe(200);
  await expect(page.getByText(`${bundesbank} disabled`, { exact: true })).toBeVisible();
  await expect(enabled).not.toBeChecked();
  await expect(page.getByText("disabled", { exact: true })).toBeVisible();

  const on = page.waitForResponse((r) => r.request().method() === "PATCH" && r.url().includes("/api/v1/connectors/"));
  await enabled.click();
  expect((await on).status()).toBe(200);
  await expect(enabled).toBeChecked();
  await expect(page.getByText("disabled", { exact: true })).toHaveCount(0);
});

test("a connector's credentials can be set from its page and the still-needed line clears", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/connectors/import");
  await page.getByRole("radio", { name: "OpenAPI", exact: true }).check();
  await page.getByLabel("OpenAPI document").fill(openapiDoc);
  await page.getByLabel("Connector name").fill("Allotments");
  await page.getByLabel("Tool name prefix").fill("allotments");
  await page.getByRole("button", { name: "Preview import" }).click();
  await expect(page.getByRole("region", { name: "What this would create" })).toBeVisible();
  // The credential is left empty on purpose.
  await page.getByRole("button", { name: "Import connector" }).click();
  // An import lands on the new connector's page, as an install does.
  await expect(page).toHaveURL(/\/connectors\/[^/]+$/);
  await expect(page.getByRole("heading", { name: "Allotments imported", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Allotments", level: 1 })).toBeVisible();
  await expect(page.getByText("Imported", { exact: true })).toBeVisible();
  const status = page.getByRole("region", { name: "Status" });
  await expect(status.getByText("Still needed: API_KEY.")).toBeVisible();
  // The address it reaches, and nothing more of it.
  await expect(status.getByText("http · allotments.example.test")).toBeVisible();

  const credentials = page.getByRole("region", { name: "Credentials" });
  await expect(credentials.getByText("Still needed: API_KEY.")).toBeVisible();
  await expectAccessible(page);

  await credentials.getByLabel("API_KEY").fill("not-a-real-key"); // gitleaks:allow
  const saved = page.waitForResponse(
    (r) => r.url().endsWith("/credentials") && r.request().method() === "PUT",
  );
  await credentials.getByRole("button", { name: "Save credentials" }).click();
  expect((await saved).status()).toBe(200);

  await expect(page.getByText("Credentials saved for Allotments", { exact: true })).toBeVisible();
  await expect(page.getByText(/Still needed/)).toHaveCount(0);
  await expect(status.getByText("All set: API_KEY.")).toBeVisible();
  // The value is gone from the form once it is stored, and never shown again.
  await expect(credentials.getByLabel("API_KEY")).toHaveValue("");
  await expect(credentials.getByText("(set; type to replace it)")).toBeVisible();

  await page.getByRole("link", { name: "Connectors", exact: true }).first().click();
  await expect(page.getByText("credentials missing")).toHaveCount(0);
});

test("removing a connector asks first and returns to the list", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const id = await installBundesbank(page);
  await expect(page).toHaveURL(new RegExp(`/connectors/${id}$`));

  const danger = page.getByRole("region", { name: "Danger zone" });
  await danger.getByRole("button", { name: "Remove" }).click();
  const dialog = page.getByRole("dialog", { name: `Delete ${bundesbank}` });
  await expect(dialog).toBeVisible();
  const confirm = dialog.getByRole("button", { name: "Remove connector" });
  await expect(confirm).toBeDisabled();

  // Changing one's mind removes nothing.
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
  expect((await page.request.get(`/api/v1/connectors/${id}`)).status()).toBe(200);

  await danger.getByRole("button", { name: "Remove" }).click();
  await dialog.getByRole("textbox", { name: `Type ${bundesbank} to confirm deletion` }).fill(bundesbank);
  const removed = page.waitForResponse(
    (r) => r.url().endsWith(`/api/v1/connectors/${id}`) && r.request().method() === "DELETE",
  );
  await confirm.click();
  expect((await removed).status()).toBe(204);

  await expect(page).toHaveURL(/\/connectors$/);
  await expect(page.getByText(`${bundesbank} removed`, { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No connectors yet" })).toBeVisible();
  expect((await page.request.get(`/api/v1/connectors/${id}`)).status()).toBe(404);

  // Its old address says it is gone rather than waiting for it.
  await page.goto(`/connectors/${id}`);
  await expect(page.getByRole("heading", { name: "Connector not found" })).toBeVisible();
  await page.getByRole("link", { name: "Back to connectors" }).click();
  await expect(page.getByRole("heading", { name: "Connectors", level: 1 })).toBeVisible();
});

test("an OAuth connector is authorized from its page", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/catalog/datev-sandbox");
  await page.getByLabel("DATEV_CLIENT_ID").fill("browser-test-client");
  await page.getByLabel("DATEV_CLIENT_SECRET").fill("not-a-real-secret"); // gitleaks:allow
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors\/[^/]+$/);

  const credentials = page.getByRole("region", { name: "Credentials" });
  await expect(credentials.getByText(/Register this redirect address with the vendor/)).toBeVisible();
  await expect(credentials.getByText("/auth/connectors/callback", { exact: false })).toBeVisible();

  // The vendor's consent screen is another site; the test stands in for
  // it rather than reaching out to it, and only checks it was asked.
  await page.route("https://login.datev.de/**", (route) =>
    route.fulfill({ contentType: "text/html", body: "<title>Consent</title><h1>Vendor consent</h1>" }),
  );
  const started = page.waitForResponse(
    (r) => r.url().endsWith("/oauth/authorize") && r.request().method() === "POST",
  );
  await credentials.getByRole("button", { name: "Authorize" }).click();
  expect((await started).status()).toBe(200);
  await expect(page).toHaveURL(/^https:\/\/login\.datev\.de\/openidsandbox\/authorize\?/);
  expect(new URL(page.url()).searchParams.get("client_id")).toBe("browser-test-client");
});

test("the return from a vendor's consent screen is told on the connector's page", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const id = await installBundesbank(page);
  const page$ = new RegExp(`/connectors/${id}$`);

  // Where the server sends the browser back to: the connector's own page,
  // with how it went. Said once, then taken off the address.
  await page.goto(`/connectors/${id}?oauth=vendor_refused`);
  const refused = page.getByRole("alert").filter({ hasText: "The vendor refused the request" });
  await expect(refused).toBeVisible();
  await expect(page).toHaveURL(page$);
  await expectAccessible(page);
  // A refusal says what to do next, so it stays until put away.
  await refused.getByRole("button", { name: "Dismiss" }).click();
  await expect(refused).toHaveCount(0);

  await page.goto(`/connectors/${id}?oauth=no_refresh_token`);
  await expect(page.getByRole("alert").filter({ hasText: /sent no refresh token/ })).toBeVisible();
  await expect(page).toHaveURL(page$);

  // A code this page does not know is said as plainly as it can be.
  await page.goto(`/connectors/${id}?oauth=connect_failed`);
  await expect(page.getByRole("alert").filter({ hasText: "Connecting failed." })).toBeVisible();
  await expect(page).toHaveURL(page$);

  await page.goto(`/connectors/${id}?oauth=ok`);
  await expect(
    page.getByRole("heading", {
      name: "Connected. The vendor approved access, and the workspace now holds the tokens.",
      exact: true,
    }),
  ).toBeVisible();
  await expect(page).toHaveURL(page$);
  // Reloading does not say it again.
  await page.reload();
  await expect(page.getByRole("heading", { name: bundesbank, level: 1 })).toBeVisible();
  await expect(page.getByRole("alert").filter({ hasText: /vendor/ })).toHaveCount(0);

  // A return that names no connector ends on the list.
  await page.goto("/connectors?oauth=expired");
  await expect(page.getByRole("alert").filter({ hasText: /The approval took too long/ })).toBeVisible();
  await expect(page).toHaveURL(/\/connectors$/);
});

test("an OAuth connector's page says whether it is authorized", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();
  test.setTimeout(90_000);

  // A consent-screen connector nobody has approved yet.
  await page.goto("/catalog/datev-sandbox");
  await page.getByLabel("DATEV_CLIENT_ID").fill("browser-test-client");
  await page.getByLabel("DATEV_CLIENT_SECRET").fill("not-a-real-secret"); // gitleaks:allow
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors\/[^/]+$/);
  const status = page.getByRole("region", { name: "Status" });
  const credentials = page.getByRole("region", { name: "Credentials" });
  await expect(status.getByText("Not authorized yet", { exact: true })).toBeVisible();
  await expect(credentials.getByRole("button", { name: "Authorize", exact: true })).toBeVisible();
  await expect(credentials.getByRole("button", { name: "Re-authorize" })).toHaveCount(0);
  await expectAccessible(page);

  // A client-credentials connector holds a token once it has fetched one,
  // which it does at its first call. Its token endpoint is this instance's
  // own, and its client a service account of this workspace, so the grant
  // really happens and nothing outside is reached.
  await page.goto("/settings/service-accounts");
  await page.getByRole("button", { name: "New service account" }).first().click();
  const dialog = page.getByRole("dialog", { name: "New service account" });
  await dialog.getByLabel("Name").fill("Token source");
  await dialog.getByRole("button", { name: "Create account" }).click();
  const issued = await page.getByRole("alert").filter({ hasText: /copy this secret now/i }).innerText();
  const clientId = /client_id: (\S+)/.exec(issued)?.[1];
  const clientSecret = /client_secret: (\S+)/.exec(issued)?.[1];
  expect(clientId && clientSecret, issued).toBeTruthy();
  await page.getByRole("button", { name: "Done" }).click();

  const origin = new URL(page.url()).origin;
  await page.goto("/connectors/import");
  await page.getByRole("radio", { name: "OpenAPI", exact: true }).check();
  await page.getByLabel("OpenAPI document").fill(
    JSON.stringify({
      openapi: "3.1.0",
      info: { title: "Self check", version: "1.0.0" },
      servers: [{ url: origin }],
      security: [{ machine: [] }],
      components: {
        securitySchemes: {
          machine: { type: "oauth2", flows: { clientCredentials: { tokenUrl: `${origin}/oauth/token`, scopes: {} } } },
        },
      },
      paths: {
        "/healthz": {
          get: { operationId: "readHealth", summary: "Whether the instance is up", responses: { "200": { description: "Up" } } },
        },
      },
    }),
  );
  await page.getByLabel("Connector name").fill("Self check");
  await page.getByLabel("Tool name prefix").fill("selfcheck");
  await page.getByRole("button", { name: "Preview import" }).click();
  await expect(page.getByRole("region", { name: "What this would create" })).toBeVisible();
  await page.getByLabel("OAUTH_CLIENT_ID").fill(clientId as string);
  await page.getByLabel("OAUTH_CLIENT_SECRET").fill(clientSecret as string);
  await page.getByRole("button", { name: "Import connector" }).click();
  await expect(page.getByRole("heading", { name: "Self check", level: 1 })).toBeVisible();
  const connectorPage = page.url();
  await expect(status.getByText("Not authorized yet", { exact: true })).toBeVisible();
  // Nobody approves a client-credentials grant, so there is nothing to press.
  await expect(page.getByRole("button", { name: /authorize/i })).toHaveCount(0);

  const serverId = await createServer(page, "Self check server", [/Self check/]);
  const secret = await createKey(page, "Self check key");
  const call = await request.post(`/mcp/${serverId}`, {
    headers: { "X-API-Key": secret, Accept: "application/json, text/event-stream" },
    data: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "selfcheck_read_health", arguments: {} } },
  });
  expect(call.ok(), `tools/call: ${call.status()} ${await call.text()}`).toBeTruthy();

  await page.goto(connectorPage);
  await expect(status.getByText("Authorized", { exact: true })).toBeVisible();
  // The call is found by the server as this connector's own.
  const recent = page.waitForResponse((r) => new URL(r.url()).searchParams.has("connectorId"));
  await page.reload();
  expect((await recent).status()).toBe(200);
  await expect(status.getByRole("cell", { name: "selfcheck_read_health" })).toBeVisible();
});
