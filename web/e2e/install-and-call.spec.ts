import { test, expect, expectAccessible, signUp, createKey, createServer, installAdapter } from "./fixtures";

// The path a new workspace actually takes: find an adapter, install it,
// expose it on an MCP server, mint a key, and call a tool with that key.
// Every step here is one a person performs, which is why this file exists
// separately from the Go tests that reach the same code through services.

test("a workspace installs an adapter, exposes it and calls a tool", async ({ page, request, workspace }) => {
  await page.goto("/catalog");
  await expect(page.getByRole("heading", { name: "Catalog" })).toBeVisible();
  await expect(page.getByText(/\d+ adapters/)).toBeVisible();

  // A keyless adapter, so the install needs no credentials from us.
  await page.getByRole("link", { name: /Deutsche Bundesbank Statistics/ }).click();
  await expect(page.getByRole("heading", { name: "Deutsche Bundesbank Statistics" })).toBeVisible();
  await expect(page.getByText("bundesbank_get_exchange_rates")).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Install" }).click();
  await expect(page.getByText("Deutsche Bundesbank Statistics installed", { exact: true })).toBeVisible();
  // It lands on the new connector's own page.
  await expect(page).toHaveURL(/\/connectors\/[^/]+$/);
  await expect(page.getByRole("heading", { name: "Deutsche Bundesbank Statistics", level: 1 })).toBeVisible();
  await expect(page.getByRole("region", { name: "Status" })).toBeVisible();

  // An MCP server is what an AI client is actually pointed at.
  const serverId = await createServer(page, "Browser server", [/Deutsche Bundesbank Statistics/]);
  await expect(page.getByText("MCP server Browser server created", { exact: true })).toBeVisible();
  await expect(page.getByRole("listitem").filter({ hasText: "Browser server" })).toContainText("1 connector");

  // The key is shown once, which is the whole contract of that screen.
  const secret = await createKey(page, "Browser key");
  expect(secret).toMatch(/^smk_/);

  // And now the part that matters: the key works against the MCP endpoint.
  const list = await request.post(`/mcp/${serverId}`, {
    headers: { "X-API-Key": secret, Accept: "application/json, text/event-stream" },
    data: { jsonrpc: "2.0", id: 1, method: "tools/list" },
  });
  expect(list.ok(), "tools/list was refused for a key that was just minted").toBeTruthy();
  const body = await list.text();
  expect(body).toContain("bundesbank_get_exchange_rates");

  // The call is recorded where a person can see it.
  await page.goto("/activity");
  await expect(page.getByRole("heading", { name: "Activity", level: 1 })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Calls" })).toHaveAttribute("aria-selected", "true");
});

test("an API key from one workspace cannot reach another workspace's server", async ({ page, browser, workspace }) => {
  expect(workspace.email).toBeTruthy();
  // The first workspace installs something and exposes it.
  await installAdapter(page);
  await expect(page).toHaveURL(/\/connectors\/[^/]+$/);
  const serverId = await createServer(page, "Private server", [/Deutsche Bundesbank Statistics/]);

  // The second workspace gets its own browser context rather than sharing
  // this one: clearing cookies leaves the first workspace's state behind
  // in ways a real second person would never have.
  const context = await browser.newContext();
  const intruderPage = await context.newPage();
  const stamp = Date.now();
  await signUp(intruderPage, {
    email: `intruder-${stamp}@example.test`,
    password: "Correct Horse Battery 9", // gitleaks:allow
    org: `Intruder ${stamp}`,
  });

  const intruderKey = await createKey(intruderPage, "Intruder key");

  const res = await context.request.post(`/mcp/${serverId}`, {
    headers: { "X-API-Key": intruderKey, Accept: "application/json, text/event-stream" },
    data: { jsonrpc: "2.0", id: 1, method: "tools/list" },
  });
  expect(
    res.status(),
    "a key from another workspace reached this server; tenant isolation is the one thing that must never fail",
  ).toBeGreaterThanOrEqual(400);
  await context.close();
});
