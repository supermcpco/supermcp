import { test, expect } from "./fixtures";

// What would this actually send? The question a person asks before they
// trust a tool with a real argument, and the fastest way to find a mapping
// that is wrong. The answer must come back without anything leaving the
// instance, which is why it is offered to everybody who may make the call.

test("a tool call can be rendered without being sent", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const api = page.request;

  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);

  const connectors = await (await api.get("/api/v1/connectors")).json();
  const connectorId = connectors[0].id;
  const tools = await (await api.get(`/api/v1/connectors/${connectorId}/tools`)).json();
  // A tool that needs nothing renders from nothing.
  const tool =
    tools.find((t: { name: string; parameters?: { required?: string[] } }) => !t.parameters?.required?.length) ??
    tools[0];

  const preview = await api.post(`/api/v1/connectors/${connectorId}/tools/${tool.id}/dry-run`, {
    data: { arguments: {} },
  });
  expect(preview.ok(), await preview.text()).toBeTruthy();
  const body = await preview.json();
  expect(body.method).toBe("GET");
  expect(body.url, "a preview that does not show the address shows nothing useful").toContain("bundesbank.de");

  // A tool that needs an argument says which one rather than rendering a
  // request with a hole in it.
  const needsOne = tools.find((t: { parameters?: { required?: string[] } }) => t.parameters?.required?.length);
  if (needsOne) {
    const refused = await api.post(`/api/v1/connectors/${connectorId}/tools/${needsOne.id}/dry-run`, {
      data: { arguments: {} },
    });
    expect(refused.status()).toBe(422);
    expect(await refused.text()).toContain(needsOne.parameters.required[0]);
  }

  // And the same thing over MCP, which is where a model asks for it.
  await page.goto("/servers");
  await page.getByLabel("Name").fill("Preview server");
  await page.getByRole("checkbox", { name: /Deutsche Bundesbank Statistics/ }).check();
  await page.getByRole("button", { name: "Create server" }).click();
  const endpoint = await page.locator("code", { hasText: "/mcp/" }).first().innerText();
  const serverId = endpoint.trim().split("/mcp/")[1];

  await page.goto("/api-keys");
  await page.getByLabel("Name").fill("Preview key");
  await page.getByRole("button", { name: "Create key" }).click();
  const secret = (await page.locator("code").first().innerText()).trim();

  const called = await request.post(`/mcp/${serverId}`, {
    headers: { "X-API-Key": secret, Accept: "application/json, text/event-stream" },
    data: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: tool.name, arguments: { _dry_run: true } },
    },
  });
  const text = await called.text();
  expect(text).toContain("Nothing was sent");
  expect(text).toContain("bundesbank.de");
  expect(text, "the flag steers this system and is not part of the request").not.toContain("_dry_run=");

  // The preview is recorded: seeing how a credential is used is close
  // enough to using it that an auditor needs to know it happened.
  await expect
    .poll(
      async () => {
        const events = await api.get("/api/v1/audit?category=tool&limit=50");
        return (await events.json()).events.map((e: { action: string }) => e.action);
      },
      { timeout: 10_000 },
    )
    .toContain("tool.dry_run");
});
