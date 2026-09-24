import { test, expect, expectAccessible } from "./fixtures";

// What a workspace does about the calls it does not trust: inspect what
// they carry, and hold the ones that need a person. Both gates sit on the
// live call path, so both are exercised by making a real call.

test("a rule inspects what a tool call carries, and an approval holds one until somebody agrees", async ({
  page,
  request,
  workspace,
}) => {
  expect(workspace.email).toBeTruthy();

  // A keyless adapter on a server, with a key, is the shortest path to a
  // call that the gates can act on.
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);

  await page.goto("/servers");
  await page.getByLabel("Name").fill("Governed server");
  await page.getByRole("checkbox", { name: /Deutsche Bundesbank Statistics/ }).check();
  await page.getByRole("button", { name: "Create server" }).click();
  const endpoint = await page.locator("code", { hasText: "/mcp/" }).first().innerText();
  const serverId = endpoint.trim().split("/mcp/")[1];

  await page.goto("/api-keys");
  await page.getByLabel("Name").fill("Governed key");
  await page.getByRole("button", { name: "Create key" }).click();
  const secret = (await page.locator("code").first().innerText()).trim();

  // The data-loss rule, added the way an administrator adds it.
  await page.goto("/settings/dlp");
  await expect(page.getByRole("heading", { name: "Data-loss rules" })).toBeVisible();
  await expect(page.getByText(/no rules yet/i)).toBeVisible();
  // What the detectors match is covered by the Go tests; what matters here
  // is that a rule can be added from the screen and that a call still goes
  // through the gate it puts on the path.
  await page.getByLabel("What it is for").fill("Mask identifiers in results");
  await page.getByLabel("What it does").selectOption("mask");
  await page.getByRole("button", { name: "Add the rule" }).click();
  await expect(page.getByText("Mask identifiers in results").first()).toBeVisible();
  await expectAccessible(page);

  // The approval policy has no screen yet, so it is set the way the API
  // documents it. What has a screen is the queue, which is the part a
  // person uses.
  const api = page.request;
  const tools = await api.get("/api/v1/connectors");
  const connectors = await tools.json();
  const connectorId = connectors[0].id;
  const toolList = await api.get(`/api/v1/connectors/${connectorId}/tools`);
  const toolName = (await toolList.json())[0].name;

  const policy = await api.post("/api/v1/approval-policies", {
    data: {
      name: "Everything from this connector",
      scope: "connector",
      scopeId: connectorId,
      trigger: "tool",
      toolName,
      effect: "require",
      ttlSeconds: 3600,
      enabled: true,
    },
  });
  expect(policy.ok(), `${policy.status()} ${await policy.text()}`).toBeTruthy();

  // The call is made by a service account, not by the person who will
  // approve it: nobody approves their own call, which the API enforces and
  // this test would otherwise trip over.
  await page.goto("/settings/service-accounts");
  await page.getByLabel("Name").fill("Caller");
  await page.getByRole("button", { name: "Create account" }).click();
  const issued = await page.getByRole("alert").locator("code").innerText();
  const clientId = /client_id: (\S+)/.exec(issued)?.[1] ?? "";
  const clientSecret = /client_secret: (\S+)/.exec(issued)?.[1] ?? "";
  expect(clientId).toMatch(/^sms_/);
  await page.getByRole("button", { name: "Done" }).click();

  // It needs a role before it may invoke anything. Granting one has its
  // own screen and its own test; here the API is the shorter path to the
  // state this test is about.
  const roles = await api.get("/api/v1/roles");
  const invoker = (await roles.json()).roles.find((r: { permissions: string[] }) =>
    r.permissions.some((p) => p === "tools:invoke" || p === "*"),
  );
  const accounts = await api.get("/api/v1/service-accounts");
  const account = (await accounts.json()).accounts.find((a: { clientId: string }) => a.clientId === clientId);
  const bound = await api.post(`/api/v1/roles/${invoker.id}/bindings`, {
    data: { principalKind: "service_account", principalId: account.id, scopeKind: "org" },
  });
  expect(bound.ok(), await bound.text()).toBeTruthy();

  const token = await request.post("/oauth/token", {
    form: { grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret },
  });
  expect(token.ok(), await token.text()).toBeTruthy();
  const accessToken = (await token.json()).access_token;

  // The call now comes back held rather than done.
  const held = await request.post(`/mcp/${serverId}`, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json, text/event-stream" },
    data: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: toolName, arguments: {} } },
  });
  const heldBody = await held.text();
  expect(heldBody, "a gated call should name the request it raised").toMatch(/approval/i);

  // And a person can see it and agree to it.
  await page.goto("/approvals");
  await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible();
  await expect(page.getByText(toolName).first()).toBeVisible();
  await expectAccessible(page);

  // Unsealing the arguments is privileged and recorded, so the queue asks
  // before it shows them.
  await page.getByRole("button", { name: "Show what it would run" }).first().click();
  await expect(page.getByText("No arguments.")).toBeVisible();

  await page.getByRole("textbox", { name: `Why, for ${toolName}` }).fill("Checked with the requester");
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("Checked with the requester")).toBeVisible();
});
