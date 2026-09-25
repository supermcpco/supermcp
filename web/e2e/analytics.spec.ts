import { test, expect, expectAccessible } from "./fixtures";
import type { APIRequestContext, Page } from "@playwright/test";

// The analytics screen counts the calls a workspace made. The calls here
// go through the real MCP endpoint with a real key, so what is counted is
// what the call path wrote, not rows this test made up. The tools are
// static, which answer without leaving the instance: a count that depends
// on an upstream being reachable would test the upstream.

const echoTool = "analytics_echo";
const cardTool = "analytics_card";

function staticTool(name: string, value: string): string {
  return JSON.stringify({
    name,
    description: "Answers with a fixed text, so the browser suite can make calls that never leave the instance.",
    input: { type: "object", properties: { note: { type: "string", description: "Anything at all" } } },
    operation: { kind: "static", value },
  });
}

async function callTool(request: APIRequestContext, serverId: string, key: string, name: string, note: string) {
  const res = await request.post(`/mcp/${serverId}`, {
    headers: { "X-API-Key": key, Accept: "application/json, text/event-stream" },
    data: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: { note } } },
  });
  expect(res.ok(), `tools/call ${name}: ${res.status()} ${await res.text()}`).toBeTruthy();
  return res.text();
}

/** The figure a totals card shows, found by the label above it. */
function figure(page: Page, label: string) {
  return page
    .getByRole("region", { name: "Totals for the period" })
    .getByRole("group", { name: label, exact: true })
    .getByRole("paragraph");
}

test("the analytics screen counts a workspace's calls, and another workspace sees none of them", async ({
  page,
  request,
  browser,
  workspace,
}) => {
  expect(workspace.email).toBeTruthy();
  test.setTimeout(90_000);

  // Before any call, the screen says there is nothing to show rather than
  // drawing empty charts. It is asked about the last 90 days here and the
  // default seven below, because the server keeps an answer for a minute
  // and the calls in between would not be in this one.
  await page.goto("/analytics?range=90d");
  await expect(page.getByRole("heading", { name: "Analytics" })).toBeVisible();
  await expect(page.getByText("No tool calls in this period.", { exact: false })).toBeVisible();
  await expectAccessible(page);

  const api = page.request;
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);
  const connectorId = (await (await api.get("/api/v1/connectors")).json())[0].id as string;

  // Two tools of our own. Adding tools has its own screen and its own
  // test; here the API is the shorter path.
  const echo = await api.post(`/api/v1/connectors/${connectorId}/tools`, {
    data: { definition: staticTool(echoTool, "echo") },
  });
  expect(echo.ok(), await echo.text()).toBeTruthy();
  const echoId = (await echo.json()).tool.id as string;
  const card = await api.post(`/api/v1/connectors/${connectorId}/tools`, {
    data: { definition: staticTool(cardTool, "card") },
  });
  expect(card.ok(), await card.text()).toBeTruthy();

  // A rule that refuses an email address in the echo tool's arguments is
  // the way to make a call fail that depends on nothing outside.
  const rule = await api.post("/api/v1/dlp/policies", {
    data: {
      name: "No addresses to the echo tool",
      connectorId,
      toolId: echoId,
      scan: "arguments",
      detectors: ["email"],
      action: "refuse",
      enabled: true,
    },
  });
  expect(rule.ok(), await rule.text()).toBeTruthy();

  await page.goto("/servers");
  await page.getByLabel("Name").fill("Analytics server");
  await page.getByRole("checkbox", { name: /Deutsche Bundesbank Statistics/ }).check();
  await page.getByRole("button", { name: "Create server" }).click();
  const endpoint = await page.locator("code", { hasText: "/mcp/" }).first().innerText();
  const serverId = endpoint.trim().split("/mcp/")[1];

  await page.goto("/api-keys");
  await page.getByLabel("Name").fill("Analytics key");
  await page.getByRole("button", { name: "Create key" }).click();
  const secret = (await page.locator("code").first().innerText()).trim();

  // Four calls to the echo tool, one of them refused, and one to the card.
  for (const note of ["one", "two", "three"]) {
    expect(await callTool(request, serverId, secret, echoTool, note)).toContain("echo");
  }
  expect(await callTool(request, serverId, secret, echoTool, "write to someone@example.com")).toMatch(/refused/i);
  expect(await callTool(request, serverId, secret, cardTool, "four")).toContain("card");

  // The charts draw on a canvas and position their tooltips with inline
  // styles, which is what the page's content security policy is strict
  // about; a violation would leave a chart half-drawn without failing
  // anything else here.
  const violations: string[] = [];
  page.on("console", (m) => {
    if (/Content Security Policy/i.test(m.text())) violations.push(m.text());
  });

  await page.goto("/analytics");
  await expect(figure(page, "Calls")).toHaveText("5");
  await expect(figure(page, "Errors")).toHaveText("1 (20%)");
  await expect(page.getByRole("img", { name: /5 calls and 1 error in total/ })).toBeVisible();
  await expect(page.getByRole("img", { name: /call duration per/ })).toBeVisible();
  await page.getByRole("img", { name: /5 calls and 1 error in total/ }).hover();

  // The busiest tool comes first, with its own counts.
  const top = page.getByRole("table", { name: /busiest by tool/i });
  const first = top.getByRole("row").nth(1);
  await expect(first.getByRole("rowheader")).toHaveText(echoTool);
  await expect(first.getByRole("cell").nth(0)).toHaveText("4");
  await expect(first.getByRole("cell").nth(1)).toHaveText("1 (25%)");
  await expect(top.getByRole("row", { name: new RegExp(cardTool) }).getByRole("cell").nth(0)).toHaveText("1");
  await expectAccessible(page);
  expect(violations, "the content security policy refused something the charts do").toEqual([]);

  // The same calls broken down by connector and by server, and the choice
  // is kept in the address.
  await page.getByRole("radio", { name: "Connector" }).click();
  await expect(page).toHaveURL(/by=connector/);
  const byConnector = page.getByRole("table", { name: /busiest by connector/i }).getByRole("row").nth(1);
  await expect(byConnector.getByRole("rowheader")).toHaveText("Deutsche Bundesbank Statistics");
  await expect(byConnector.getByRole("cell").nth(0)).toHaveText("5");

  await page.getByRole("radio", { name: "MCP server" }).click();
  await expect(page).toHaveURL(/by=server/);
  const byServer = page.getByRole("table", { name: /busiest by mcp server/i }).getByRole("row").nth(1);
  await expect(byServer.getByRole("rowheader")).toHaveText("Analytics server");
  await expect(byServer.getByRole("cell").nth(0)).toHaveText("5");

  await page.getByRole("combobox", { name: "Period" }).selectOption({ label: "Last 24 hours" });
  await expect(page).toHaveURL(/range=24h/);
  await expect(figure(page, "Calls")).toHaveText("5");

  // A reload lands on the same view.
  await page.reload();
  await expect(page.getByRole("combobox", { name: "Period" })).toHaveValue("24h");
  await expect(page.getByRole("radio", { name: "MCP server" })).toHaveAttribute("aria-checked", "true");

  // A second workspace, in a browser context of its own, sees none of it:
  // not on the screen and not from the API behind it.
  const context = await browser.newContext();
  const other = await context.newPage();
  const stamp = Date.now();
  await other.goto("/login");
  await other.getByRole("button", { name: /create a new workspace/i }).click();
  await other.getByLabel("Email").fill(`analytics-other-${stamp}@example.test`);
  await other.getByLabel("Password").fill("Correct Horse Battery 9");
  await other.getByLabel("Workspace name").fill(`Analytics other ${stamp}`);
  await other.getByRole("button", { name: /create workspace/i }).click();
  await expect(other.getByText(`Analytics other ${stamp}`)).toBeVisible();

  await other.goto("/analytics?range=24h");
  await expect(other.getByText("No tool calls in this period.", { exact: false })).toBeVisible();
  const theirs = await context.request.get("/api/v1/analytics/usage?by=tool");
  expect(theirs.ok(), await theirs.text()).toBeTruthy();
  const body = await theirs.json();
  expect(body.totals.calls, "another workspace's calls were counted here").toBe(0);
  expect(body.top).toEqual([]);
  await context.close();
});
