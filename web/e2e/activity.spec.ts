import { test, expect, expectAccessible, createServer, createKey } from "./fixtures";
import type { APIRequestContext } from "@playwright/test";

// The activity screen holds the list of calls and the analytics as two
// tabs of one screen. The calls here go through the real MCP endpoint
// with a real key, to static tools that answer without leaving the
// instance, so the list shows what the call path wrote.

const echoTool = "activity_echo";
const cardTool = "activity_card";

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

test("the activity screen shows calls and analytics as tabs and the old addresses still open them", async ({
  page,
  workspace,
}) => {
  expect(workspace.email).toBeTruthy();
  const nav = page.getByRole("navigation", { name: "Primary" });
  const calls = page.getByRole("tab", { name: "Calls" });
  const analytics = page.getByRole("tab", { name: "Analytics" });

  await nav.getByRole("link", { name: "Activity" }).click();
  await expect(page).toHaveURL(/\/activity$/);
  await expect(page.getByRole("heading", { name: "Activity", level: 1 })).toBeVisible();
  await expect(calls).toHaveAttribute("aria-selected", "true");

  // Nothing has called anything yet, and the way to change that is one
  // click away.
  const panel = page.getByRole("tabpanel", { name: "Calls" });
  await expect(panel.getByText("No calls yet", { exact: true })).toBeVisible();
  await expect(panel.getByRole("link", { name: "Connect a client" })).toHaveAttribute("href", "/servers");
  await expectAccessible(page);

  // The longer explanation sits behind the "?" next to the description.
  await page.getByRole("button", { name: "About the calls" }).click();
  await expect(page.getByRole("dialog", { name: "What this list holds" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "What this list holds" })).toBeHidden();

  // The tab is kept in the address; a reload lands on it, and Back
  // returns to the tab before.
  await analytics.click();
  await expect(page).toHaveURL(/\/activity\?tab=analytics$/);
  await expect(page.getByRole("tabpanel", { name: "Analytics" }).getByRole("combobox", { name: "Period" })).toBeVisible();
  await expect(page.getByText("No calls in this period", { exact: true })).toBeVisible();
  await expectAccessible(page);
  await page.reload();
  await expect(analytics).toHaveAttribute("aria-selected", "true");
  await page.goBack();
  await expect(calls).toHaveAttribute("aria-selected", "true");
  await expect(nav.getByRole("link", { name: "Activity" })).toHaveAttribute("aria-current", "page");

  // The addresses the two screens had before still lead to them, the
  // analytics one with its period.
  await page.goto("/tool-calls");
  await expect(page).toHaveURL(/\/activity$/);
  await expect(calls).toHaveAttribute("aria-selected", "true");
  await page.goto("/analytics?range=30d&by=connector");
  await expect(page).toHaveURL(/\/activity\?/);
  await expect(page).toHaveURL(/tab=analytics/);
  await expect(analytics).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("combobox", { name: "Period" })).toHaveValue("30d");
});

test("the calls tab filters the latest calls by status and by tool name, and keeps the filters in the address", async ({
  page,
  request,
  workspace,
}) => {
  expect(workspace.email).toBeTruthy();
  test.setTimeout(90_000);

  const api = page.request;
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);
  const connectorId = (await (await api.get("/api/v1/connectors")).json())[0].id as string;

  // Two tools of our own, and a rule refusing an email address in the
  // echo tool's arguments: the way to make a call fail that depends on
  // nothing outside.
  const echo = await api.post(`/api/v1/connectors/${connectorId}/tools`, {
    data: { definition: staticTool(echoTool, "echo") },
  });
  expect(echo.ok(), await echo.text()).toBeTruthy();
  const echoId = (await echo.json()).tool.id as string;
  const card = await api.post(`/api/v1/connectors/${connectorId}/tools`, {
    data: { definition: staticTool(cardTool, "card") },
  });
  expect(card.ok(), await card.text()).toBeTruthy();
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

  const serverId = await createServer(page, "Activity server", [/Deutsche Bundesbank Statistics/]);
  const secret = await createKey(page, "Activity key");

  // Two good calls to the echo tool, one refused, and one to the card.
  for (const note of ["one", "two"]) {
    expect(await callTool(request, serverId, secret, echoTool, note)).toContain("echo");
  }
  expect(await callTool(request, serverId, secret, echoTool, "write to someone@example.com")).toMatch(/refused/i);
  expect(await callTool(request, serverId, secret, cardTool, "three")).toContain("card");

  await page.goto("/activity");
  const table = page.getByRole("table", { name: "Latest tool calls" });
  const rows = table.getByRole("row");
  // A header row and a row per call.
  await expect(rows).toHaveCount(5);
  await expect(page.getByText("4 calls", { exact: true })).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("combobox", { name: "Status" }).selectOption({ label: "Failed" });
  await expect(page).toHaveURL(/status=failed/);
  await expect(rows).toHaveCount(2);
  await expect(table.getByRole("rowheader")).toHaveText(echoTool);
  await expect(page.getByText("1 of 4 calls", { exact: true })).toBeVisible();

  await page.getByRole("combobox", { name: "Status" }).selectOption({ label: "All calls" });
  await page.getByRole("searchbox", { name: "Tool name" }).fill("CARD");
  await expect(page).toHaveURL(/q=CARD/);
  await expect(rows).toHaveCount(2);
  await expect(table.getByRole("rowheader")).toHaveText(cardTool);

  // A reload keeps the filters, which then match nothing together.
  await page.getByRole("combobox", { name: "Status" }).selectOption({ label: "Failed" });
  await page.reload();
  await expect(page.getByRole("searchbox", { name: "Tool name" })).toHaveValue("CARD");
  await expect(page.getByRole("combobox", { name: "Status" })).toHaveValue("failed");
  await expect(page.getByText("No calls match", { exact: true })).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Clear the filters" }).click();
  await expect(page).toHaveURL(/\/activity$/);
  await expect(rows).toHaveCount(5);
  await expect(page.getByRole("searchbox", { name: "Tool name" })).toHaveValue("");
});
