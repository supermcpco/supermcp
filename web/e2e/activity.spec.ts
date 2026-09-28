import { test, expect, expectAccessible, createServer, createKey } from "./fixtures";
import type { APIRequestContext } from "@playwright/test";

// The activity screen holds the list of calls and the analytics as two
// tabs of one screen. The calls here go through the real MCP endpoint
// with a real key, to static tools that answer without leaving the
// instance, so the list shows what the call path wrote.

const echoTool = "activity_echo";
const cardTool = "activity_card";
const postcodeTool = "activity_postcode";

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

test("the calls tab filters on the server and keeps the filters in the address", async ({
  page,
  request,
  workspace,
}) => {
  expect(workspace.email).toBeTruthy();
  test.setTimeout(120_000);

  const api = page.request;
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors\/[^/]+$/);
  const bankId = new URL(page.url()).pathname.split("/").pop() as string;
  await page.goto("/catalog/openplz");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors\/[^/]+$/);
  const plzId = new URL(page.url()).pathname.split("/").pop() as string;
  expect(plzId).not.toBe(bankId);

  // Two tools of our own on one connector and one on the other, and a
  // rule refusing an email address in the echo tool's arguments: the way
  // to make a call fail that depends on nothing outside.
  const addTool = async (connectorId: string, name: string, value: string) => {
    const res = await api.post(`/api/v1/connectors/${connectorId}/tools`, { data: { definition: staticTool(name, value) } });
    expect(res.ok(), await res.text()).toBeTruthy();
    return (await res.json()).tool.id as string;
  };
  const echoId = await addTool(bankId, echoTool, "echo");
  await addTool(bankId, cardTool, "card");
  await addTool(plzId, postcodeTool, "postcode");
  const rule = await api.post("/api/v1/dlp/policies", {
    data: {
      name: "No addresses to the echo tool",
      connectorId: bankId,
      toolId: echoId,
      scan: "arguments",
      detectors: ["email"],
      action: "refuse",
      enabled: true,
    },
  });
  expect(rule.ok(), await rule.text()).toBeTruthy();

  const serverId = await createServer(page, "Activity server", [/Deutsche Bundesbank Statistics/, /OpenPLZ Germany/]);
  const secret = await createKey(page, "Activity key");

  // Two good calls to the echo tool, one refused, one to the card and
  // one to the other connector.
  for (const note of ["one", "two"]) {
    expect(await callTool(request, serverId, secret, echoTool, note)).toContain("echo");
  }
  expect(await callTool(request, serverId, secret, echoTool, "write to someone@example.com")).toMatch(/refused/i);
  expect(await callTool(request, serverId, secret, cardTool, "three")).toContain("card");
  expect(await callTool(request, serverId, secret, postcodeTool, "four")).toContain("postcode");

  // The answer to a filtered list, once it carries every parameter named.
  const listed = (params: Record<string, string | RegExp>) =>
    page.waitForResponse((r) => {
      const url = new URL(r.url());
      if (url.pathname !== "/api/v1/tool-calls" || r.request().method() !== "GET") return false;
      return Object.entries(params).every(([k, v]) => {
        const got = url.searchParams.get(k);
        return got !== null && (typeof v === "string" ? got === v : v.test(got));
      });
    });

  // The plain list asks for nothing but the latest calls.
  const plain = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/v1/tool-calls" && r.request().method() === "GET",
  );
  await page.goto("/activity");
  expect([...new URL((await plain).url()).searchParams.keys()]).toEqual(["limit"]);
  const table = page.getByRole("table", { name: "Latest tool calls" });
  const rows = table.getByRole("row");
  // A header row and a row per call.
  await expect(rows).toHaveCount(6);
  await expect(page.getByText("5 calls", { exact: true })).toBeVisible();
  // Each call leads to its connector.
  await expect(table.getByRole("link", { name: "OpenPLZ Germany" })).toHaveAttribute("href", `/connectors/${plzId}`);
  await expect(table.getByRole("link", { name: "Deutsche Bundesbank Statistics" })).toHaveCount(4);
  await expectAccessible(page);

  const status = page.getByRole("combobox", { name: "Status" });
  const connector = page.getByRole("combobox", { name: "Connector" });
  const server = page.getByRole("combobox", { name: "MCP server" });
  const period = page.getByRole("combobox", { name: "Period" });
  const name = page.getByRole("searchbox", { name: "Tool name" });

  // A call refused by a data-loss rule is recorded as failed.
  let answer = listed({ status: "error" });
  await status.selectOption({ label: "Failed" });
  expect((await answer).status()).toBe(200);
  await expect(page).toHaveURL(/status=error/);
  await expect(rows).toHaveCount(2);
  await expect(table.getByRole("rowheader")).toHaveText(echoTool);
  await expect(page.getByText("1 call", { exact: true })).toBeVisible();

  await status.selectOption({ label: "All calls" });
  answer = listed({ connectorId: plzId });
  await connector.selectOption({ label: "OpenPLZ Germany" });
  expect((await answer).status()).toBe(200);
  await expect(page).toHaveURL(new RegExp(`connector=${plzId}`));
  await expect(rows).toHaveCount(2);
  await expect(table.getByRole("rowheader")).toHaveText(postcodeTool);

  await connector.selectOption({ label: "All connectors" });
  answer = listed({ q: "CARD" });
  await name.fill("CARD");
  expect((await answer).status()).toBe(200);
  await expect(page).toHaveURL(/q=CARD/);
  await expect(rows).toHaveCount(2);
  await expect(table.getByRole("rowheader")).toHaveText(cardTool);

  // The period and the server narrow it further, and it still holds.
  answer = listed({ q: "CARD", since: /^\d{4}-/, until: /^\d{4}-/ });
  await period.selectOption({ label: "Last 24 hours" });
  expect((await answer).status()).toBe(200);
  await expect(page).toHaveURL(/period=24h/);
  answer = listed({ q: "CARD", serverId });
  await server.selectOption({ label: "Activity server" });
  expect((await answer).status()).toBe(200);
  await expect(page).toHaveURL(new RegExp(`server=${serverId}`));
  await expect(rows).toHaveCount(2);
  await expect(table.getByRole("rowheader")).toHaveText(cardTool);

  // A reload keeps the filters, which then match nothing together.
  await status.selectOption({ label: "Failed" });
  await page.reload();
  await expect(name).toHaveValue("CARD");
  await expect(status).toHaveValue("error");
  await expect(period).toHaveValue("24h");
  await expect(server).toHaveValue(serverId);
  await expect(page.getByText("No calls match", { exact: true })).toBeVisible();
  await expectAccessible(page);

  // A search refused because two others are running is said calmly, and
  // asked again on request. Two searches cannot be held open on purpose
  // from here, so the server's refusal is stood in for, once.
  await page.route(
    (url) => url.pathname === "/api/v1/tool-calls" && url.searchParams.get("status") === "timeout",
    (route) =>
      route.fulfill({
        status: 429,
        contentType: "application/problem+json",
        body: JSON.stringify({ status: 429, title: "Too Many Requests", detail: "too many analytics queries running" }),
      }),
    { times: 1 },
  );
  await status.selectOption({ label: "Timed out" });
  const notice = page.getByRole("status").filter({ hasText: "Another search is still running, try again in a moment." });
  await expect(notice).toBeVisible();
  answer = listed({ status: "timeout" });
  await notice.getByRole("button", { name: "Try again" }).click();
  expect((await answer).status()).toBe(200);
  await expect(page.getByText("No calls match", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Clear the filters" }).click();
  await expect(page).toHaveURL(/\/activity$/);
  await expect(rows).toHaveCount(6);
  await expect(name).toHaveValue("");
});
