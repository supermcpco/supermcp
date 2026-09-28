import { test, expect, expectAccessible, closeSecret, createKey, createServer } from "./fixtures";
import type { APIRequestContext, Page } from "@playwright/test";

// The overview is what a new workspace lands on. Until the workspace can
// serve a client it is a list of what is left to do, each step ticking
// from what the server reports; after that it is a dashboard. Every step
// here is done the way a person does it, and the page is reloaded to see
// what it says, because that is what a person would look at.

test("a fresh workspace sees the setup checklist and each step completes as it is done", async ({
  page,
  request,
  workspace,
}) => {
  expect(workspace.email).toBeTruthy();
  const step = (title: string) =>
    page.getByRole("listitem").filter({ has: page.getByRole("heading", { name: title }) });
  const states = async () =>
    Promise.all(
      ["Install a connector", "Create an MCP server", "Create an API key", "Connect a client"].map(async (t) =>
        (await step(t).innerText()).match(/\b(Done|To do)\b/)?.[1],
      ),
    );

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Set up your workspace" })).toBeVisible();
  await expect(page.getByText("0 of 4 steps done")).toBeVisible();
  expect(await states()).toEqual(["To do", "To do", "To do", "To do"]);
  await expectAccessible(page);

  // 1. The step's own link leads to the catalog, where the install happens.
  await step("Install a connector").getByRole("link", { name: "Open the catalog" }).click();
  await expect(page).toHaveURL(/\/catalog$/);
  await page.getByRole("link", { name: /Deutsche Bundesbank Statistics/ }).click();
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page.getByText("Deutsche Bundesbank Statistics installed", { exact: true })).toBeVisible();
  await page.goto("/");
  await expect(page.getByText("1 of 4 steps done")).toBeVisible();
  expect(await states()).toEqual(["Done", "To do", "To do", "To do"]);

  // 2. A server.
  const serverId = await createServer(page, "Checklist server", [/Deutsche Bundesbank Statistics/]);
  await page.goto("/");
  await expect(page.getByText("2 of 4 steps done")).toBeVisible();
  expect(await states()).toEqual(["Done", "Done", "To do", "To do"]);

  // 3. A key. The last step now shows how to connect, with the endpoint.
  const secret = await createKey(page, "Checklist key");
  await closeSecret(page);
  await page.goto("/");
  await expect(page.getByText("3 of 4 steps done")).toBeVisible();
  expect(await states()).toEqual(["Done", "Done", "Done", "To do"]);
  const endpoint = step("Connect a client").getByLabel("Endpoint of Checklist server", { exact: true });
  await expect(endpoint).toHaveValue(new RegExp(`/mcp/${serverId}$`));
  await expect(step("Connect a client").getByRole("region", { name: "Claude Desktop config" })).toContainText(
    `/mcp/${serverId}`,
  );
  await expectAccessible(page);

  // 4. A client connects: the first request any client sends, with the key.
  const init = await request.post(`/mcp/${serverId}`, {
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    data: {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "browser-test", version: "1" } },
    },
  });
  expect(init.ok(), `initialize was refused: ${init.status()} ${await init.text()}`).toBeTruthy();

  // Set up: the checklist gives way to the dashboard.
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Recent tool calls" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Set up your workspace" })).toHaveCount(0);
  const main = page.getByRole("main");
  await expect(main.getByText("Connectors", { exact: true })).toBeVisible();
  await expect(main.getByText("Calls in the last 24 hours", { exact: true })).toBeVisible();
  await expect(main.getByText("Failures in the last 24 hours", { exact: true })).toBeVisible();
  await expect(page.getByText("No calls yet.")).toBeVisible();
  await expect(page.getByLabel("Endpoint of Checklist server", { exact: true })).toHaveValue(
    new RegExp(`/mcp/${serverId}$`),
  );
  await expect(page.getByRole("button", { name: "Copy endpoint of Checklist server" })).toBeVisible();
  await expectAccessible(page);
});

async function callTool(request: APIRequestContext, serverId: string, key: string, name: string, note: string) {
  const res = await request.post(`/mcp/${serverId}`, {
    headers: { "X-API-Key": key, Accept: "application/json, text/event-stream" },
    data: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: { note } } },
  });
  expect(res.ok(), `tools/call ${name}: ${res.status()} ${await res.text()}`).toBeTruthy();
  return res.text();
}

/**
 * Installs a connector with a tool that answers without leaving the
 * instance, and returns what a call to it needs.
 */
async function echoConnector(page: Page) {
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors\/[^/]+$/);
  const connectorId = new URL(page.url()).pathname.split("/").pop() as string;
  const tool = await page.request.post(`/api/v1/connectors/${connectorId}/tools`, {
    data: {
      definition: JSON.stringify({
        name: "overview_echo",
        description: "Answers with a fixed text, so the browser suite can make calls that never leave the instance.",
        input: { type: "object", properties: { note: { type: "string", description: "Anything at all" } } },
        operation: { kind: "static", value: "echo" },
      }),
    },
  });
  expect(tool.ok(), await tool.text()).toBeTruthy();
  return { connectorId, toolId: (await tool.json()).tool.id as string };
}

test("the overview counts the day's calls from the summary", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const { connectorId, toolId } = await echoConnector(page);

  // A rule that refuses an email address in the echo tool's arguments, so
  // one call can fail.
  const rule = await page.request.post("/api/v1/dlp/policies", {
    data: {
      name: "No addresses to the echo tool",
      connectorId,
      toolId,
      scan: "arguments",
      detectors: ["email"],
      action: "refuse",
      enabled: true,
    },
  });
  expect(rule.ok(), await rule.text()).toBeTruthy();

  const serverId = await createServer(page, "Overview server", [/Deutsche Bundesbank Statistics/]);
  const secret = await createKey(page, "Overview key");
  await closeSecret(page);

  expect(await callTool(request, serverId, secret, "overview_echo", "one")).toContain("echo");
  expect(await callTool(request, serverId, secret, "overview_echo", "two")).toContain("echo");
  expect(await callTool(request, serverId, secret, "overview_echo", "to someone@example.com")).toMatch(/refused/i);

  // The tiles are the server's count of the day, not a count of rows.
  const summary = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/v1/tool-calls/summary" && r.request().method() === "GET",
  );
  await page.goto("/");
  const answer = await summary;
  expect(answer.status()).toBe(200);
  const since = new URL(answer.url()).searchParams.get("since");
  const until = new URL(answer.url()).searchParams.get("until");
  expect(since && until && Date.parse(until) - Date.parse(since)).toBe(24 * 60 * 60 * 1000);

  const main = page.getByRole("main");
  await expect(main.getByRole("group", { name: "Calls in the last 24 hours" })).toHaveText(/^Calls in the last 24 hours3$/);
  await expect(main.getByRole("group", { name: "Failures in the last 24 hours" })).toHaveText(
    /^Failures in the last 24 hours1$/,
  );
  await expect(page.getByRole("heading", { name: "Recent tool calls" })).toBeVisible();
  await expect(main.getByRole("cell", { name: "overview_echo" })).toHaveCount(3);
  await expectAccessible(page);
});

test("the overview's recent calls lead to their connector", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const { connectorId } = await echoConnector(page);
  const serverId = await createServer(page, "Recent calls server", [/Deutsche Bundesbank Statistics/]);
  const secret = await createKey(page, "Recent calls key");
  await closeSecret(page);
  expect(await callTool(request, serverId, secret, "overview_echo", "one")).toContain("echo");

  await page.goto("/");
  const recent = page.getByRole("region", { name: "Recent tool calls" });
  const row = recent.getByRole("row").filter({ has: page.getByRole("cell", { name: "overview_echo" }) });
  await expect(row).toHaveCount(1);
  const link = row.getByRole("link", { name: "Deutsche Bundesbank Statistics", exact: true });
  await expect(link).toHaveAttribute("href", `/connectors/${connectorId}`);
  await expectAccessible(page);

  await link.click();
  await expect(page).toHaveURL(new RegExp(`/connectors/${connectorId}$`));
  await expect(page.getByRole("heading", { name: "Deutsche Bundesbank Statistics", level: 1 })).toBeVisible();
});
