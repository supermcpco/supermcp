import { test, expect, expectAccessible, closeSecret, createKey, createServer } from "./fixtures";

// How a person gets from a server on this screen to a client talking to
// it: the config for their client, with the endpoint and, when a key was
// just made, the key. The snippets are checked by using them.

/** Picks `client` in the Client picker inside `scope`. */
async function pick(scope: import("@playwright/test").Locator, client: string) {
  await scope.getByRole("combobox", { name: "Client", exact: true }).click();
  await scope.page().getByRole("option", { name: client, exact: true }).click();
  await expect(scope.getByRole("combobox", { name: "Client", exact: true })).toHaveText(client);
}

/** The JSON object in a config region's text. */
async function configIn(region: import("@playwright/test").Locator) {
  const text = await region.innerText();
  const json = /\{[\s\S]*\}/.exec(text)?.[0] ?? "";
  return JSON.parse(json);
}

test("a server shows how to connect a client and the snippet carries the endpoint", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const serverId = await createServer(page, "Connect server");
  const card = page.getByRole("listitem").filter({ hasText: "Connect server" });
  // Sessions and the endpoint stay where they were.
  await expect(card.getByLabel("Sessions")).toHaveValue("stateless");

  await card.getByRole("button", { name: "Connect a client to Connect server" }).click();
  // Claude Code comes first, as one command to run.
  const code = card.getByRole("region", { name: "Claude Code config" });
  await expect(code).toContainText(`claude mcp add --transport http connect-server `);
  await expect(code).toContainText(new RegExp(`/mcp/${serverId} --header "Authorization: Bearer <your API key>"`));
  await expectAccessible(page);

  await pick(card, "Claude Desktop");
  const claude = card.getByRole("region", { name: "Claude Desktop config" });
  await expect(claude).toBeVisible();
  await expect(claude).toContainText("mcp-remote");
  await expect(claude).toContainText("<your API key>");
  const desktop = await configIn(claude);
  const entry = Object.values(desktop.mcpServers)[0] as { args: string[] };
  expect(entry.args.some((a) => a.endsWith(`/mcp/${serverId}`))).toBe(true);

  await pick(card, "Cursor");
  const cursor = card.getByRole("region", { name: "Cursor config" });
  await expect(cursor).toContainText(".cursor/mcp.json");
  const cursorEntry = Object.values((await configIn(cursor)).mcpServers)[0] as {
    url: string;
    headers: { Authorization: string };
  };
  expect(cursorEntry.url).toMatch(new RegExp(`/mcp/${serverId}$`));
  expect(cursorEntry.headers.Authorization).toBe("Bearer <your API key>");

  await pick(card, "curl");
  await expect(card.getByRole("region", { name: "curl config" })).toContainText('"method":"initialize"');

  // The Cursor entry, with a real key in place of the placeholder, is
  // accepted by the endpoint it names.
  const secret = await createKey(page, "Connect key");
  const init = await request.post(cursorEntry.url, {
    headers: {
      Authorization: cursorEntry.headers.Authorization.replace("<your API key>", secret),
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
});

test("a new key's secret is shown once in a dialog with a connection snippet", async ({ page, context, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);

  // Before any server exists the dialog says so and points at where to make one.
  await createKey(page, "Early key");
  const shown = page.getByRole("dialog", { name: "Copy this key now" });
  await expect(shown.getByText("There is no MCP server to connect to yet.")).toBeVisible();
  await expect(shown.getByRole("link", { name: "Create one on MCP servers" })).toBeVisible();
  await closeSecret(page);

  const serverId = await createServer(page, "Keyed server");
  const secret = await createKey(page, "Desktop key");
  await expect(page.getByText("API key Desktop key created", { exact: true })).toBeVisible();

  // The only server is picked, and the snippet carries the secret and its endpoint.
  await expect(shown.getByLabel("Server", { exact: true })).toHaveValue(serverId);
  await expect(shown.getByLabel("Endpoint of Keyed server", { exact: true })).toHaveValue(
    new RegExp(`/mcp/${serverId}$`),
  );
  // Claude Code, the default, carries the secret in its command.
  const code = shown.getByRole("region", { name: "Claude Code config" });
  await expect(code).toContainText(`/mcp/${serverId} --header "Authorization: Bearer ${secret}"`);
  await expect(code).not.toContainText("<your API key>");
  await pick(shown, "Claude Desktop");
  const claude = shown.getByRole("region", { name: "Claude Desktop config" });
  await expect(claude).not.toContainText("<your API key>");
  const entry = Object.values((await configIn(claude)).mcpServers)[0] as { args: string[]; env: Record<string, string> };
  expect(entry.args.some((a) => a.endsWith(`/mcp/${serverId}`))).toBe(true);
  expect(Object.values(entry.env)).toContain(`Bearer ${secret}`);
  await expectAccessible(page);

  // Copy puts the secret on the clipboard.
  await shown.getByRole("button", { name: "Copy secret" }).click();
  await expect(shown.getByRole("button", { name: "Copied secret" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secret);

  // A stray Escape does not lose it; only Done closes it.
  await page.keyboard.press("Escape");
  await expect(shown).toBeVisible();
  await closeSecret(page);

  // And once closed it is gone, from the page and from a reload.
  await expect(page.getByLabel("Secret", { exact: true })).toHaveCount(0);
  await expect(page.getByText(secret)).toHaveCount(0);
  await expect(page.getByRole("listitem").filter({ hasText: "Desktop key" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { name: "API keys", exact: true })).toBeVisible();
  await expect(page.getByText(secret)).toHaveCount(0);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("the client picker groups its clients and remembers the last one picked", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const serverId = await createServer(page, "Picker server");
  const card = page.getByRole("listitem").filter({ hasText: "Picker server" });
  await card.getByRole("button", { name: "Connect a client to Picker server" }).click();

  const picker = card.getByRole("combobox", { name: "Client", exact: true });
  await expect(picker).toHaveText("Claude Code");
  await picker.click();
  const list = page.getByRole("listbox");
  const group = (name: string) => list.getByRole("group", { name, exact: true });
  const options = async (name: string) => group(name).getByRole("option").allInnerTexts();
  await expect(group("Coding assistants")).toBeVisible();
  expect(await options("Coding assistants")).toEqual([
    "Claude Code",
    "Cursor",
    "VS Code (GitHub Copilot)",
    "Windsurf",
    "Zed",
    "JetBrains AI Assistant",
    "OpenAI Codex CLI",
    "Gemini CLI",
  ]);
  expect(await options("Desktop apps")).toEqual(["Claude Desktop", "ChatGPT and the OpenAI API"]);
  expect(await options("Other")).toEqual(["curl", "Other client (JSON)"]);
  await expectAccessible(page);
  await page.keyboard.press("Escape");
  await expect(list).toHaveCount(0);

  await pick(card, "VS Code (GitHub Copilot)");
  const vscode = card.getByRole("region", { name: "VS Code (GitHub Copilot) config" });
  await expect(vscode).toContainText(".vscode/mcp.json");
  await expect(vscode).toContainText("VS Code asks for the key");
  const cfg = await configIn(vscode);
  const entry = Object.values(cfg.servers)[0] as {
    type: string;
    url: string;
    headers: { Authorization: string };
  };
  expect(entry.type).toBe("http");
  expect(entry.url).toMatch(new RegExp(`/mcp/${serverId}$`));
  // The key is prompted for, not written into the file.
  expect(entry.headers.Authorization).toBe("Bearer ${input:api-token}");
  expect(cfg.inputs).toEqual([{ type: "promptString", id: "api-token", description: "<your API key>", password: true }]);

  // The pick outlives the page.
  await page.reload();
  await card.getByRole("button", { name: "Connect a client to Picker server" }).click();
  await expect(card.getByRole("combobox", { name: "Client", exact: true })).toHaveText("VS Code (GitHub Copilot)");
  await expect(card.getByRole("region", { name: "VS Code (GitHub Copilot) config" })).toContainText(
    `/mcp/${serverId}`,
  );
});
