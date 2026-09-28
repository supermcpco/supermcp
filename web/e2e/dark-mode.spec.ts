import { test, expect, expectAccessible, createServer, createKey, installAdapter, openAccountMenu } from "./fixtures";
import type { Page } from "@playwright/test";

// The console follows the system's light or dark setting. Every screen
// here is drawn with a dark system and checked the way the light ones
// are, contrast included: a colour that only works on white shows up as
// grey on grey, or as a white card on a dark page.

test.use({ colorScheme: "dark" });

/** The page is drawn in its dark scheme, not merely told about it. */
async function expectDark(page: Page) {
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe("dark");
}

test("the sign-in and sign-up cards are dark on a dark system", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in", level: 1 })).toBeVisible();
  await expectDark(page);
  await expectAccessible(page);
  await page.getByRole("button", { name: "Create a workspace" }).click();
  await expect(page.getByRole("heading", { name: "Create your workspace", level: 1 })).toBeVisible();
  await expectAccessible(page);
});

test("the overview, the sidebar either way and the settings tabs are dark", async ({ page, workspace }) => {
  await expect(page.getByText(workspace.org)).toBeVisible();
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Set up your workspace" })).toBeVisible();
  await expectDark(page);
  await expectAccessible(page);

  await page.getByRole("button", { name: "Collapse sidebar" }).click();
  await expect(page.getByRole("complementary", { name: "Sidebar" })).toHaveAttribute("data-state", "collapsed");
  await expectAccessible(page);
  // The footer on a short window, with a tooltip out over the page, and
  // with the account menu open.
  await page.setViewportSize({ width: 1440, height: 600 });
  await page.getByRole("complementary", { name: "Sidebar" }).getByRole("button", { name: workspace.email }).hover();
  await expect(page.getByRole("tooltip", { name: workspace.email })).toBeVisible();
  await expectAccessible(page);
  await openAccountMenu(page, workspace.email);
  await expectAccessible(page);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("menu")).toHaveCount(0);
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.getByRole("button", { name: "Expand sidebar" }).click();
  await expect(page.getByRole("complementary", { name: "Sidebar" })).toHaveAttribute("data-state", "expanded");
  await openAccountMenu(page, workspace.email);
  await expectAccessible(page);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("menu")).toHaveCount(0);

  await page.goto("/settings");
  await expect(page.getByRole("tablist").first()).toBeVisible();
  await expectAccessible(page);

  await page.setViewportSize({ width: 900, height: 700 });
  await page.getByRole("button", { name: "Menu" }).click();
  await expect(page.getByRole("navigation", { name: "Menu" })).toBeVisible();
  await expectAccessible(page);
});

test("a create dialog, a toast, the connector page and a confirm dialog are dark", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/servers");
  await page.getByRole("button", { name: "Create server" }).click();
  const create = page.getByRole("dialog", { name: "New server" });
  await expect(create.getByLabel("Name")).toBeVisible();
  await expectDark(page);
  await expectAccessible(page);
  await page.keyboard.press("Escape");
  await expect(create).toHaveCount(0);

  await installAdapter(page);
  await expect(page.getByRole("status", { name: "Deutsche Bundesbank Statistics installed" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Deutsche Bundesbank Statistics", level: 1 })).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Remove", exact: true }).click();
  const confirm = page.getByRole("dialog", { name: "Delete Deutsche Bundesbank Statistics" });
  await expect(confirm).toBeVisible();
  await expectAccessible(page);
});

test("the activity tables are dark", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await installAdapter(page);
  const connectorId = (await (await page.request.get("/api/v1/connectors")).json())[0].id as string;
  const tool = await page.request.post(`/api/v1/connectors/${connectorId}/tools`, {
    data: {
      definition: JSON.stringify({
        name: "dark_echo",
        description: "Answers with a fixed text, so a call never leaves the instance.",
        input: { type: "object", properties: {} },
        operation: { kind: "static", value: "echo" },
      }),
    },
  });
  expect(tool.ok(), await tool.text()).toBeTruthy();
  const serverId = await createServer(page, "Dark server", [/Deutsche Bundesbank Statistics/]);
  const key = await createKey(page, "Dark key");
  const call = await request.post(`/mcp/${serverId}`, {
    headers: { "X-API-Key": key, Accept: "application/json, text/event-stream" },
    data: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "dark_echo", arguments: {} } },
  });
  expect(call.ok(), await call.text()).toBeTruthy();

  await page.goto("/activity");
  await expect(page.getByRole("table", { name: "Latest tool calls" }).getByRole("row")).toHaveCount(2);
  await expectDark(page);
  await expectAccessible(page);

  await page.getByRole("tab", { name: "Analytics" }).click();
  await expect(page.getByRole("tabpanel", { name: "Analytics" }).getByRole("combobox", { name: "Period" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Calls and errors" })).toBeVisible();
  await expectAccessible(page);
});
