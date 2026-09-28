import { test, expect, expectAccessible, createKey, createServer, installAdapter } from "./fixtures";
import type { Locator, Page } from "@playwright/test";

// A control that shows only an icon, or a word standing for a sentence,
// says the rest in a tooltip on hover and on keyboard focus. Every such
// tooltip is a real one to a screen reader (role "tooltip", named by its
// words), and a page with one open is as usable as without it.

/** Every tooltip on the page has words in it; at least one is open. */
async function expectTooltipsSaySomething(page: Page) {
  const tips = page.getByRole("tooltip");
  await expect(tips.first()).toBeVisible();
  const count = await tips.count();
  for (let i = 0; i < count; i++) await expect(tips.nth(i)).toHaveText(/\S/);
}

/** Moves focus with the Tab key, the way a keyboard user does, until it is on `target`. */
async function tabTo(page: Page, target: Locator) {
  await expect(async () => {
    await page.keyboard.press("Tab");
    await expect(target).toBeFocused({ timeout: 50 });
  }).toPass({ intervals: [0], timeout: 15_000 });
}

test("the endpoint's Copy button says what it copies, and a long endpoint shows whole", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await installAdapter(page);
  await createServer(page, "Tooltip server", [/Deutsche Bundesbank Statistics/]);

  const copy = page.getByRole("button", { name: "Copy endpoint of Tooltip server" });
  await copy.hover();
  const tip = page.getByRole("tooltip", { name: /copy/i });
  await expect(tip).toHaveText("Copy the endpoint of Tooltip server to the clipboard");
  // While it shows, the button is described by it.
  await expect(copy).toHaveAccessibleDescription("Copy the endpoint of Tooltip server to the clipboard");
  await expectTooltipsSaySomething(page);
  await expectAccessible(page);

  // On a narrow screen the address no longer fits its field; pointing at
  // the field shows all of it.
  await page.setViewportSize({ width: 360, height: 800 });
  const endpoint = page.getByLabel("Endpoint of Tooltip server", { exact: true });
  const url = await endpoint.inputValue();
  await endpoint.hover();
  await expect(page.getByRole("tooltip", { name: url, exact: true })).toBeVisible();
  await expectTooltipsSaySomething(page);
  await expectAccessible(page);
});

test("a new key's Copy button says what it copies, and never shows the secret", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const secret = await createKey(page, "Tooltip key");

  const shown = page.getByRole("dialog", { name: "Copy this key now" });
  await shown.getByRole("button", { name: "Copy secret" }).hover();
  const tip = page.getByRole("tooltip", { name: /copy/i });
  await expect(tip).toHaveText("Copy the secret to the clipboard");
  await expect(tip).not.toContainText(secret);
  await expectTooltipsSaySomething(page);
  await expectAccessible(page);
});

test("the help button on Approvals names itself on keyboard focus", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/approvals");
  await expect(page.getByRole("heading", { name: "Approvals", level: 1 })).toBeVisible();

  const about = page.getByRole("button", { name: "About approvals" });
  await tabTo(page, about);
  await expect(page.getByRole("tooltip", { name: "About approvals", exact: true })).toBeVisible();
  await expectTooltipsSaySomething(page);
  await expectAccessible(page);

  // Opening it still works from the keyboard, and the popover is titled the same.
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "About approvals" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "About approvals" })).toBeHidden();
});

test("a connector's help, a switched-off tool and a name too long for its card explain themselves", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  // Imported without its credential, under a name longer than a card.
  const name =
    "Allotment Register of the Municipal Gardens Association of the Greater City and all of its Surrounding Districts";
  await page.goto("/connectors/import");
  await page.getByRole("radio", { name: "OpenAPI", exact: true }).check();
  await page.getByLabel("OpenAPI document").fill(
    JSON.stringify({
      openapi: "3.1.0",
      info: { title: "Allotment Register", version: "1.0.0" },
      servers: [{ url: "https://allotments.example.test/api" }],
      security: [{ apiKey: [] }],
      components: { securitySchemes: { apiKey: { type: "apiKey", in: "header", name: "X-Allotment-Key" } } },
      paths: {
        "/plots": {
          get: { operationId: "listPlots", summary: "List the plots", responses: { "200": { description: "The plots" } } },
        },
      },
    }),
  );
  await page.getByLabel("Connector name").fill(name);
  await page.getByLabel("Tool name prefix").fill("allotments");
  await page.getByRole("button", { name: "Preview import" }).click();
  await expect(page.getByRole("region", { name: "What this would create" })).toBeVisible();
  await page.getByRole("button", { name: "Import connector" }).click();
  await expect(page.getByRole("heading", { name, level: 1 })).toBeVisible();

  // The connector's page: the "?" on its tools names itself.
  await page.getByRole("tablist", { name: "Connector" }).getByRole("tab", { name: "Tools" }).click();
  await page.getByRole("button", { name: "About tools" }).hover();
  await expect(page.getByRole("tooltip", { name: "About tools", exact: true })).toBeVisible();
  await expectTooltipsSaySomething(page);
  await expectAccessible(page);

  // A tool switched off is marked "off", and the mark says what that means.
  const switched = page.waitForResponse(
    (r) => /\/api\/v1\/tools\/[^/]+$/.test(r.url()) && r.request().method() !== "GET",
  );
  // The switch follows what the server stored, so it is clicked, not unchecked.
  const offered = page.getByRole("switch", { name: /^Offered / });
  await offered.click();
  expect((await switched).ok(), "switching the tool off failed").toBeTruthy();
  await expect(offered).not.toBeChecked();
  await page.getByText("off", { exact: true }).hover();
  await expect(page.getByRole("tooltip", { name: /not offered to clients/ })).toBeVisible();
  await expectTooltipsSaySomething(page);
  await expectAccessible(page);

  // The list: the name is cut off on a narrow screen and shown whole on
  // hover.
  await page.setViewportSize({ width: 480, height: 800 });
  await page.goto("/connectors");
  await page.getByRole("link", { name, exact: true }).hover();
  await expect(page.getByRole("tooltip", { name, exact: true })).toBeVisible();
  await expectTooltipsSaySomething(page);
  await expectAccessible(page);
});
