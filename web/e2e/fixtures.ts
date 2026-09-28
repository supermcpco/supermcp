import { test as base, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

// A workspace per test file, created through the real sign-up form. The
// alternative, seeding the database, would test a state the product can
// never actually be in.
export interface Workspace {
  email: string;
  password: string;
  org: string;
}

export const test = base.extend<{ workspace: Workspace }>({
  workspace: async ({ page }, use, testInfo) => {
    const unique = `${Date.now()}-${testInfo.workerIndex}-${Math.floor(Math.random() * 1e6)}`;
    const workspace: Workspace = {
      email: `browser-${unique}@example.test`,
      password: "Correct Horse Battery 9",
      org: `Browser ${unique}`,
    };
    await signUp(page, workspace);
    await use(workspace);
  },
});

export { expect };

/** Creates an account through the form a first visitor sees. */
export async function signUp(page: Page, w: Workspace) {
  await page.goto("/login");
  await page.getByRole("button", { name: "Create a workspace" }).click();
  await page.getByLabel("Email").fill(w.email);
  await page.getByLabel("Password").fill(w.password);
  await page.getByLabel("Workspace name").fill(w.org);
  await page.getByRole("button", { name: "Create workspace", exact: true }).click();
  // The workspace name in the sidebar only appears for a session.
  await expect(page.getByText(w.org, { exact: false })).toBeVisible();
}

/**
 * Opens the menu behind the person's button at the foot of the sidebar,
 * the one named by their address, and returns it.
 */
export async function openAccountMenu(page: Page, email: string) {
  await page.getByRole("complementary", { name: "Sidebar" }).getByRole("button", { name: email }).click();
  const menu = page.getByRole("menu");
  await expect(menu).toBeVisible();
  return menu;
}

/** Signs out through the sidebar's account menu, the way a person does. */
export async function signOutFromMenu(page: Page, email: string) {
  const menu = await openAccountMenu(page, email);
  await menu.getByRole("menuitem", { name: "Sign out" }).click();
}

/** Signs in an existing account. */
export async function signIn(page: Page, w: Workspace) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(w.email);
  await page.getByLabel("Password").fill(w.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByText(w.org, { exact: false })).toBeVisible();
}

/**
 * Fails on the accessibility rules that stop someone using a page at all:
 * unusable contrast, controls with no name, a form field with no label.
 * Best-practice rules are left out so the check stays actionable.
 */
export async function expectAccessible(page: Page) {
  // Measured at rest: a toast fading behind the next one is half its own
  // colour for a quarter of a second, and axe would read that as a fault.
  // Endless animations (a spinner) never finish, so they are not waited on.
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((a) => a.effect?.getComputedTiming().endTime !== Infinity)
        .map((a) => a.finished.catch(() => undefined)),
    ),
  );
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(
    serious.map((v) => `${v.id}: ${v.help} (${v.nodes.length} places, e.g. ${v.nodes[0]?.target.join(" ")})`),
    "the page has accessibility faults that would stop someone using it",
  ).toEqual([]);
}

/** Installs a keyless adapter from its catalog page, the way a person does. */
export async function installAdapter(page: Page, slug = "bundesbank") {
  await page.goto(`/catalog/${slug}`);
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);
}

/**
 * Creates an MCP server through the "New server" dialog, attaching the
 * connectors named, and returns its id, read from the endpoint it shows.
 */
export async function createServer(page: Page, name: string, connectors: (string | RegExp)[] = []): Promise<string> {
  await page.goto("/servers");
  await expect(page.getByRole("heading", { name: "MCP servers", exact: true })).toBeVisible();
  // The empty screen offers the button twice, in the header and in the card.
  await page.getByRole("button", { name: "Create server" }).first().click();
  const dialog = page.getByRole("dialog", { name: "New server" });
  await dialog.getByLabel("Name").fill(name);
  for (const c of connectors) await dialog.getByRole("checkbox", { name: c }).check();
  await dialog.getByRole("button", { name: "Create server" }).click();
  await expect(dialog).toBeHidden();
  const endpoint = await page.getByLabel(`Endpoint of ${name}`, { exact: true }).inputValue();
  expect(endpoint).toContain("/mcp/");
  return endpoint.trim().split("/mcp/")[1];
}

/**
 * Creates an API key through the "Create key" dialog and returns its
 * secret, read from the dialog that shows it once. That dialog is left
 * open; `closeSecret` puts it away.
 */
export async function createKey(page: Page, name: string): Promise<string> {
  await page.goto("/api-keys");
  await expect(page.getByRole("heading", { name: "API keys", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Create key" }).first().click();
  const form = page.getByRole("dialog", { name: "New API key" });
  await form.getByLabel("Name").fill(name);
  await form.getByRole("button", { name: "Create key" }).click();
  const shown = page.getByRole("dialog", { name: "Copy this key now" });
  await expect(shown).toBeVisible();
  const secret = await shown.getByLabel("Secret", { exact: true }).inputValue();
  expect(secret).toMatch(/^smk_/);
  return secret;
}

/** Closes the dialog a secret is shown in, the only way it closes. */
export async function closeSecret(page: Page) {
  const shown = page.getByRole("dialog", { name: "Copy this key now" });
  await shown.getByRole("button", { name: "Done" }).click();
  await expect(shown).toBeHidden();
}
