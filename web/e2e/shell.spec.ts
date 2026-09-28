import { test as anonymous } from "@playwright/test";
import { test, expect, expectAccessible, installAdapter, signUp } from "./fixtures";

// The frame every screen sits in: where the screens are listed, what a
// person sees for an address that leads nowhere, and how the list is
// reached on a screen too narrow to keep it beside the content.

test("the sidebar lists the screens under Build, Operate and Settings", async ({ page, workspace }) => {
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav).toBeVisible();
  for (const group of ["Build", "Operate", "Settings"]) {
    await expect(nav.getByRole("heading", { name: group, exact: true })).toBeVisible();
  }
  // The owner of a new workspace holds every permission, so every screen
  // is there. Settings is one item: its parts are tabs on its own screen,
  // not entries here.
  await expect(nav.getByRole("link", { name: "Settings", exact: true })).toBeVisible();
  for (const tab of ["Members", "Roles", "Audit trail", "Single sign-on", "Service accounts", "Status"]) {
    await expect(nav.getByRole("link", { name: tab })).toHaveCount(0);
  }
  // Calls and analytics are one entry, Activity, with a tab each.
  await expect(nav.getByRole("link", { name: "Activity" })).toBeVisible();
  await expect(nav.getByRole("link", { name: /^(Tool calls|Analytics)$/ })).toHaveCount(0);
  await expect(page.getByText(workspace.email)).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
  await expectAccessible(page);

  // Importing is something done to connectors, so it lives on their screen.
  await expect(nav.getByRole("link", { name: "Import an API" })).toHaveCount(0);
  await nav.getByRole("link", { name: "Connectors" }).click();
  await expect(page.getByRole("heading", { name: "Connectors", level: 1 })).toBeVisible();
  await page.getByRole("link", { name: "Import an API" }).click();
  await expect(page.getByRole("heading", { name: "Import an API description" })).toBeVisible();
});

test("the sign-out button stays in view on a short window", async ({ page, workspace }) => {
  await page.setViewportSize({ width: 1280, height: 420 });
  await expect(page.getByText(workspace.email)).toBeInViewport();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeInViewport();
  const nav = page.getByRole("navigation", { name: "Primary" });
  await nav.getByRole("link", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeInViewport();
});

test("the sidebar footer keeps the email, sign out and the toggle in view at a short window, expanded and collapsed", async ({
  page,
  workspace,
}) => {
  await page.setViewportSize({ width: 1440, height: 600 });
  const sidebar = page.getByRole("complementary", { name: "Sidebar" });
  const nav = page.getByRole("navigation", { name: "Primary" });
  const email = sidebar.getByText(workspace.email);
  const signOut = sidebar.getByRole("button", { name: "Sign out" });
  await expect(email).toBeInViewport();
  await expect(signOut).toBeInViewport();
  await expect(sidebar.getByRole("button", { name: "Collapse sidebar" })).toBeInViewport();
  // Sign out is an entry like the screens above it, and starts where they do.
  const lineUp = async () => {
    const entry = await nav.getByRole("link", { name: "Settings", exact: true }).boundingBox();
    const out = await signOut.boundingBox();
    expect(out?.x).toBe(entry?.x);
  };
  await lineUp();

  await sidebar.getByRole("button", { name: "Collapse sidebar" }).click();
  await expect(sidebar).toHaveAttribute("data-state", "collapsed");
  await expect.poll(async () => (await sidebar.boundingBox())?.width).toBeLessThan(80);
  // The address has no room on the rail; the way out and the way back do.
  await expect(email).toBeHidden();
  await expect(signOut).toBeInViewport();
  await expect(sidebar.getByRole("button", { name: "Expand sidebar" })).toBeInViewport();
  await lineUp();
});

anonymous("a workspace name too long for the sidebar is shown whole in a tooltip", async ({ page }) => {
  const unique = `${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const org = `Northwind Traders International Holdings ${unique}`;
  await signUp(page, { email: `long-name-${unique}@example.test`, password: "Correct Horse Battery 9", org });
  await page.getByRole("complementary", { name: "Sidebar" }).getByText(org).hover();
  await expect(page.getByRole("tooltip", { name: org })).toBeVisible();
});

test("an unknown adapter says so and leads back to the catalog", async ({ page, workspace }) => {
  await page.goto("/catalog/no-such-adapter");
  await expect(page.getByRole("heading", { name: "Adapter not found" })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("link", { name: "Back to the catalog" }).click();
  await expect(page.getByRole("heading", { name: "Catalog", level: 1 })).toBeVisible();
});

test("an unknown connector says so and leads back to the connectors", async ({ page, workspace }) => {
  await page.goto("/connectors/no-such-connector/tools");
  await expect(page.getByRole("heading", { name: "Connector not found" })).toBeVisible();
  await page.getByRole("link", { name: "Back to connectors" }).click();
  await expect(page.getByRole("heading", { name: "Connectors", level: 1 })).toBeVisible();
});

test("on a narrow window the navigation opens from the Menu button", async ({ page, workspace }) => {
  await page.setViewportSize({ width: 900, height: 700 });
  const nav = page.getByRole("navigation", { name: "Primary" });
  const sheet = page.getByRole("navigation", { name: "Menu" });
  const menu = page.getByRole("button", { name: "Menu" });
  await expect(menu).toBeVisible();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  // The sidebar is not beside the content at this width: it is a sheet,
  // put away and out of reach until the button brings it out.
  await expect(page.getByRole("complementary", { name: "Sidebar" })).toHaveCount(0);
  await expect(sheet).toBeHidden();
  await expect(nav).toBeHidden();
  // The button is only an icon; its name is in a tooltip as well.
  await menu.hover();
  await expect(page.getByRole("tooltip", { name: "Menu" })).toBeVisible();

  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await expect(sheet).toBeVisible();
  await expect(nav).toBeVisible();
  await expect(sheet.getByText(workspace.org)).toBeVisible();
  await expect(sheet.getByText(workspace.email)).toBeVisible();
  for (const group of ["Build", "Operate", "Settings"]) {
    await expect(nav.getByRole("heading", { name: group, exact: true })).toBeVisible();
  }
  // Only the wide sidebar collapses; the sheet has no use for that toggle.
  await expect(sheet.getByRole("button", { name: /sidebar/ })).toHaveCount(0);
  await expectAccessible(page);

  // Escape puts it away and hands the keyboard back to the button.
  await page.keyboard.press("Escape");
  await expect(nav).toBeHidden();
  await expect(menu).toBeFocused();

  // So does its own close button.
  await menu.click();
  await sheet.getByRole("button", { name: "Close navigation" }).click();
  await expect(nav).toBeHidden();

  // Picking a screen closes the sheet on the way there.
  await menu.click();
  await nav.getByRole("link", { name: "Catalog" }).click();
  await expect(page.getByRole("heading", { name: "Catalog", level: 1 })).toBeVisible();
  await expect(nav).toBeHidden();

  // A sheet left open while the window is widened past the breakpoint is
  // put away, so narrowing the window again does not bring it back.
  await menu.click();
  await expect(sheet).toBeVisible();
  await page.setViewportSize({ width: 1280, height: 700 });
  await expect(page.getByRole("complementary", { name: "Sidebar" })).toBeVisible();
  await expect(menu).toHaveCount(0);
  await page.setViewportSize({ width: 900, height: 700 });
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await expect(sheet).toBeHidden();
  await expect(nav).toBeHidden();
});

test("the sidebar collapses to icons and remembers it after a reload", async ({ page, workspace }) => {
  const sidebar = page.getByRole("complementary", { name: "Sidebar" });
  const nav = page.getByRole("navigation", { name: "Primary" });
  const collapse = page.getByRole("button", { name: "Collapse sidebar" });
  const expand = page.getByRole("button", { name: "Expand sidebar" });
  const wide = (await sidebar.boundingBox())?.width ?? 0;
  expect(wide).toBeGreaterThan(200);
  await expect(collapse).toHaveAttribute("aria-expanded", "true");

  await collapse.click();
  await expect(expand).toHaveAttribute("aria-expanded", "false");
  await expect(sidebar).toHaveAttribute("data-state", "collapsed");
  await expect.poll(async () => (await sidebar.boundingBox())?.width).toBeLessThan(80);
  // The address has no room on the rail; the screens are still there,
  // under the same names, and still lead somewhere.
  await expect(page.getByText(workspace.email)).toBeHidden();
  await nav.getByRole("link", { name: "Connectors" }).click();
  await expect(page.getByRole("heading", { name: "Connectors", level: 1 })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Connectors" })).toHaveAttribute("aria-current", "page");
  // On the rail each entry names itself in a tooltip, one a screen reader
  // knows for a tooltip.
  await nav.getByRole("link", { name: "Catalog" }).hover();
  await expect(page.getByRole("tooltip", { name: "Catalog" })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: "Sign out" }).hover();
  await expect(page.getByRole("tooltip", { name: "Sign out" })).toBeVisible();
  // The toggle is only an icon either way, so it names itself too.
  await expand.hover();
  await expect(page.getByRole("tooltip", { name: "Expand sidebar" })).toBeVisible();
  // Somebody on a keyboard gets the same names, one Tab at a time.
  await page.mouse.move(700, 400);
  await nav.getByRole("link", { name: "Settings", exact: true }).focus();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Sign out" })).toBeFocused();
  await expect(page.getByRole("tooltip", { name: "Sign out" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(expand).toBeFocused();
  await expect(page.getByRole("tooltip", { name: "Expand sidebar" })).toBeVisible();

  await page.reload();
  await expect(page.getByRole("heading", { name: "Connectors", level: 1 })).toBeVisible();
  await expect(expand).toBeVisible();
  await expect(sidebar).toHaveAttribute("data-state", "collapsed");

  await expand.click();
  await expect(collapse).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText(workspace.email)).toBeVisible();
  await expect.poll(async () => (await sidebar.boundingBox())?.width).toBeGreaterThan(200);
  await page.reload();
  await expect(collapse).toBeVisible();
  await expect(page.getByText(workspace.email)).toBeVisible();
});

test("the current screen is marked in the sidebar, the overview only on itself", async ({ page, workspace }) => {
  const nav = page.getByRole("navigation", { name: "Primary" });
  await page.goto("/");
  await expect(nav.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  await nav.getByRole("link", { name: "Connectors" }).click();
  await expect(page.getByRole("heading", { name: "Connectors", level: 1 })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Connectors" })).toHaveAttribute("aria-current", "page");
  await expect(nav.getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current", "page");
  // A page beneath a screen keeps that screen current.
  await page.goto("/connectors/no-such-connector/tools");
  await expect(page.getByRole("heading", { name: "Connector not found" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Connectors" })).toHaveAttribute("aria-current", "page");
  await expect(nav.getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current", "page");
});

test("no screen uses a Kumo variant or prop that Kumo has deprecated", async ({ page, workspace }) => {
  // Kumo says so with a console warning on every render; a screen that
  // triggers one is using an API the next Kumo release may remove.
  const warnings: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "warning" || m.type() === "error") warnings.push(m.text());
  });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
  await expect(page.getByText(workspace.org)).toBeVisible();
  await page.goto("/settings");
  await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();
  await installAdapter(page);
  await expect(page.getByRole("heading", { name: "Deutsche Bundesbank Statistics", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Status", level: 2 })).toBeVisible();
  expect(warnings.filter((w) => /deprecated/i.test(w) || w.startsWith("[Kumo Input]"))).toEqual([]);
});

anonymous("the sign-in card names its inputs the way Kumo checks for", async ({ page }) => {
  // Kumo cannot see a <label> wrapped around its input, and warns on every
  // render unless the input is named through a prop it reads. The names
  // stay what the visible labels say.
  const warnings: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "warning" || m.type() === "error") warnings.push(m.text());
  });
  await page.goto("/login");
  const signIn = page.getByRole("form", { name: "Sign in" });
  await expect(signIn.getByRole("textbox", { name: "Email", exact: true })).toBeVisible();
  await expect(signIn.getByLabel("Password", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Create a workspace" }).click();
  const signUp = page.getByRole("form", { name: "Create your workspace" });
  await expect(signUp.getByRole("textbox", { name: "Email", exact: true })).toBeVisible();
  await expect(signUp.getByLabel("Password", { exact: true })).toBeVisible();
  await expect(signUp.getByRole("textbox", { name: "Workspace name", exact: true })).toBeVisible();
  await expectAccessible(page);
  expect(warnings.filter((w) => w.startsWith("[Kumo Input]"))).toEqual([]);
});

test("a confirmation is announced as a status, not a dialog", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await installAdapter(page);
  await expect(page.getByRole("status", { name: "Deutsche Bundesbank Statistics installed" })).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
  await expectAccessible(page);
});
