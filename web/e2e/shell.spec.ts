import { test, expect, expectAccessible } from "./fixtures";

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
  // is there, the last one included.
  await expect(nav.getByRole("link", { name: "Service accounts" })).toBeVisible();
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
  await nav.getByRole("link", { name: "Service accounts" }).click();
  await expect(page.getByRole("heading", { name: "Service accounts", level: 1 })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeInViewport();
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
  await expectAccessible(page);

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
