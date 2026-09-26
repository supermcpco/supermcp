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
  const menu = page.getByRole("button", { name: "Menu" });
  await expect(menu).toBeVisible();
  await expect(nav).toBeHidden();
  await expect(page.getByText(workspace.org)).toBeHidden();

  await menu.click();
  await expect(nav).toBeVisible();
  const drawer = page.getByRole("dialog", { name: "Menu" });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText(workspace.org)).toBeVisible();
  await expectAccessible(page);

  // Escape puts it away and hands the keyboard back to the button.
  await page.keyboard.press("Escape");
  await expect(nav).toBeHidden();
  await expect(menu).toBeFocused();

  // Picking a screen closes the drawer on the way there.
  await menu.click();
  await nav.getByRole("link", { name: "Catalog" }).click();
  await expect(page.getByRole("heading", { name: "Catalog", level: 1 })).toBeVisible();
  await expect(nav).toBeHidden();
});
