import { test, expect, expectAccessible } from "./fixtures";
import type { Locator, Page } from "@playwright/test";

// A fresh workspace has nothing on these screens. What it sees there is
// a card, the size of its two lines, saying so; the way to add the first
// one is the button in the screen's header, and the card does not repeat
// it.

/** The empty card hugs its headline and its sentence. */
async function expectCompact(empty: Locator) {
  const box = await empty.boundingBox();
  expect(box, "the empty state is laid out").not.toBeNull();
  expect(box!.height).toBeLessThan(120);
}

/** The header's button is the only one on the screen with its name. */
async function expectOnlyInHeader(page: Page, empty: Locator, role: "button" | "link", name: string) {
  await expect(empty.getByRole(role)).toHaveCount(0);
  await expect(page.getByRole(role, { name, exact: true })).toHaveCount(1);
}

test("empty connectors, servers and keys screens are one small card, and their header holds the first action", async ({
  page,
  workspace,
}) => {
  expect(workspace.email).toBeTruthy();

  await test.step("connectors lead to the catalog from the header", async () => {
    await page.goto("/connectors");
    const empty = page.getByRole("region", { name: "No connectors yet" });
    await expect(empty).toBeVisible();
    await expectCompact(empty);
    await expectOnlyInHeader(page, empty, "link", "Browse catalog");
    await expectAccessible(page);
    await page.getByRole("link", { name: "Browse catalog", exact: true }).click();
    await expect(page).toHaveURL(/\/catalog$/);
    await expect(page.getByRole("heading", { name: "Catalog", exact: true })).toBeVisible();
  });

  await test.step("servers open the form for the first one from the header", async () => {
    await page.goto("/servers");
    const empty = page.getByRole("region", { name: "No MCP servers yet" });
    await expect(empty).toBeVisible();
    await expectCompact(empty);
    await expectOnlyInHeader(page, empty, "button", "Create server");
    await expectAccessible(page);
    await page.getByRole("button", { name: "Create server" }).click();
    const dialog = page.getByRole("dialog", { name: "New server" });
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(empty).toBeVisible();
  });

  await test.step("keys open the form for the first one from the header", async () => {
    await page.goto("/api-keys");
    const empty = page.getByRole("region", { name: "No API keys yet" });
    await expect(empty).toBeVisible();
    await expectCompact(empty);
    await expectOnlyInHeader(page, empty, "button", "Create key");
    await expectAccessible(page);
    await page.getByRole("button", { name: "Create key" }).click();
    const dialog = page.getByRole("dialog", { name: "New API key" });
    await expect(dialog).toBeVisible();
    // Its "For" choice is named by its label alone, not by every option in it.
    await expect(dialog.getByRole("combobox", { name: "For", exact: true })).toHaveValue("client");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(empty).toBeVisible();
  });
});

test("an empty settings list is one muted line under the header that adds to it", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  await page.goto("/settings/service-accounts");
  await expect(page.getByText("No service accounts yet.")).toBeVisible();
  await expect(page.getByRole("button", { name: "New service account" })).toHaveCount(1);
  await expectAccessible(page);

  await page.goto("/settings/dlp");
  await expect(page.getByText("No rules yet, so nothing is inspected and nothing is masked.")).toBeVisible();
  await expect(page.getByRole("button", { name: "New rule" })).toHaveCount(1);

  await page.goto("/settings/sso");
  await expect(page.getByText("No providers yet.")).toBeVisible();
  await expect(page.getByText("No SAML providers yet.")).toBeVisible();
  await expect(page.getByRole("button", { name: "New OpenID Connect provider" })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "New SAML provider" })).toHaveCount(1);

  await page.goto("/approvals");
  const rules = page.getByRole("region", { name: "No rules yet" });
  await expect(rules).toBeVisible();
  await expectCompact(rules);
  await expectOnlyInHeader(page, rules, "button", "Add rule");
});
