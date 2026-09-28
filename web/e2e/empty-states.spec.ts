import { test, expect, expectAccessible } from "./fixtures";

// A fresh workspace has nothing on these screens. What it sees there is
// the headline saying so and, in the same card, the way to add the first
// one: the thing a person came to the screen to do.

test("empty connectors, servers and keys screens each offer their first action", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  await test.step("connectors lead to the catalog", async () => {
    await page.goto("/connectors");
    const empty = page.getByRole("region", { name: "No connectors yet" });
    await expect(empty).toBeVisible();
    await expectAccessible(page);
    await empty.getByRole("link", { name: "Browse catalog" }).click();
    await expect(page).toHaveURL(/\/catalog$/);
    await expect(page.getByRole("heading", { name: "Catalog", exact: true })).toBeVisible();
  });

  await test.step("servers open the form for the first one", async () => {
    await page.goto("/servers");
    const empty = page.getByRole("region", { name: "No MCP servers yet" });
    await expect(empty).toBeVisible();
    await expectAccessible(page);
    await empty.getByRole("button", { name: "Create server" }).click();
    const dialog = page.getByRole("dialog", { name: "New server" });
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(empty).toBeVisible();
  });

  await test.step("keys open the form for the first one", async () => {
    await page.goto("/api-keys");
    const empty = page.getByRole("region", { name: "No API keys yet" });
    await expect(empty).toBeVisible();
    await expectAccessible(page);
    await empty.getByRole("button", { name: "Create key" }).click();
    const dialog = page.getByRole("dialog", { name: "New API key" });
    await expect(dialog).toBeVisible();
    // Its "For" choice is named by its label alone, not by every option in it.
    await expect(dialog.getByRole("combobox", { name: "For", exact: true })).toHaveValue("client");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(empty).toBeVisible();
  });
});
