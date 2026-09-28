import { test, expect, expectAccessible } from "./fixtures";

// The create forms open in a dialog. What matters to the person using
// one is that leaving it leaves nothing behind, that they land back on
// the button they started from, and that a refusal is read out where
// they are looking.

test("a create dialog closes on Escape without creating and returns focus", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/service-accounts");
  await expect(page.getByText("No service accounts yet.")).toBeVisible();

  const opener = page.getByRole("button", { name: "New service account" }).first();
  await opener.click();
  const dialog = page.getByRole("dialog", { name: "New service account" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel("Name")).toBeFocused();
  await expectAccessible(page);

  await dialog.getByLabel("Name").fill("Never created");
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(opener).toBeFocused();
  await expect(page.getByText("Never created")).toHaveCount(0);
  await expect(page.getByText("No service accounts yet.")).toBeVisible();

  // Nothing reached the server either.
  const accounts = await (await page.request.get("/api/v1/service-accounts")).json();
  expect(accounts.accounts ?? []).toEqual([]);

  // Cancel does the same, from the button in the empty state this time.
  const fromEmpty = page.getByRole("button", { name: "New service account" }).last();
  await fromEmpty.click();
  await dialog.getByLabel("Name").fill("Never created either");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
  await expect(fromEmpty).toBeFocused();
  await expect(page.getByText("No service accounts yet.")).toBeVisible();
});

test("an approval rule is added from its dialog, and removing it says so", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/approvals");
  await expect(page.getByText("No rules, so no call is ever held.")).toBeVisible();

  await page.getByRole("button", { name: "New rule" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add a rule" });
  await dialog.getByLabel("Which calls").selectOption("tool");
  await dialog.getByLabel("What it is for").fill("Hold the exchange rates");
  // A rule for one tool needs the tool's name before it can be sent.
  await expect(dialog.getByRole("button", { name: "Add the rule" })).toBeDisabled();
  await dialog.getByLabel("Tool name").fill("exchange_rates");
  await expectAccessible(page);
  await dialog.getByRole("button", { name: "Add the rule" }).click();

  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Rule Hold the exchange rates added", exact: true })).toBeVisible();
  const rule = page.getByRole("listitem").filter({ hasText: "Hold the exchange rates" });
  await expect(rule.getByText("exchange_rates", { exact: true })).toBeVisible();

  await rule.getByRole("button", { name: "Delete Hold the exchange rates" }).click();
  await expect(page.getByRole("heading", { name: "Rule Hold the exchange rates deleted", exact: true })).toBeVisible();
  await expect(page.getByText("No rules, so no call is ever held.")).toBeVisible();
});
