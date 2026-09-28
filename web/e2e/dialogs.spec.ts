import { test, expect, expectAccessible } from "./fixtures";

// The create forms open in a dialog. What matters to the person using
// one is that leaving it leaves nothing behind, that they land back on
// the button they started from, and that a refusal is read out where
// they are looking.

test("a create dialog closes on Escape without creating and returns focus", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/service-accounts");
  await expect(page.getByRole("tab", { name: "Service accounts", exact: true })).toHaveAttribute("aria-selected", "true");
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

test("an approval rule is added from its dialog", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/approvals");
  await expect(page.getByRole("heading", { name: "No rules yet", exact: true })).toBeVisible();

  // The longer explanation is one press away, and Escape puts it back.
  const about = page.getByRole("button", { name: "About approvals" });
  await about.click();
  const explained = page.getByRole("dialog", { name: "About approvals" });
  await expect(explained.getByText("Without one, nothing is ever held.", { exact: false })).toBeVisible();
  await expectAccessible(page);
  await page.keyboard.press("Escape");
  await expect(explained).toHaveCount(0);
  await expect(about).toBeFocused();

  await page.getByRole("button", { name: "Add rule", exact: true }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add a rule" });
  await dialog.getByLabel("Which calls").selectOption("tool");
  await dialog.getByLabel("What it is for").fill("Hold the exchange rates");
  // A rule for one tool needs the tool's name before it can be sent.
  await expect(dialog.getByRole("button", { name: "Add rule", exact: true })).toBeDisabled();
  await dialog.getByLabel("Tool name").fill("exchange_rates");
  await expectAccessible(page);
  await dialog.getByRole("button", { name: "Add rule", exact: true }).click();

  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Rule Hold the exchange rates added", exact: true })).toBeVisible();
  const rule = page.getByRole("listitem").filter({ hasText: "Hold the exchange rates" });
  await expect(rule.getByText("exchange_rates", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No rules yet", exact: true })).toHaveCount(0);
});

test("an approval rule is only removed after confirming", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const name = "Hold whatever writes";
  await page.goto("/approvals");
  await page.getByRole("button", { name: "Add rule", exact: true }).first().click();
  const add = page.getByRole("dialog", { name: "Add a rule" });
  await add.getByLabel("What it is for").fill(name);
  await add.getByRole("button", { name: "Add rule", exact: true }).click();
  await expect(add).toHaveCount(0);
  const rule = page.getByRole("listitem").filter({ hasText: name });
  await expect(rule).toBeVisible();
  const stored = async () =>
    (((await (await page.request.get("/api/v1/approval-policies")).json()).policies ?? []) as { name: string }[]).map(
      (p) => p.name,
    );

  // The first press only asks.
  await rule.getByRole("button", { name: `Delete ${name}` }).click();
  const confirm = page.getByRole("dialog", { name: `Delete ${name}` });
  await expect(confirm).toBeVisible();
  const remove = confirm.getByRole("button", { name: "Delete rule" });
  await expect(remove).toBeDisabled();
  await expectAccessible(page);

  // Changing one's mind deletes nothing.
  await confirm.getByRole("button", { name: "Cancel" }).click();
  await expect(confirm).toHaveCount(0);
  await expect(rule).toBeVisible();
  expect(await stored()).toEqual([name]);

  // Typing the rule's name is the confirmation.
  await rule.getByRole("button", { name: `Delete ${name}` }).click();
  await confirm.getByRole("textbox", { name: `Type ${name} to confirm deletion` }).fill(name);
  const deleted = page.waitForResponse(
    (r) => /\/api\/v1\/approval-policies\/[^/]+$/.test(r.url()) && r.request().method() === "DELETE",
  );
  await remove.click();
  expect((await deleted).ok()).toBeTruthy();

  await expect(confirm).toHaveCount(0);
  await expect(page.getByRole("heading", { name: `Rule ${name} deleted`, exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "No rules yet", exact: true })).toBeVisible();
  expect(await stored()).toEqual([]);
});
