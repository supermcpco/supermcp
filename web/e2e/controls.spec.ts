import type { Locator, Page } from "@playwright/test";
import { test, expect, expectAccessible, createKey } from "./fixtures";

// The form controls are Kumo's, and a field beside its button is the
// button's height: the screens once had native fields a few pixels short
// of the Kumo button next to them. Measured in a browser, because only a
// browser lays them out.

test.use({ viewport: { width: 1440, height: 900 } });

/** Waits for opening animations to end, so a dialog is measured at full size. */
async function settle(page: Page) {
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((a) => a.effect?.getComputedTiming().endTime !== Infinity)
        .map((a) => a.finished.catch(() => undefined)),
    ),
  );
}

async function expectSameHeight(page: Page, field: Locator, button: Locator) {
  await expect(field).toBeVisible();
  await expect(button).toBeVisible();
  await settle(page);
  const a = await field.boundingBox();
  const b = await button.boundingBox();
  expect(a, "the field has no box").not.toBeNull();
  expect(b, "the button has no box").not.toBeNull();
  expect(Math.abs((a?.height ?? 0) - (b?.height ?? 0)), `field ${a?.height}px, button ${b?.height}px`).toBeLessThanOrEqual(1);
  // Side by side, too: the same height is no use if one sits lower.
  expect(Math.abs((a?.y ?? 0) - (b?.y ?? 0)), `field at ${a?.y}px, button at ${b?.y}px`).toBeLessThanOrEqual(1);
}

test("a field and the button beside it are the same height", async ({ page, workspace }) => {
  // API keys: the secret, shown once, and the button that copies it.
  await createKey(page, "Height key");
  const shown = page.getByRole("dialog", { name: "Copy this key now" });
  await expectSameHeight(page, shown.getByLabel("Secret", { exact: true }), shown.getByRole("button", { name: "Copy secret" }));
  await shown.getByRole("button", { name: "Done" }).click();
  await expect(shown).toBeHidden();

  // Members: a member's role and the buttons in the same row.
  await page.goto("/settings/members");
  const self = page.getByRole("row").filter({ hasText: workspace.email });
  await expectSameHeight(page, self.getByRole("combobox"), self.getByRole("button", { name: /^Deactivate/ }));

  // Retention: the days and Save; the hold's date and Hold.
  await page.goto("/settings/audit/retention");
  await expectSameHeight(page, page.getByLabel("Days"), page.getByRole("button", { name: "Save" }));
  await expectSameHeight(page, page.getByLabel("From"), page.getByRole("button", { name: "Hold" }));
  await expectSameHeight(page, page.getByLabel("Why"), page.getByRole("button", { name: "Release" }));
});

test.describe("on a wide screen", () => {
  test.use({ viewport: { width: 1920, height: 1080 } });

  test("the capture level is a form, capped, with its choices stacked", async ({ page, workspace }) => {
    expect(workspace.email).toBeTruthy();
    await page.goto("/settings/audit/retention");
    await expect(page.getByRole("heading", { name: "What tool calls record" })).toBeVisible();
    const group = page.getByRole("radiogroup");
    const choices = group.getByRole("radio");
    await expect(choices).toHaveCount(4);
    await expect(group.getByRole("radio", { name: /^Shapes/ })).toBeChecked();
    const box = await group.boundingBox();
    expect(box?.width ?? Infinity, `the group is ${box?.width}px wide`).toBeLessThanOrEqual(800);
    // Stacked: each choice starts below the one before it, at the same left edge.
    const first = await choices.nth(0).boundingBox();
    const second = await choices.nth(1).boundingBox();
    expect(second?.y ?? 0).toBeGreaterThan(first?.y ?? 0);
    expect(Math.abs((second?.x ?? 0) - (first?.x ?? 0))).toBeLessThanOrEqual(1);
    await expectAccessible(page);
  });
});

test("a Kumo select is worked by keyboard and is accessible while open", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/audit");
  const category = page.getByRole("combobox", { name: "Category", exact: true });
  await expect(category).toHaveText("Everything");

  // Enter opens it on the current choice.
  await category.focus();
  await page.keyboard.press("Enter");
  const list = page.getByRole("listbox");
  await expect(list).toBeVisible();
  await expect(category).toHaveAttribute("aria-expanded", "true");
  await expect(list.getByRole("option", { name: "Everything", exact: true })).toHaveAttribute("aria-selected", "true");
  await expectAccessible(page);

  // Down to the next choice, and Enter takes it.
  await page.keyboard.press("ArrowDown");
  await expect(list.getByRole("option", { name: "auth", exact: true })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(list).toBeHidden();
  await expect(category).toHaveText("auth");
  await expect(category).toBeFocused();
  await expect(page).toHaveURL(/category=auth/);

  // Space opens it too, and Escape leaves the value as it was.
  await page.keyboard.press(" ");
  await expect(list).toBeVisible();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Escape");
  await expect(list).toBeHidden();
  await expect(category).toHaveText("auth");
  await expect(page).toHaveURL(/category=auth/);
});
