import { test, expect, expectAccessible } from "./fixtures";
import type { Locator, Page } from "@playwright/test";

// The row above the catalog's cards: the search, the "No credentials
// needed" filter and the count. The search once sat in a box wider than
// itself, leaving a gap before the filter; these pin the row's shape.

/** The number the count reads, "1,234 adapters" included. */
async function counted(count: Locator) {
  return Number((await count.textContent())!.replace(/\D/g, ""));
}

function row(page: Page) {
  return {
    search: page.getByRole("searchbox", { name: "Search adapters" }),
    keyless: page.getByRole("checkbox", { name: "No credentials needed" }),
    count: page.getByText(/^\d+ adapters?$/),
  };
}

async function box(name: string, l: Locator) {
  const b = await l.boundingBox();
  expect(b, `${name} has a box`).not.toBeNull();
  return b!;
}

test("on a wide screen the search, the filter and the count share one line", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/catalog");
  const { search, keyless, count } = row(page);
  await expect(count).toBeVisible();

  const s = await box("search", search);
  const k = await box("filter", keyless);
  const c = await box("count", count);
  const centre = (b: { y: number; height: number }) => b.y + b.height / 2;
  expect(Math.abs(centre(k) - centre(s))).toBeLessThanOrEqual(2);
  expect(Math.abs(centre(c) - centre(s))).toBeLessThanOrEqual(2);
  // In order, and the filter follows the search closely rather than
  // after a stretch of empty space.
  expect(k.x).toBeGreaterThan(s.x + s.width);
  expect(k.x - (s.x + s.width)).toBeLessThanOrEqual(24);
  expect(c.x).toBeGreaterThan(k.x + k.width);

  // The filter is a real control: it narrows the list and says so.
  const all = await counted(count);
  await keyless.click();
  await expect(keyless).toBeChecked();
  await expect.poll(() => counted(count)).toBeLessThan(all);
});

test("on a phone the row wraps under the search without scrolling sideways", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/catalog");
  const { search, keyless, count } = row(page);
  await expect(count).toBeVisible();

  const s = await box("search", search);
  const k = await box("filter", keyless);
  const c = await box("count", count);
  expect(k.y).toBeGreaterThanOrEqual(s.y + s.height);
  expect(c.y).toBeGreaterThanOrEqual(s.y + s.height);
  expect(await page.evaluate(() => document.scrollingElement!.scrollWidth <= innerWidth)).toBe(true);

  await search.fill("no adapter is called this");
  await expect(page.getByText("No adapters match")).toBeVisible();
  await expect(count).toHaveText("0 adapters");
  expect(await page.evaluate(() => document.scrollingElement!.scrollWidth <= innerWidth)).toBe(true);
});

for (const colorScheme of ["light", "dark"] as const) {
  test(`the catalog passes the accessibility check in the ${colorScheme} scheme`, async ({ page, workspace }) => {
    expect(workspace.email).toBeTruthy();
    await page.emulateMedia({ colorScheme });
    await page.goto("/catalog");
    await expect(row(page).count).toBeVisible();
    await expectAccessible(page);
    await row(page).keyless.click();
    await expect(row(page).keyless).toBeChecked();
    await expectAccessible(page);
  });
}
