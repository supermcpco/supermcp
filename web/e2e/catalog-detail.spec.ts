import { test, expect, expectAccessible } from "./fixtures";
import type { Page } from "@playwright/test";

// An adapter's catalog page: what it is, what it takes to set up, and the
// tools it brings, before anything is installed. Bundesbank needs no
// credentials and has three tools, which is what most of this reads.

const bundesbank = "Deutsche Bundesbank Statistics";

async function openBundesbank(page: Page) {
  await page.goto("/catalog/bundesbank");
  await expect(page.getByRole("heading", { name: bundesbank, level: 1 })).toBeVisible();
}

test("an adapter page shows its badges, set-up card and filtered tools", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await openBundesbank(page);

  const badges = page.getByRole("list", { name: "About this adapter" });
  await expect(badges.getByText("No credentials needed", { exact: true })).toBeVisible();
  await expect(badges.getByText("finance", { exact: true })).toBeVisible();
  await expect(badges.getByText("HTTP", { exact: true })).toBeVisible();
  await expect(badges.getByText("3 tools", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: /^Docs/ })).toHaveAttribute("href", /bundesbank\.de/);

  const setUp = page.getByRole("region", { name: "Set up" });
  await expect(setUp.getByText(/^No credentials needed:/)).toBeVisible();
  await expect(setUp.getByRole("button", { name: "Install", exact: true })).toBeEnabled();
  const details = page.getByRole("region", { name: "Details" });
  // Where it reaches, and its documentation, which lives on the same host.
  await expect(details.getByText("api.statistiken.bundesbank.de", { exact: true })).toHaveCount(2);
  await expect(details.getByRole("link", { name: /^api\.statistiken\.bundesbank\.de/ })).toBeVisible();

  const tools = page.getByRole("region", { name: "Tools" });
  await expect(tools.getByRole("listitem").filter({ has: page.getByText(/^bundesbank_/) })).toHaveCount(3);
  await tools.getByRole("searchbox", { name: "Filter tools" }).fill("bund_yields");
  await expect(tools.getByText("1 of 3 tools", { exact: true })).toBeVisible();
  await expect(tools.getByText("bundesbank_get_bund_yields", { exact: true })).toBeVisible();
  await expect(tools.getByText("bundesbank_get_exchange_rates", { exact: true })).toHaveCount(0);

  // The parameters open from the keyboard, and say which are required.
  const disclosure = tools.getByRole("button", { name: "3 parameters of bundesbank_get_bund_yields" });
  await expect(disclosure).toHaveAttribute("aria-expanded", "false");
  await disclosure.focus();
  await page.keyboard.press("Enter");
  await expect(disclosure).toHaveAttribute("aria-expanded", "true");
  const params = tools.getByRole("list", { name: "Parameters of bundesbank_get_bund_yields" });
  await expect(params.getByText("maturityYears", { exact: true })).toBeVisible();
  await expect(params.getByText("required", { exact: true })).toHaveCount(1);
  await expect(params.getByText("One of 01, 02, 05, 10, 30. Defaults to 10.", { exact: true })).toBeVisible();
  await expectAccessible(page);

  // A filter that matches nothing says so and can be cleared.
  await tools.getByRole("searchbox", { name: "Filter tools" }).fill("nothing like this");
  await expect(tools.getByText("0 of 3 tools", { exact: true })).toBeVisible();
  await tools.getByRole("button", { name: "Clear the filter" }).click();
  await expect(tools.getByText("3 tools", { exact: true })).toBeVisible();
});

test("an adapter that needs credentials asks for them before it installs", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/catalog/clockodo");
  await expect(page.getByRole("heading", { name: "clockodo", level: 1 })).toBeVisible();
  await expect(page.getByRole("list", { name: "About this adapter" }).getByText("API key", { exact: true })).toBeVisible();
  const setUp = page.getByRole("region", { name: "Set up" });
  const install = setUp.getByRole("button", { name: "Install", exact: true });
  await expect(install).toBeDisabled();
  await setUp.getByLabel("CLOCKODO_API_KEY").fill("key");
  await setUp.getByLabel("CLOCKODO_API_USER").fill("someone@example.test");
  await expect(install).toBeEnabled();
});

test("an installed adapter says so and links to its connector", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await openBundesbank(page);
  const installed = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/connectors/install") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Install", exact: true }).click();
  const id = ((await (await installed).json()) as { id: string }).id;
  await expect(page).toHaveURL(new RegExp(`/connectors/${id}$`));

  await openBundesbank(page);
  const setUp = page.getByRole("region", { name: "Set up" });
  await expect(setUp.getByText("Installed", { exact: true })).toBeVisible();
  await expect(setUp.getByRole("button", { name: "Install", exact: true })).toHaveCount(0);
  await expect(setUp.getByRole("button", { name: "Install another" })).toBeEnabled();
  await setUp.getByRole("link", { name: bundesbank, exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/connectors/${id}$`));
});

test("an adapter page lays out for phone and desktop", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const setUp = page.getByRole("region", { name: "Set up" });
  const tools = page.getByRole("region", { name: "Tools" });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/catalog/teamleader");
  await expect(page.getByRole("heading", { name: "Teamleader Focus", level: 1 })).toBeVisible();
  // Every Teamleader call is a POST, but each of its tools is named for a
  // read (get_, list_), so none is called a write, let alone destructive.
  await expect(tools.getByText("reads only", { exact: true })).toHaveCount(10);
  await expect(tools.getByText("writes", { exact: true })).toHaveCount(0);
  await expect(tools.getByText("destructive", { exact: true })).toHaveCount(0);
  // Nothing is wider than the phone: the page scrolls one way only.
  await expect
    .poll(() => page.locator("main").evaluate((m) => m.scrollWidth - m.clientWidth))
    .toBe(0);
  // Set up comes before the tools, and the header's link goes to it.
  const setUpBox = await setUp.boundingBox();
  const toolsBox = await tools.boundingBox();
  expect(setUpBox && toolsBox && setUpBox.y < toolsBox.y).toBeTruthy();
  await page.getByRole("link", { name: "Install", exact: true }).click();
  await expect(setUp).toBeFocused();

  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.getByRole("link", { name: "Install", exact: true })).toBeHidden();
  // Two columns: the set-up card stands to the right of the tools, level
  // with the header, and there is one Install.
  await expect.poll(async () => (await setUp.boundingBox())!.x > (await tools.boundingBox())!.x + 300).toBe(true);
  // The card starts inside the first screen; where exactly depends on how
  // the description wraps, which differs by platform fonts.
  expect((await setUp.boundingBox())!.y).toBeLessThan(400);
  await expect(page.getByRole("button", { name: "Install", exact: true })).toHaveCount(1);
});

for (const colorScheme of ["light", "dark"] as const) {
  test.describe(`in the ${colorScheme} scheme`, () => {
    test.use({ colorScheme });
    test(`adapter pages pass the accessibility check in the ${colorScheme} scheme`, async ({ page, workspace }) => {
      expect(workspace.email).toBeTruthy();
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: width > 1000 ? 900 : 844 });
        for (const [slug, name] of [
          ["bundesbank", bundesbank],
          ["clockodo", "clockodo"],
          ["teamleader", "Teamleader Focus"],
          ["bexio", "bexio"],
        ]) {
          await page.goto(`/catalog/${slug}`);
          await expect(page.getByRole("heading", { name, level: 1 })).toBeVisible();
          await expect(page.getByRole("region", { name: "Details" }).getByText(/^[0-9a-f]{12}$/)).toBeVisible();
          await expectAccessible(page);
        }
      }
    });
  });
}
