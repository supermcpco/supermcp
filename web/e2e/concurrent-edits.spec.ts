import { test, expect, expectAccessible, signIn } from "./fixtures";

// Two people with the same connector open: the second one to save must be
// told the connector moved on, not silently undo the first one's change.

test("a restore made against a connector somebody else changed is refused until it is reloaded", async ({
  page,
  browser,
  workspace,
}) => {
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);

  // A rename leaves an earlier version to go back to.
  const api = page.request;
  const connectors = await (await api.get("/api/v1/connectors")).json();
  const id: string = connectors[0].id;
  const renamed = await api.patch(`/api/v1/connectors/${id}`, { data: { name: "Renamed before the race" } });
  expect(renamed.ok()).toBeTruthy();

  // The same person in a second browser, as a colleague would be.
  const context = await browser.newContext();
  const other = await context.newPage();
  await signIn(other, workspace);

  const versions = /^Version \d+$/;
  const restoreButton = (p: typeof page) => p.getByRole("button", { name: /restore this version/i }).last();
  for (const p of [page, other]) {
    await p.goto(`/connectors/${id}/history`);
    await expect(p.getByRole("heading", { name: "History" })).toBeVisible();
    // The button waits for the connector's version, which the restore
    // sends back.
    await expect(restoreButton(p)).toBeEnabled();
  }
  const start = await page.getByText(versions).count();

  // The first restore goes through.
  const first = page.waitForResponse((r) => r.url().includes("/restore") && r.request().method() === "POST");
  await restoreButton(page).click();
  expect((await first).status()).toBe(200);
  await expect(page.getByText(versions)).toHaveCount(start + 1);

  // The second, from a screen that still shows the old version, is not.
  const second = other.waitForResponse((r) => r.url().includes("/restore") && r.request().method() === "POST");
  await restoreButton(other).click();
  expect((await second).status()).toBe(409);
  const notice = other.getByRole("alert");
  await expect(notice).toContainText("changed by someone else");
  const reload = notice.getByRole("button", { name: "Reload the connector" });
  await expect(reload).toBeVisible();
  await expectAccessible(other);

  // Reloading shows the first person's restore and lets this one through.
  await reload.click();
  await expect(other.getByRole("alert")).toHaveCount(0);
  await expect(other.getByText(versions)).toHaveCount(start + 1);
  await expect(restoreButton(other)).toBeEnabled();
  const third = other.waitForResponse((r) => r.url().includes("/restore") && r.request().method() === "POST");
  await restoreButton(other).click();
  expect((await third).status()).toBe(200);
  await expect(other.getByText(versions)).toHaveCount(start + 2);

  await context.close();
});
