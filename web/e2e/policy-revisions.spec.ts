import { test, expect, expectAccessible } from "./fixtures";

// A data-loss rule keeps a history like a connector does: a change made
// on the rules screen is a version that can be put back from the same
// screen.

test("a data-loss rule is changed, and the earlier version restored from its history", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/dlp");
  await expect(page.getByRole("heading", { name: "Data-loss rules" })).toBeVisible();

  await page.getByLabel("What it is for").fill("Customer addresses");
  await page.getByLabel("What it does").selectOption("mask");
  await Promise.all([
    page.waitForResponse((r) => r.url().endsWith("/api/v1/dlp/policies") && r.request().method() === "POST" && r.ok()),
    page.getByRole("button", { name: "Add the rule" }).click(),
  ]);
  const rule = page.getByRole("listitem").filter({ hasText: "Customer addresses" }).first();
  await expect(rule.getByText("mask", { exact: true })).toBeVisible();

  // Change what it does. The save is awaited by its answer, so the
  // history is not opened before the change has reached the server.
  await rule.getByRole("button", { name: "Change Customer addresses" }).click();
  await rule.getByLabel("What the rule does").selectOption("refuse");
  await Promise.all([
    page.waitForResponse((r) => /\/api\/v1\/dlp\/policies\/[^/]+$/.test(r.url()) && r.request().method() === "PUT" && r.ok()),
    rule.getByRole("button", { name: "Save the rule" }).click(),
  ]);
  await expect(rule.getByText("refuse", { exact: true })).toBeVisible();

  const [answer] = await Promise.all([
    page.waitForResponse((r) => /\/api\/v1\/dlp\/policies\/[^/]+\/revisions(\?|$)/.test(r.url())),
    rule.getByRole("button", { name: "History of Customer addresses" }).click(),
  ]);
  expect((await answer.json()).revisions.length, "creating the rule and changing it are both recorded").toBe(2);

  const history = page.getByRole("region", { name: "History of Customer addresses" });
  const versions = history.getByText(/^Version \d+$/);
  await expect(versions).toHaveCount(2);
  // The change reads as what it was, in the product's words. The newest
  // version is first, and its only change is what the rule does.
  const newest = history.getByRole("listitem").first();
  await expect(newest.getByText("What it does")).toBeVisible();
  await expect(newest.getByText("refuse", { exact: true })).toBeVisible();
  await expectAccessible(page);

  // Restoring is recorded as a further version rather than a rewind.
  await Promise.all([
    page.waitForResponse((r) => /\/revisions\/1\/restore$/.test(r.url()) && r.ok()),
    history.getByRole("button", { name: "Restore this version" }).click(),
  ]);
  await expect(versions).toHaveCount(3);

  await rule.getByRole("button", { name: "Hide the history of Customer addresses" }).click();
  await expect(rule.getByText("mask", { exact: true })).toBeVisible();
  await expect(rule.getByText("refuse", { exact: true })).toHaveCount(0);

  // And the server agrees: the rule masks again.
  const policies = await (await page.request.get("/api/v1/dlp/policies")).json();
  expect(policies.policies.find((p: { name: string }) => p.name === "Customer addresses").action).toBe("mask");
});
