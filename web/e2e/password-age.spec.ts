import { test, expect, expectAccessible } from "./fixtures";
import { sql } from "./db";

// A password past the workspace's maximum age gets one screen: change
// it. The Go tests prove the server refuses everything else; this proves
// a person sees why, can do the one thing asked, and gets the product
// back. Time is the only part the product cannot supply, so the account
// is aged in the database before the rule is set.

test("an expired password gets the change screen and nothing else, until it is changed", async ({
  page,
  workspace,
}) => {
  // The password was set at sign-up and never changed, so it is as old
  // as the account. Aged first: a password found within its age is
  // trusted for a minute, and saving the rule is what forgets that.
  const aged = sql(`UPDATE users SET created_at = now() - interval '31 days' WHERE email = $1 RETURNING id`, workspace.email);
  expect(aged, "the account was not found to age").not.toEqual("");

  await page.goto("/settings/security");
  await page.getByLabel("Expires after (days)").fill("30");
  await page.getByRole("button", { name: "Save rules" }).click();
  await expect(page.getByText("Saved.")).toBeVisible();

  // Every screen is now the same screen.
  for (const path of ["/connectors", "/catalog", "/api-keys"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { name: "Your password has expired" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Change password" })).toBeVisible();
  }
  await expectAccessible(page);

  // The gate's own form applies the workspace's rules.
  await page.getByLabel("Current password").fill(workspace.password);
  await page.getByLabel("New password").fill("short");
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Your password has expired" })).toBeVisible();

  const next = "Stapler Ocean Drift 77";
  await page.getByLabel("Current password").fill(workspace.password);
  await page.getByLabel("New password").fill(next);
  await page.getByRole("button", { name: "Change password" }).click();

  // Changed, and the product is back without a reload.
  await expect(page.getByRole("heading", { name: "Your password has expired" })).toBeHidden();
  await page.goto("/connectors");
  await expect(page.getByRole("heading", { name: "Connectors", exact: true })).toBeVisible();
});
