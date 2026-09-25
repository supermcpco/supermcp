import { test, expect, expectAccessible, signIn } from "./fixtures";

// The settings screens, driven the way an administrator drives them. Each
// assertion is about what the person sees, not about the shape of a JSON
// response, because the response was already right when the screen that
// showed it was unreachable.

test("the audit trail records what the administrator just did", async ({ page, workspace }) => {
  await page.goto("/api-keys");
  await page.getByLabel("Name").fill("Audited key");
  await page.getByRole("button", { name: "Create key" }).click();
  await expect(page.getByRole("heading", { name: /copy this key now/i })).toBeVisible();

  await page.goto("/settings/audit");
  await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();
  await expect(page.getByText("The chain is intact")).toBeVisible();
  await expect(page.getByText("apikey.create")).toBeVisible();
  // The sign-up and the key both name the same person, so match the first.
  await expect(page.getByText(workspace.email).first()).toBeVisible();
  await expectAccessible(page);

  // Narrowing to a category the event is not in must hide it, or the
  // filter is decorative.
  await page.getByLabel("Category").selectOption("auth");
  await expect(page.getByText("apikey.create")).toHaveCount(0);
  await page.getByLabel("Category").selectOption("");
  await expect(page.getByText("apikey.create")).toBeVisible();

  // The sign-up left events of its own, so the whole trail is more than
  // the key. A search for the key's name narrows it to the key alone.
  const rows = page.getByRole("row");
  await expect(rows).not.toHaveCount(2);
  const search = page.getByRole("searchbox", { name: "Search" });
  await search.fill('"audited key"');
  await expect(page).toHaveURL(/[?&]q=/);
  await expect(rows).toHaveCount(2); // the header and the key
  await expect(rows.nth(1)).toContainText("apikey.create");

  // The search is kept in the address, so a reload shows the same trail.
  await page.reload();
  await expect(search).toHaveValue('"audited key"');
  await expect(rows).toHaveCount(2);

  // Words nothing carries say so, rather than showing an empty table.
  await search.fill("nosuchwordanywhere");
  await expect(page.getByText("Nothing matches these filters.")).toBeVisible();
  await expect(page.getByText("apikey.create")).toHaveCount(0);
  await expectAccessible(page);

  await search.fill("");
  await expect(page).not.toHaveURL(/[?&]q=/);
  await expect(page.getByText("apikey.create")).toBeVisible();
});

test("the workspace's password rules are enforced on a real change", async ({ page, workspace }) => {
  await page.goto("/settings/security");
  await expect(page.getByRole("heading", { name: "Security" })).toBeVisible();
  await expectAccessible(page);

  await page.getByLabel("Minimum length").fill("16");
  await page.getByRole("button", { name: "Save rules" }).click();
  await expect(page.getByText("Saved.")).toBeVisible();

  // Too short for the rule that was just saved.
  await page.getByLabel("Current password").fill(workspace.password);
  await page.getByLabel("New password").fill("Short Pass 12");
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByRole("alert")).toContainText(/at least 16/i);

  // Long enough, and the session that made the change survives it.
  const next = "Stapler Ocean Drift 77";
  await page.getByLabel("Current password").fill(workspace.password);
  await page.getByLabel("New password").fill(next);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByRole("status")).toContainText(/password changed/i);

  // And the new password is the one that works.
  await page.context().clearCookies();
  await signIn(page, { ...workspace, password: next });
});

test("a service account is created with a secret shown once", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/service-accounts");
  await expect(page.getByRole("heading", { name: "Service accounts" })).toBeVisible();
  await page.getByLabel("Name").fill("Nightly export");
  await page.getByRole("button", { name: "Create account" }).click();

  await expect(page.getByRole("alert")).toContainText(/copy this secret now/i);
  const shown = await page.getByRole("alert").locator("code").innerText();
  expect(shown).toContain("client_id: sms_");
  expect(shown).toContain("client_secret: ");

  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByText("Nightly export")).toBeVisible();

  // Reloading must not show the secret again.
  await page.reload();
  await expect(page.getByText(/client_secret:/)).toHaveCount(0);
});

test("the single sign-on screen tells an administrator what to register", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/sso");
  await expect(page.getByRole("heading", { name: "Single sign-on" })).toBeVisible();
  await expect(page.getByText("/auth/sso/callback")).toBeVisible();
  await expect(page.getByText("/scim/v2")).toBeVisible();
  await expectAccessible(page);

  // An issuer that does not exist must fail on this screen rather than at
  // someone's first sign-in.
  await page.getByLabel("Issuer URL").fill("https://localhost:9/not-a-provider");
  await page.getByRole("button", { name: /test this issuer/i }).click();
  await expect(page.getByRole("alert")).toBeVisible({ timeout: 15_000 });
});

test("signing out ends the session", async ({ page, workspace }) => {
  await page.goto("/");
  await expect(page.getByText(workspace.org)).toBeVisible();
  await page.context().clearCookies();
  await page.goto("/connectors");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});
