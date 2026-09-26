import type { Browser, Page } from "@playwright/test";
import { test, expect, expectAccessible } from "./fixtures";

// The line between the console and the sign-in card. Everything a person
// can do lives behind a session, so an anonymous visitor must meet the
// card, never a sidebar full of screens that refuse them, and the card has
// to bring them back to where they were going.

/** A browser with no session, the way a first-time visitor arrives. */
async function anonymous(browser: Browser) {
  const context = await browser.newContext();
  return { context, page: await context.newPage() };
}

/** Where the page is, as a path and the `next` it carries. */
function where(page: Page) {
  const url = new URL(page.url());
  return { path: url.pathname, next: url.searchParams.get("next") };
}

test("an anonymous visit to a console screen is sent to sign in and brought back after", async ({
  browser,
  workspace,
}) => {
  const { context, page } = await anonymous(browser);
  await page.goto("/connectors");

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(where(page)).toEqual({ path: "/login", next: "/connectors" });
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Settings" })).toHaveCount(0);
  await expectAccessible(page);

  await page.getByLabel("Email").fill(workspace.email);
  await page.getByLabel("Password").fill(workspace.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  await expect(page.getByRole("heading", { name: "Connectors", exact: true })).toBeVisible();
  expect(where(page).path).toBe("/connectors");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await context.close();
});

test("a first visit to the front page shows the sign-in card with a way to create a workspace", async ({
  browser,
}) => {
  const { context, page } = await anonymous(browser);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(where(page).path).toBe("/login");
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create a workspace" })).toBeVisible();

  // Sign-in asks the password manager for a saved account.
  const signIn = page.getByRole("form", { name: "Sign in" });
  await expect(signIn.getByLabel("Email")).toHaveAttribute("autocomplete", "username");
  await expect(signIn.getByLabel("Password")).toHaveAttribute("autocomplete", "current-password");
  await signIn.getByLabel("Email").fill("someone@example.test");
  await signIn.getByLabel("Password").fill("a saved password"); // gitleaks:allow

  // Creating a workspace is a different form that asks for a new
  // password, so nothing saved or typed for sign-in lands in it.
  await page.getByRole("button", { name: "Create a workspace" }).click();
  const signUp = page.getByRole("form", { name: "Create your workspace" });
  await expect(signUp).toBeVisible();
  await expect(signIn).toHaveCount(0);
  await expect(signUp.getByLabel("Email")).toHaveAttribute("autocomplete", "username");
  await expect(signUp.getByLabel("Password")).toHaveAttribute("autocomplete", "new-password");
  await expect(signUp.getByLabel("Workspace name")).toHaveAttribute("autocomplete", "organization");
  await expect(signUp.getByLabel("Email")).toHaveValue("");
  await expect(signUp.getByLabel("Password")).toHaveValue("");
  await expectAccessible(page);

  await page.getByRole("button", { name: "Sign in instead" }).click();
  await expect(page.getByRole("form", { name: "Sign in" })).toBeVisible();
  await context.close();
});

test("a refused sign-in says why, next to the form", async ({ browser, workspace }) => {
  const { context, page } = await anonymous(browser);
  await page.goto("/login");
  const form = page.getByRole("form", { name: "Sign in" });
  await form.getByLabel("Email").fill(workspace.email);
  await form.getByLabel("Password").fill("not the password at all"); // gitleaks:allow
  await form.getByRole("button", { name: "Sign in", exact: true }).click();

  const alert = form.getByRole("alert");
  await expect(alert).toBeVisible();
  // The server's words, as a sentence, and the form is described by them.
  await expect(alert).toHaveText(/^[A-Z].*[.!?]$/);
  await expect(form).toHaveAccessibleDescription(((await alert.textContent()) ?? "").trim());
  expect(where(page).path).toBe("/login");
  await expectAccessible(page);
  await context.close();
});

// The server sends a failed provider sign-in back here with one word:
// sso_error from OpenID Connect, saml_error from SAML. Both are said as
// something a person can act on.
test("a provider's refusal is explained on the sign-in card", async ({ browser }) => {
  const { context, page } = await anonymous(browser);
  await page.goto("/login?saml_error=already_used");
  const form = page.getByRole("form", { name: "Sign in" });
  await expect(form.getByRole("alert")).toHaveText("That sign-in had already been used. Start it again from here.");

  await page.goto("/login?sso_error=domain_not_allowed");
  await expect(form.getByRole("alert")).toHaveText(
    "That account's email domain is not allowed to sign in to this workspace.",
  );
  await context.close();
});

test("signing out from inside the console lands on the sign-in card", async ({ page, workspace }) => {
  await page.goto("/connectors");
  await expect(page.getByText(workspace.org)).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(where(page)).toEqual({ path: "/login", next: null });
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
  await expect(page.getByText(workspace.org)).toHaveCount(0);

  // The session is gone, not just the sidebar.
  await page.goto("/settings/members");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(where(page)).toEqual({ path: "/login", next: "/settings/members" });
});

test("a tab left open is sent to sign in when it is looked at again after signing out elsewhere", async ({
  page,
  workspace,
}) => {
  // The first tab's clock is under the test's control, so "a while later"
  // is a jump rather than a wait.
  await page.clock.install();
  await page.goto("/connectors");
  await expect(page.getByText(workspace.org)).toBeVisible();

  const elsewhere = await page.context().newPage();
  await elsewhere.goto("/connectors");
  await elsewhere.getByRole("button", { name: "Sign out" }).click();
  await expect(elsewhere.getByRole("heading", { name: "Sign in" })).toBeVisible();

  // Coming back to the first tab, a minute later.
  await page.clock.fastForward("01:00");
  await page.bringToFront();
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange", { bubbles: true })));

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(where(page)).toEqual({ path: "/login", next: "/connectors" });
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
});
