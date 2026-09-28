import type { Browser, Page } from "@playwright/test";
import { test, expect, expectAccessible, openAccountMenu, signIn } from "./fixtures";

// The server's own sentence says what a name may be; the screen only has
// to show it where the person is looking.
const refusal = /1 to 120 characters/;

// Names people read: your own, on the Account tab, and the workspace's, on
// the Members tab. Both show up in the sidebar's account button, which is
// where a person notices whether the change took.

function sidebar(page: Page) {
  return page.getByRole("complementary", { name: "Sidebar" });
}

/** A browser with no cookies: the person an invitation link was sent to. */
async function stranger(browser: Browser) {
  const context = await browser.newContext();
  return { context, page: await context.newPage() };
}

/**
 * Invites somebody as a viewer through the members screen and has them
 * join from the link in a browser of their own, the way anybody joins.
 */
async function inviteViewer(page: Page, browser: Browser, org: string) {
  const email = `named-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.test`;
  const name = "Vera Viewer";
  await page.goto("/settings/members");
  await page.getByRole("button", { name: "Invite someone" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Invite someone" });
  await dialog.getByLabel("Email", { exact: true }).fill(email);
  await dialog.getByLabel("Role", { exact: true }).selectOption({ label: "viewer" });
  await dialog.getByRole("button", { name: "Create invitation link" }).click();
  await expect(dialog).toHaveCount(0);
  const banner = page.getByRole("alert").filter({ hasText: `Copy the invitation link for ${email} now` });
  const link = (await banner.getByText(/\/invite\/[A-Za-z0-9_-]+$/).textContent())?.trim() ?? "";
  expect(link).toMatch(/\/invite\//);
  await page.getByRole("button", { name: "Done" }).click();

  const member = await stranger(browser);
  await member.page.goto(link);
  await member.page.getByLabel("Name").fill(name);
  await member.page.getByLabel("Password").fill("Viewer Horse Battery 5");
  await member.page.getByRole("button", { name: "Create account and join" }).click();
  await expect(sidebar(member.page).getByText(org)).toBeVisible();
  return { ...member, email, name };
}

test("a person sets their display name and the sidebar shows it", async ({ page, workspace }) => {
  const name = "Ada Lovelace";
  // Nobody is asked for a name at sign-up, so the button starts with the address.
  await expect(sidebar(page).getByRole("button", { name: workspace.email })).toBeVisible();

  const menu = await openAccountMenu(page, workspace.email);
  await menu.getByRole("menuitem", { name: "Account settings" }).click();
  await expect(page.getByRole("tab", { name: "Account", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("heading", { name: "Account", level: 2 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Profile", level: 3 })).toBeVisible();

  const profile = page.getByRole("form", { name: "Your name" });
  const field = profile.getByLabel("Name", { exact: true });
  const save = profile.getByRole("button", { name: "Save name" });
  await expect(page.getByText(workspace.email, { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Password", { exact: true }).first()).toBeVisible();
  await expect(field).toHaveValue("");
  await expect(field).toHaveAttribute("placeholder", "How you want to be shown");
  await expect(save).toBeDisabled();
  await expectAccessible(page);

  await field.fill(name);
  await expect(save).toBeEnabled();
  await save.click();
  await expect(page.getByRole("heading", { name: "Name saved", exact: true })).toBeVisible();
  await expect(save).toBeDisabled();
  const account = sidebar(page).getByRole("button", { name });
  await expect(account).toBeVisible();

  // It is the server's name, not the page's: signing out and in again keeps it.
  await account.click();
  await page.getByRole("menu").getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await signIn(page, workspace);
  await expect(sidebar(page).getByRole("button", { name })).toBeVisible();
  await page.goto("/settings/security");
  await expect(page.getByRole("form", { name: "Your name" }).getByLabel("Name", { exact: true })).toHaveValue(name);
});

test("a name the server refuses is explained under the field", async ({ page, workspace }) => {
  await page.goto("/settings/security");
  const profile = page.getByRole("form", { name: "Your name" });
  const field = profile.getByLabel("Name", { exact: true });
  // A right-to-left override would make the name read as something else.
  await field.fill("Ada ‮ecalevol");
  await profile.getByRole("button", { name: "Save name" }).click();
  const alert = profile.getByRole("alert");
  await expect(alert).toHaveText(refusal);
  await expect(field).toHaveAttribute("aria-invalid", "true");
  await expect(field).toHaveAccessibleDescription(refusal);
  // What was typed stays, to be corrected; nothing changed anywhere else.
  await expect(field).toHaveValue("Ada ‮ecalevol");
  await expect(sidebar(page).getByRole("button", { name: workspace.email })).toBeVisible();
  await expectAccessible(page);

  // Typing again clears the complaint.
  await field.fill("Ada");
  await expect(alert).toHaveCount(0);
});

test("an owner renames the workspace and a member sees the new name", async ({ page, browser, workspace }) => {
  test.setTimeout(90_000);
  const member = await inviteViewer(page, browser, workspace.org);
  const renamed = `Renamed ${Date.now()}`;

  await page.goto("/settings/members");
  const section = page.getByRole("region", { name: "Workspace", exact: true });
  await expect(section.getByText(workspace.org, { exact: true })).toBeVisible();
  const slug = (await section.getByRole("code").textContent())?.trim() ?? "";
  expect(slug).not.toBe("");
  await expect(section.getByText(/stays the same when the name changes/)).toBeVisible();

  await section.getByRole("button", { name: "Rename workspace" }).click();
  const dialog = page.getByRole("dialog", { name: "Rename workspace" });
  const field = dialog.getByLabel("Name", { exact: true });
  await expect(field).toHaveValue(workspace.org);
  // Nothing to send until the name is different.
  await expect(dialog.getByRole("button", { name: "Rename workspace" })).toBeDisabled();
  await expectAccessible(page);

  // A refusal is explained in the dialog, which stays open.
  await field.fill("x".repeat(121));
  await dialog.getByRole("button", { name: "Rename workspace" }).click();
  await expect(dialog.getByRole("alert")).toHaveText(refusal);

  await field.fill(renamed);
  await dialog.getByRole("button", { name: "Rename workspace" }).click();
  await expect(page.getByRole("heading", { name: "Workspace renamed", exact: true })).toBeVisible();
  await expect(dialog).toHaveCount(0);
  await expect(section.getByText(renamed, { exact: true })).toBeVisible();
  await expect(section.getByRole("code")).toHaveText(slug);
  await expect(sidebar(page).getByRole("button", { name: renamed })).toBeVisible();

  // The member's next look at the session carries the new name.
  await member.page.reload();
  await expect(sidebar(member.page).getByRole("button", { name: renamed })).toBeVisible();
  await expect(sidebar(member.page).getByText(workspace.org)).toHaveCount(0);
  await member.context.close();
});

test("a member without org:update sees no way to rename the workspace", async ({ page, browser, workspace }) => {
  test.setTimeout(90_000);
  const member = await inviteViewer(page, browser, workspace.org);

  await member.page.goto("/settings/members");
  const section = member.page.getByRole("region", { name: "Workspace", exact: true });
  await expect(section.getByText(workspace.org, { exact: true })).toBeVisible();
  await expect(member.page.getByRole("button", { name: "Rename workspace" })).toHaveCount(0);
  await expectAccessible(member.page);

  // Their own name is still theirs to change.
  await member.page.goto("/settings/security");
  const field = member.page.getByRole("form", { name: "Your name" }).getByLabel("Name", { exact: true });
  await expect(field).toHaveValue(member.name);
  await member.context.close();
});
