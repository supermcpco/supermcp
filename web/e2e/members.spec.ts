import type { Browser, Page } from "@playwright/test";
import { test, expect, expectAccessible, signUp } from "./fixtures";

// Members and invitations, end to end: an owner invites somebody by link,
// that person joins from a browser that has never seen the workspace, and
// the owner then changes, deactivates and removes them. Nothing is mailed,
// so the link travels the way it does for real: copied off the screen.

const invitee = { name: "Ada Invitee", password: "Invited Horse Battery 7" };

function unique(prefix: string) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.test`;
}

/** Creates an invitation through the form and returns the link shown once. */
async function invite(page: Page, email: string, role: string): Promise<string> {
  await page.goto("/settings/members");
  const dialog = await openInvite(page);
  await dialog.getByLabel("Email", { exact: true }).fill(email);
  await dialog.getByLabel("Role", { exact: true }).selectOption({ label: role });
  await dialog.getByLabel("Link works for (days)").fill("3");
  await dialog.getByRole("button", { name: "Create invitation link" }).click();
  // The link is shown on the screen once the dialog has closed.
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("heading", { name: `Invitation for ${email} created`, exact: true })).toBeVisible();
  const banner = page.getByRole("alert").filter({ hasText: `Copy the invitation link for ${email} now` });
  await expect(banner.getByText("This link is shown once. Send it to the person yourself; no email is sent.")).toBeVisible();
  const url = (await banner.getByText(/\/invite\/[A-Za-z0-9_-]+$/).textContent())?.trim() ?? "";
  expect(url).toMatch(/\/invite\/[A-Za-z0-9_-]+$/);
  return url;
}

/** Opens the invitation form from the screen's header. */
async function openInvite(page: Page) {
  await page.getByRole("button", { name: "Invite someone" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Invite someone" });
  await expect(dialog).toBeVisible();
  return dialog;
}

/** A browser with no cookies: the person the link was sent to. */
async function stranger(browser: Browser) {
  const context = await browser.newContext();
  return { context, page: await context.newPage() };
}

function memberRow(page: Page, email: string) {
  return page.getByRole("row").filter({ hasText: email });
}

test("an owner invites someone who joins from the link, then changes, deactivates and removes them", async ({
  page,
  browser,
  workspace,
}) => {
  test.setTimeout(120_000);
  const email = unique("invitee");

  await test.step("the owner's own row cannot be changed", async () => {
    await page.goto("/settings/members");
    await expect(page.getByRole("heading", { name: "Members", exact: true })).toBeVisible();
    const self = memberRow(page, workspace.email);
    await expect(self).toBeVisible();
    await expect(self.getByRole("button", { name: /^Deactivate/ })).toBeDisabled();
    await expect(self.getByRole("button", { name: /^Remove/ })).toBeDisabled();
    await expect(self.getByRole("combobox")).toBeDisabled();
    await expect(self.getByText(/This is you/)).toBeVisible();
    await expectAccessible(page);
  });

  let link = "";
  await test.step("the owner creates a link and copies it", async () => {
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    link = await invite(page, email, "viewer");
    await page.getByRole("button", { name: "Copy", exact: true }).click();
    await expect(page.getByText("Copied.")).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link);
    await expectAccessible(page);

    const listed = page.getByRole("list", { name: "Invitations" }).getByRole("listitem").filter({ hasText: email });
    await expect(listed.getByText("pending")).toBeVisible();
    // The owner signed up without a name, so the list names them by address.
    await expect(listed.getByText(`sent by ${workspace.email}`, { exact: false })).toBeVisible();

    // One open invitation per address.
    await page.getByRole("button", { name: "Done" }).click();
    const dialog = await openInvite(page);
    await dialog.getByLabel("Email", { exact: true }).fill(email);
    await dialog.getByLabel("Role", { exact: true }).selectOption({ label: "viewer" });
    await dialog.getByRole("button", { name: "Create invitation link" }).click();
    // Refused inside the dialog, which stays open with what was typed.
    await expect(dialog.getByRole("alert").filter({ hasText: /already open/ })).toBeVisible();
    await expect(dialog.getByLabel("Email", { exact: true })).toHaveValue(email);
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
  });

  const member = await stranger(browser);
  await test.step("the invited person registers from the link and lands signed in", async () => {
    await member.page.goto(link);
    await expect(member.page.getByRole("heading", { name: `Join ${workspace.org}` })).toBeVisible();
    await expect(member.page.getByText(email).first()).toBeVisible();
    // The workspace's rules as they stand, which here are the defaults.
    await expect(
      member.page.getByText("At least 12 characters, using at least 2 of lower case, upper case, digits and symbols."),
    ).toBeVisible();
    await expectAccessible(member.page);

    await member.page.getByLabel("Name").fill(invitee.name);
    await member.page.getByLabel("Password").fill(invitee.password);
    await member.page.getByRole("button", { name: "Create account and join" }).click();
    await expect(member.page).toHaveURL(/\/$/);
    await expect(member.page.getByText(workspace.org, { exact: false }).first()).toBeVisible();
  });

  await test.step("the owner sees them with the invited role", async () => {
    await page.goto("/settings/members");
    const row = memberRow(page, email);
    // The name also labels the row's buttons for a screen reader.
    await expect(row.getByText(invitee.name).first()).toBeVisible();
    await expect(row.getByRole("list", { name: `Roles of ${invitee.name}` }).getByText("viewer")).toBeVisible();
    await expect(row.getByText("Password", { exact: true })).toBeVisible();
    await expect(row.getByText("active", { exact: true })).toBeVisible();
  });

  await test.step("the owner changes their role", async () => {
    await page.getByLabel(`Role for ${invitee.name}`).selectOption({ label: "editor" });
    await page.getByRole("button", { name: `Change ${invitee.name}'s role` }).click();
    await expect(page.getByRole("heading", { name: `${invitee.name} now holds editor`, exact: true })).toBeVisible();
    const roles = memberRow(page, email).getByRole("list", { name: `Roles of ${invitee.name}` });
    await expect(roles.getByText("editor")).toBeVisible();
    await expect(roles.getByText("viewer")).toHaveCount(0);
  });

  await test.step("deactivating them ends their session", async () => {
    await page.getByRole("button", { name: `Deactivate ${invitee.name}` }).click();
    await page.getByRole("button", { name: `Yes, deactivate ${invitee.name}` }).click();
    await expect(page.getByRole("heading", { name: `${invitee.name} deactivated`, exact: true })).toBeVisible();
    await expect(memberRow(page, email).getByText("deactivated", { exact: true })).toBeVisible();

    const res = await member.page.request.get("/api/v1/auth/session");
    const refused = !res.ok() || (await res.json()).anonymous === true;
    expect(refused, "a deactivated member's session must no longer work").toBe(true);
    const members = await member.page.request.get("/api/v1/org/members");
    expect(members.ok()).toBe(false);
  });

  await test.step("removing them takes them off the list", async () => {
    await page.getByRole("button", { name: `Remove ${invitee.name}` }).click();
    await page.getByRole("button", { name: `Remove ${invitee.name} for good` }).click();
    await expect(page.getByRole("heading", { name: `${invitee.name} removed from the workspace`, exact: true })).toBeVisible();
    await expect(memberRow(page, email)).toHaveCount(0);
  });

  await test.step("a used link no longer works", async () => {
    const again = await stranger(browser);
    await again.page.goto(link);
    await expect(again.page.getByText("This invitation is not valid or has expired.")).toBeVisible();
    await again.context.close();
  });

  await member.context.close();
});

test("a revoked link shows the same generic error as any other", async ({ page, browser, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const email = unique("revoked");
  const link = await invite(page, email, "viewer");
  await page.getByRole("button", { name: "Done" }).click();

  await page.getByRole("button", { name: `Revoke the invitation for ${email}` }).click();
  await expect(page.getByRole("heading", { name: `Invitation for ${email} revoked`, exact: true })).toBeVisible();
  const listed = page.getByRole("list", { name: "Invitations" }).getByRole("listitem").filter({ hasText: email });
  // Exact: the address itself starts with "revoked".
  await expect(listed.getByText("revoked", { exact: true })).toBeVisible();

  const visitor = await stranger(browser);
  await visitor.page.goto(link);
  await expect(visitor.page.getByRole("alert")).toHaveText("This invitation is not valid or has expired.");
  // Whether it was revoked, expired or never existed is not the visitor's
  // business: a made-up token reads exactly the same.
  await visitor.page.goto("/invite/not-a-real-token");
  await expect(visitor.page.getByRole("alert")).toHaveText("This invitation is not valid or has expired.");
  await expectAccessible(visitor.page);
  await visitor.context.close();
});

test("the invite page states the workspace's own password rules, and an account made meanwhile is sent to sign in", async ({
  page,
  browser,
  workspace,
}) => {
  test.setTimeout(90_000);
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/security");
  await page.getByLabel("Minimum length").fill("16");
  await page.getByLabel("Character classes").fill("3");
  await page.getByRole("button", { name: "Save rules" }).click();
  await expect(page.getByRole("heading", { name: "Password rules saved", exact: true })).toBeVisible();

  const email = unique("meanwhile");
  const link = await invite(page, email, "viewer");
  const token = link.split("/invite/")[1];

  const visitor = await stranger(browser);
  await visitor.page.goto(link);
  await expect(
    visitor.page.getByText("At least 16 characters, using at least 3 of lower case, upper case, digits and symbols."),
  ).toBeVisible();
  await expect(visitor.page.getByLabel("Password")).toHaveAttribute("minlength", "16");
  await expectAccessible(visitor.page);

  // Somebody signs up with the invited address while the page is open, so
  // the account exists by the time the form is sent.
  const elsewhere = await stranger(browser);
  await signUp(elsewhere.page, { email, password: "Elsewhere Horse Battery 3", org: `Elsewhere ${Date.now()}` });
  await elsewhere.context.close();

  await visitor.page.getByLabel("Name").fill(invitee.name);
  await visitor.page.getByLabel("Password").fill(invitee.password);
  await visitor.page.getByRole("button", { name: "Create account and join" }).click();
  const alert = visitor.page.getByRole("alert");
  await expect(alert).toContainText("An account already exists for this email address. Sign in first");
  await expect(alert.getByRole("link", { name: "Sign in to accept" })).toHaveAttribute(
    "href",
    `/login?next=${encodeURIComponent(`/invite/${token}`)}`,
  );
  await expectAccessible(visitor.page);
  await visitor.context.close();
});
