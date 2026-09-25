import type { Browser, Page } from "@playwright/test";
import { test, expect, expectAccessible } from "./fixtures";

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
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Role", { exact: true }).selectOption({ label: role });
  await page.getByLabel("Link works for (days)").fill("3");
  await page.getByRole("button", { name: "Create invitation link" }).click();
  await expect(page.getByText("This link is shown once. Send it to the person yourself; no email is sent.")).toBeVisible();
  const url = (await page.getByTestId("invite-url").textContent())?.trim() ?? "";
  expect(url).toMatch(/\/invite\/[A-Za-z0-9_-]+$/);
  return url;
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

    // One open invitation per address.
    await page.getByRole("button", { name: "Done" }).click();
    await page.getByLabel("Email", { exact: true }).fill(email);
    await page.getByLabel("Role", { exact: true }).selectOption({ label: "viewer" });
    await page.getByRole("button", { name: "Create invitation link" }).click();
    await expect(page.getByRole("alert").filter({ hasText: /already open/ })).toBeVisible();
  });

  const member = await stranger(browser);
  await test.step("the invited person registers from the link and lands signed in", async () => {
    await member.page.goto(link);
    await expect(member.page.getByRole("heading", { name: `Join ${workspace.org}` })).toBeVisible();
    await expect(member.page.getByText(email).first()).toBeVisible();
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
    await expect(row.getByText(invitee.name)).toBeVisible();
    await expect(row.getByRole("list", { name: `Roles of ${invitee.name}` }).getByText("viewer")).toBeVisible();
    await expect(row.getByText("Password", { exact: true })).toBeVisible();
    await expect(row.getByText("active", { exact: true })).toBeVisible();
  });

  await test.step("the owner changes their role", async () => {
    await page.getByLabel(`Role for ${invitee.name}`).selectOption({ label: "editor" });
    await page.getByRole("button", { name: `Change ${invitee.name}'s role` }).click();
    const roles = memberRow(page, email).getByRole("list", { name: `Roles of ${invitee.name}` });
    await expect(roles.getByText("editor")).toBeVisible();
    await expect(roles.getByText("viewer")).toHaveCount(0);
  });

  await test.step("deactivating them ends their session", async () => {
    await page.getByRole("button", { name: `Deactivate ${invitee.name}` }).click();
    await page.getByRole("button", { name: `Yes, deactivate ${invitee.name}` }).click();
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
  const listed = page.getByRole("list", { name: "Invitations" }).getByRole("listitem").filter({ hasText: email });
  await expect(listed.getByText("revoked")).toBeVisible();

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
