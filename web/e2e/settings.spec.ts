import type { Browser, Page } from "@playwright/test";
import { test, expect, expectAccessible, createKey, signIn } from "./fixtures";

// The settings screens, driven the way an administrator drives them. Each
// assertion is about what the person sees, not about the shape of a JSON
// response, because the response was already right when the screen that
// showed it was unreachable.

test("the audit trail records what the administrator just did", async ({ page, workspace }) => {
  await createKey(page, "Audited key");

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
  await expect(page.getByRole("heading", { name: "Password rules saved", exact: true })).toBeVisible();

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
  await expect(
    page.getByRole("heading", { name: "Password changed, and your other devices have been signed out", exact: true }),
  ).toBeVisible();

  // And the new password is the one that works.
  await page.context().clearCookies();
  await signIn(page, { ...workspace, password: next });
});

test("a service account is created with a secret shown once", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/service-accounts");
  await expect(page.getByRole("heading", { name: "Service accounts" })).toBeVisible();
  // An empty screen offers the same button in its header and in the
  // empty state; the header's comes first.
  await page.getByRole("button", { name: "New service account" }).first().click();
  const dialog = page.getByRole("dialog", { name: "New service account" });
  await dialog.getByLabel("Name").fill("Nightly export");
  await dialog.getByRole("button", { name: "Create account" }).click();

  // The secret is shown on the screen once the dialog has gone, not in it.
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Service account Nightly export created", exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText(/copy this secret now/i);
  const shown = await page.getByRole("alert").locator("code").innerText();
  expect(shown).toContain("client_id: sms_");
  expect(shown).toContain("client_secret: ");

  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByText("Nightly export", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByRole("heading", { name: "Nightly export disabled", exact: true })).toBeVisible();

  // Reloading must not show the secret again.
  await page.reload();
  await expect(page.getByText(/client_secret:/)).toHaveCount(0);

  // Deleting asks first, and goes ahead only once the name is typed.
  await page.getByRole("button", { name: "Delete Nightly export" }).click();
  const confirm = page.getByRole("dialog", { name: "Delete Nightly export" });
  await confirm.getByRole("textbox", { name: "Type Nightly export to confirm deletion" }).fill("Nightly export");
  await confirm.getByRole("button", { name: "Delete service account" }).click();
  await expect(confirm).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Service account Nightly export deleted", exact: true })).toBeVisible();
  await expect(page.getByText("No service accounts yet.")).toBeVisible();
});

test("the single sign-on screen tells an administrator what to register", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/sso");
  await expect(page.getByRole("heading", { name: "Single sign-on" })).toBeVisible();
  await expect(page.getByText("/auth/sso/callback")).toBeVisible();
  await expect(page.getByText("/scim/v2")).toBeVisible();
  await expectAccessible(page);

  // An issuer that does not exist must fail in the form rather than at
  // someone's first sign-in.
  await page.getByRole("button", { name: "New OpenID Connect provider" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add a provider" });
  await expect(dialog.getByText("/auth/sso/callback")).toBeVisible();
  await expectAccessible(page);
  await dialog.getByLabel("Issuer URL").fill("https://localhost:9/not-a-provider");
  await dialog.getByRole("button", { name: /test this issuer/i }).click();
  await expect(dialog.getByRole("alert")).toBeVisible({ timeout: 15_000 });
});

test("signing out ends the session", async ({ page, workspace }) => {
  await page.goto("/");
  await expect(page.getByText(workspace.org)).toBeVisible();
  await page.context().clearCookies();
  await page.goto("/connectors");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(0);
});

// Settings is one screen of tabs. Each tab kept the address it had as a
// screen of its own, so a bookmark from before still lands on it.
const oldAddresses: [string, string][] = [
  ["/settings/members", "Members"],
  ["/settings/roles", "Roles"],
  ["/settings/security", "Security"],
  ["/settings/audit", "Audit"],
  ["/settings/dlp", "Data-loss rules"],
  ["/settings/sso", "Single sign-on"],
  ["/settings/service-accounts", "Service accounts"],
  ["/settings/instance", "Instance"],
];

/** The settings tab strip's tab of this name, matched whole. */
function settingsTab(page: Page, name: string) {
  return page.getByRole("tab", { name, exact: true });
}

test("settings opens as tabs and each old address lands on its tab", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const nav = page.getByRole("navigation", { name: "Primary" });

  // One item in the sidebar, and it opens on the first tab.
  await nav.getByRole("link", { name: "Settings", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\/members$/);
  await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();
  await expect(settingsTab(page, "Members")).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("tabpanel", { name: "Members" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Settings", exact: true })).toHaveAttribute("aria-current", "page");
  // An owner may read every tab.
  for (const [, tab] of oldAddresses) await expect(settingsTab(page, tab)).toBeVisible();
  await expectAccessible(page);

  for (const [address, tab] of oldAddresses) {
    await page.goto(address);
    await expect(settingsTab(page, tab), `${address} opens ${tab}`).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tabpanel", { name: tab })).toBeVisible();
    // Only one tab is open at a time.
    await expect(page.getByRole("tab", { selected: true }).filter({ hasText: tab })).toHaveCount(1);
  }

  // The status screen became the Instance tab; its old address leads there.
  await page.goto("/status");
  await expect(page).toHaveURL(/\/settings\/instance$/);
  await expect(settingsTab(page, "Instance")).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText(/This instance is running version/)).toBeVisible();

  // Tabs are links: picking one moves the address, and Back moves it back.
  await page.goto("/settings/members");
  await settingsTab(page, "Roles").click();
  await expect(page).toHaveURL(/\/settings\/roles$/);
  await expect(page.getByRole("tabpanel", { name: "Roles" }).getByRole("heading", { name: "Roles" })).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL(/\/settings\/members$/);
  await expect(settingsTab(page, "Members")).toHaveAttribute("aria-selected", "true");

  // The arrow keys move along the strip, and Enter opens the tab.
  await settingsTab(page, "Members").focus();
  await page.keyboard.press("ArrowRight");
  await expect(settingsTab(page, "Roles")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/settings\/roles$/);

  // A page beneath a tab keeps both the tab and the sidebar item current.
  await page.goto("/settings/audit/retention");
  await expect(settingsTab(page, "Audit")).toHaveAttribute("aria-selected", "true");
  await expect(nav.getByRole("link", { name: "Settings", exact: true })).toHaveAttribute("aria-current", "page");
});

/** A browser with no cookies: the person an invitation link was sent to. */
async function stranger(browser: Browser) {
  const context = await browser.newContext();
  return { context, page: await context.newPage() };
}

test("a viewer sees only the settings tabs they may read", async ({ page, browser, workspace }) => {
  test.setTimeout(90_000);
  // A viewer joins the way anybody does: from an invitation link.
  const email = `viewer-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.test`;
  await page.goto("/settings/members");
  await page.getByRole("button", { name: "Invite someone" }).first().click();
  const invite = page.getByRole("dialog", { name: "Invite someone" });
  await invite.getByLabel("Email", { exact: true }).fill(email);
  await invite.getByLabel("Role", { exact: true }).selectOption({ label: "viewer" });
  await invite.getByRole("button", { name: "Create invitation link" }).click();
  await expect(invite).toHaveCount(0);
  const banner = page.getByRole("alert").filter({ hasText: `Copy the invitation link for ${email} now` });
  const link = (await banner.getByText(/\/invite\/[A-Za-z0-9_-]+$/).textContent())?.trim() ?? "";
  expect(link).toMatch(/\/invite\//);

  const viewer = await stranger(browser);
  await viewer.page.goto(link);
  await viewer.page.getByLabel("Name").fill("Vera Viewer");
  await viewer.page.getByLabel("Password").fill("Viewer Horse Battery 5");
  await viewer.page.getByRole("button", { name: "Create account and join" }).click();
  await expect(viewer.page.getByText(workspace.org, { exact: false }).first()).toBeVisible();

  // Settings is in the sidebar for everyone, and opens on the first tab
  // this person may read.
  const nav = viewer.page.getByRole("navigation", { name: "Primary" });
  await nav.getByRole("link", { name: "Settings", exact: true }).click();
  await expect(viewer.page).toHaveURL(/\/settings\/members$/);
  const tabs = viewer.page.getByRole("tab");
  await expect(tabs).toHaveText(["Members", "Roles", "Security", "Data-loss rules", "Instance"]);
  for (const hidden of ["Audit", "Single sign-on", "Service accounts"]) {
    await expect(settingsTab(viewer.page, hidden)).toHaveCount(0);
  }
  await expectAccessible(viewer.page);

  // A tab they may not read is not offered, and its address says why
  // there is nothing to see rather than showing a column of refusals.
  await viewer.page.goto("/settings/sso");
  await expect(viewer.page.getByText("You do not have permission to manage how people sign in.", { exact: false })).toBeVisible();
  await expect(viewer.page.getByRole("tab", { selected: true })).toHaveCount(0);
  await viewer.page.goto("/settings/audit");
  await expect(viewer.page.getByText("You do not have permission to read the audit trail for this workspace.")).toBeVisible();
  await expect(viewer.page.getByRole("tab", { name: "Log" })).toHaveCount(0);
  await viewer.context.close();
});

test("audit retention and shipping sit on their own tabs and still save", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/audit");
  const logTab = page.getByRole("tab", { name: "Log", exact: true });
  const retentionTab = page.getByRole("tab", { name: "Retention", exact: true });
  const shippingTab = page.getByRole("tab", { name: "Shipping", exact: true });
  await expect(logTab).toHaveAttribute("aria-selected", "true");
  // The log is the chain, the filters and the table, and nothing else.
  await expect(page.getByText("The chain is intact")).toBeVisible();
  await expect(page.getByRole("searchbox", { name: "Search" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "What tool calls record" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Where it is shipped" })).toHaveCount(0);

  // Retention: the days, the hold, and what a tool call records.
  await retentionTab.click();
  await expect(page).toHaveURL(/\/settings\/audit\/retention$/);
  await expect(retentionTab).toHaveAttribute("aria-selected", "true");
  const panel = page.getByRole("tabpanel", { name: "Retention" });
  await expect(panel.getByRole("heading", { name: "How long it is kept" })).toBeVisible();
  await expect(panel.getByRole("heading", { name: "Hold against deletion" })).toBeVisible();
  await expect(panel.getByRole("heading", { name: "What tool calls record" })).toBeVisible();
  await expect(page.getByRole("searchbox", { name: "Search" })).toHaveCount(0);
  await expectAccessible(page);

  const range = await (await page.request.get("/api/v1/audit/retention")).json();
  const days = Math.min(range.maxDays, Math.max(range.minDays, range.days + 1));
  await panel.getByLabel("Days").fill(String(days));
  const [saved] = await Promise.all([
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/audit/retention" && r.request().method() === "PUT"),
    panel.getByRole("button", { name: "Save", exact: true }).click(),
  ]);
  expect(saved.ok(), await saved.text()).toBe(true);
  await expect(page.getByRole("heading", { name: `Events now keep their content for ${days} days`, exact: true })).toBeVisible();

  // The choice is saved as it is made, and shows as chosen once saved.
  await panel.getByRole("radio", { name: /Masked values/ }).click();
  await expect(page.getByRole("heading", { name: "Tool calls now record: Masked values", exact: true })).toBeVisible();
  await expect(panel.getByRole("radio", { name: /Masked values/ })).toBeChecked();

  await panel.getByLabel("From").fill("2026-01-01");
  await panel.getByLabel("Why").fill("Quarterly review");
  await panel.getByRole("button", { name: "Hold", exact: true }).click();
  await expect(page.getByRole("heading", { name: /^\d+ events are now held$/ })).toBeVisible();

  // What was saved is what the tab shows after a reload.
  await page.reload();
  await expect(panel.getByLabel("Days")).toHaveValue(String(days));
  await expect(panel.getByRole("radio", { name: /Masked values/ })).toBeChecked();

  // Shipping: where a copy of the trail goes.
  await shippingTab.click();
  await expect(page).toHaveURL(/\/settings\/audit\/shipping$/);
  const shipping = page.getByRole("tabpanel", { name: "Shipping" });
  await expect(shipping.getByRole("heading", { name: "Where it is shipped" })).toBeVisible();
  await expect(shipping.getByText("The trail is not being shipped anywhere.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "How long it is kept" })).toHaveCount(0);
  await shipping.getByLabel("Destination").fill("https://siem.example/ingest");
  await shipping.getByLabel("Signing secret (never shown again)").fill("a-secret-of-sufficient-length");
  await shipping.getByRole("button", { name: "Ship the trail here" }).click();
  await expect(page.getByRole("heading", { name: "The trail now ships to https://siem.example/ingest", exact: true })).toBeVisible();
  await expect(shipping.getByText("https://siem.example/ingest", { exact: true })).toBeVisible();
  await expectAccessible(page);

  // The long explanation is one question away, not in the way.
  await shipping.getByRole("button", { name: "About shipping" }).click();
  await expect(page.getByRole("dialog", { name: "About shipping" }).getByText(/X-Supermcp-Signature/)).toBeVisible();
  await page.keyboard.press("Escape");

  await shipping.getByRole("button", { name: "Stop" }).click();
  await expect(
    page.getByRole("heading", { name: "Stopped shipping the trail to https://siem.example/ingest", exact: true }),
  ).toBeVisible();
  await expect(shipping.getByText("The trail is not being shipped anywhere.")).toBeVisible();
});

test("removing a provider, a rule and a service account each ask first", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  // An OpenID Connect provider.
  await page.goto("/settings/sso");
  await page.getByRole("button", { name: "New OpenID Connect provider" }).first().click();
  const add = page.getByRole("dialog", { name: "Add a provider" }).getByRole("form", { name: "Add a provider" });
  await add.getByLabel("Provider").selectOption({ label: "Okta" });
  await add.getByLabel("Name").fill("Doomed Okta");
  await add.getByLabel("Issuer URL").fill("https://doomed.okta.test/oauth2/default");
  await add.getByLabel("Client ID").fill("doomed-client");
  await add.getByRole("button", { name: "Add provider" }).click();
  await expect(page.getByRole("heading", { name: "Provider Doomed Okta added", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Remove Doomed Okta" }).click();
  const provider = page.getByRole("dialog", { name: "Delete Doomed Okta" });
  const removeProvider = provider.getByRole("button", { name: "Remove provider" });
  await expect(removeProvider).toBeDisabled();
  await expectAccessible(page);
  // Changing one's mind removes nothing.
  await provider.getByRole("button", { name: "Cancel" }).click();
  await expect(provider).toHaveCount(0);
  const kept = await (await page.request.get("/api/v1/idps")).json();
  expect(kept.providers.map((p: { name: string }) => p.name)).toContain("Doomed Okta");

  await page.getByRole("button", { name: "Remove Doomed Okta" }).click();
  await provider.getByRole("textbox", { name: "Type Doomed Okta to confirm deletion" }).fill("Doomed Okta");
  await removeProvider.click();
  await expect(provider).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Provider Doomed Okta removed", exact: true })).toBeVisible();
  await expect(page.getByText("No providers yet.")).toBeVisible();

  // A data-loss rule.
  await page.goto("/settings/dlp");
  await page.getByRole("button", { name: "New rule" }).first().click();
  const addRule = page.getByRole("dialog", { name: "Add a rule" });
  await addRule.getByLabel("What it is for").fill("Doomed rule");
  await addRule.getByRole("button", { name: "Add the rule" }).click();
  await expect(page.getByRole("heading", { name: "Rule Doomed rule added", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Delete Doomed rule" }).click();
  const rule = page.getByRole("dialog", { name: "Delete Doomed rule" });
  await expect(rule.getByRole("button", { name: "Delete rule" })).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(rule).toHaveCount(0);
  await expect(page.getByText("Doomed rule", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Delete Doomed rule" }).click();
  await rule.getByRole("textbox", { name: "Type Doomed rule to confirm deletion" }).fill("Doomed rule");
  await rule.getByRole("button", { name: "Delete rule" }).click();
  await expect(page.getByRole("heading", { name: "Rule Doomed rule deleted", exact: true })).toBeVisible();
  await expect(page.getByText("No rules yet, so nothing is inspected and nothing is masked.")).toBeVisible();

  // A service account.
  await page.goto("/settings/service-accounts");
  await page.getByRole("button", { name: "New service account" }).first().click();
  const newAccount = page.getByRole("dialog", { name: "New service account" });
  await newAccount.getByLabel("Name").fill("Doomed pipeline");
  await newAccount.getByRole("button", { name: "Create account" }).click();
  await expect(newAccount).toHaveCount(0);
  await page.getByRole("button", { name: "Done" }).click();

  await page.getByRole("button", { name: "Delete Doomed pipeline" }).click();
  const account = page.getByRole("dialog", { name: "Delete Doomed pipeline" });
  await account.getByRole("button", { name: "Cancel" }).click();
  await expect(account).toHaveCount(0);
  const accounts = await (await page.request.get("/api/v1/service-accounts")).json();
  expect(accounts.accounts.map((a: { name: string }) => a.name)).toEqual(["Doomed pipeline"]);

  await page.getByRole("button", { name: "Delete Doomed pipeline" }).click();
  await account.getByRole("textbox", { name: "Type Doomed pipeline to confirm deletion" }).fill("Doomed pipeline");
  await account.getByRole("button", { name: "Delete service account" }).click();
  await expect(page.getByRole("heading", { name: "Service account Doomed pipeline deleted", exact: true })).toBeVisible();
  await expect(page.getByText("No service accounts yet.")).toBeVisible();
});
