import { test, expect, expectAccessible } from "./fixtures";

// An OpenID Connect provider's second-factor rule: what its ID token has to
// say for a sign-in to count as having a second factor. No provider is
// reachable from CI, and none is needed: the rule is configuration, and
// the sign-in that reads it is covered by the Go end-to-end tests.

test("an administrator sets which answers from a provider count as a second factor", async ({ page, workspace }) => {
  expect(workspace.org).toBeTruthy();
  await page.goto("/settings/sso");
  await expect(page.getByRole("tab", { name: "Single sign-on", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("button", { name: "New OpenID Connect provider" }).first().click();
  const add = page.getByRole("dialog", { name: "Add a provider" }).getByRole("form", { name: "Add a provider" });
  await expect(add.getByLabel("Second factor: amr values that count")).toHaveValue("mfa, otp, hwk, sc");

  await add.getByLabel("Provider").selectOption({ label: "Okta" });
  await add.getByLabel("Name").fill("Company Okta");
  await add.getByLabel("Issuer URL").fill("https://example.okta.test/oauth2/default");
  await add.getByLabel("Client ID").fill("okta-client");
  await add.getByLabel("Client secret").fill("okta-client-secret"); // gitleaks:allow
  await add.getByLabel("Second factor: amr values that count").fill("mfa, hwk");
  await add.getByLabel("Second factor: acr values that count").fill("phr");
  await add.getByRole("button", { name: "Add provider" }).click();
  await expect(add).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Provider Company Okta added", exact: true })).toBeVisible();
  await expect(page.getByText("Second factor: amr mfa, hwk or acr phr")).toBeVisible();
  await expectAccessible(page);

  // The rule is changed in a dialog opened from the provider's card. A
  // password is the first factor, and the server says so in the dialog.
  const edit = page.getByRole("button", { name: "Edit the second-factor rule of Company Okta" });
  await edit.click();
  const rule = page.getByRole("dialog", { name: "Edit the second-factor rule of Company Okta" });
  await expect(rule.getByLabel("Second factor: amr values that count")).toHaveValue("mfa, hwk");
  await expectAccessible(page);
  await rule.getByLabel("Second factor: amr values that count").fill("pwd");
  await rule.getByRole("button", { name: "Save second-factor rule" }).click();
  await expect(rule.getByRole("alert")).toContainText("pwd");

  // Counting by acr alone.
  await rule.getByLabel("Second factor: amr values that count").fill("");
  await rule.getByLabel("Second factor: acr values that count").fill("phr, urn:okta:loa:2fa:any");
  await rule.getByRole("button", { name: "Save second-factor rule" }).click();
  await expect(page.getByText("Second factor: acr phr, urn:okta:loa:2fa:any")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Second-factor rule of Company Okta saved", exact: true }).first(),
  ).toBeVisible();
  await expect(rule).toBeHidden();
  await expect(edit).toBeFocused();

  // No rule at all is allowed, and the screen says what it means. Saving
  // it changes the rule only: a colleague turning the provider off while
  // the editor is open is not undone.
  await edit.click();
  await expect(rule.getByLabel("Second factor: acr values that count")).toHaveValue("phr, urn:okta:loa:2fa:any");
  const origin = new URL(page.url()).origin;
  const listed = await (await page.request.get("/api/v1/idps")).json();
  const okta = listed.providers.find((p: { name: string }) => p.name === "Company Okta");
  const off = await page.request.put(`/api/v1/idps/${okta.id}`, {
    headers: { Origin: origin },
    data: { name: "Company Okta", preset: "okta", issuer: okta.issuer, clientId: okta.clientId, enabled: false },
  });
  expect(off.status()).toBe(200);
  await rule.getByLabel("Second factor: acr values that count").fill("");
  await rule.getByRole("button", { name: "Save second-factor rule" }).click();
  await expect(page.getByText("Second factor: no rule, so no sign-in counts as one")).toBeVisible();
  await expect(rule).toBeHidden();
  await expect(page.getByText("off", { exact: true })).toBeVisible();

  // The rule is part of the provider's history.
  await page.getByRole("button", { name: "History of Company Okta" }).click();
  await expect(page.getByRole("region", { name: "History of Company Okta" })).toBeVisible();
});
