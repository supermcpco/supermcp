import { test, expect, expectAccessible, closeSecret, createKey } from "./fixtures";
import { sql } from "./db";

// Creating a key needs a sign-in from the last few minutes. The Go tests
// prove the server refuses an older session; this proves a person is
// asked for their password where they are, and that the action they
// asked for then happens without them doing it again. The session is aged
// in the database because waiting five minutes is the one thing the
// product cannot do for a test.

test("a stale session is asked for the password and then gets the key", async ({ page, workspace }) => {
  const form = page.getByRole("dialog", { name: "New API key" });
  const secret = page.getByRole("dialog", { name: "Copy this key now" });
  const openForm = async () => {
    await page.getByRole("button", { name: "Create key" }).click();
    await expect(form).toBeVisible();
  };

  // Signed in a moment ago, so the first key needs nothing more.
  await createKey(page, "While fresh");
  await closeSecret(page);

  const aged = sql(
    `UPDATE sessions SET authenticated_at = now() - interval '10 minutes'
     WHERE user_id = (SELECT id FROM users WHERE email = $1) RETURNING id`,
    workspace.email,
  );
  expect(aged, "the session was not found to age").not.toEqual("");

  // Cancelling leaves the refusal on the form, in the server's words.
  await openForm();
  await form.getByLabel("Name").fill("After cancelling");
  await form.getByRole("button", { name: "Create key" }).click();
  const dialog = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(dialog).toBeVisible();
  await expectAccessible(page);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  await expect(form.getByRole("alert")).toContainText("sign in again");
  await expect(secret).toBeHidden();

  // Asked again; a wrong password is refused where it was typed.
  await form.getByRole("button", { name: "Create key" }).click();
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Password").fill("not my password");
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog.getByRole("alert")).toContainText("not your current password");
  await expect(dialog).toBeVisible();

  // The right one, and the key arrives without pressing Create again.
  await dialog.getByLabel("Password").fill(workspace.password);
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog).toBeHidden();
  await expect(secret).toBeVisible();
  await expect(form).toBeHidden();
  // Listed under the name typed before the dialog: the same request, sent once more.
  await closeSecret(page);
  await expect(page.getByRole("button", { name: "Revoke After cancelling" })).toBeVisible();

  // Fresh again: the next sensitive action goes straight through.
  await openForm();
  await form.getByLabel("Name").fill("Straight through");
  await form.getByRole("button", { name: "Create key" }).click();
  await expect(secret).toBeVisible();
  await expect(dialog).toBeHidden();
});

// The server sends a browser to /reauth when there is no screen of ours
// to open the dialog on: the OAuth consent page, and a provider sign-in
// that did not confirm a recent sign-in. It says why, takes the password,
// and goes on to where it was sent from.
test("the re-authentication page explains a refusal and returns to where it was sent from", async ({
  page,
  workspace,
}) => {
  sql(
    `UPDATE sessions SET authenticated_at = now() - interval '10 minutes'
     WHERE user_id = (SELECT id FROM users WHERE email = $1)`,
    workspace.email,
  );
  await page.goto("/reauth?error=reauth_not_recent&next=%2Fapi-keys");
  await expect(page.getByRole("heading", { name: "Confirm it is you" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("answered from an earlier sign-in");
  await expectAccessible(page);

  await page.getByLabel("Password").fill(workspace.password);
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page).toHaveURL(/\/api-keys$/);
  await page.getByRole("button", { name: "Create key" }).click();
  const form = page.getByRole("dialog", { name: "New API key" });
  await form.getByLabel("Name").fill("After the page");
  await form.getByRole("button", { name: "Create key" }).click();
  // Straight to the secret: no question asked in between.
  await expect(page.getByRole("dialog", { name: "Copy this key now" })).toBeVisible();
  await expect(page.getByRole("dialog", { name: "Confirm it is you" })).toBeHidden();
});
