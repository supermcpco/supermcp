import { test, expect, expectAccessible } from "./fixtures";
import { sql } from "./db";

// Creating a key needs a sign-in from the last few minutes. The Go tests
// prove the server refuses an older session; this proves a person is
// asked for their password where they are, and that the action they
// asked for then happens without them doing it again. The session is aged
// in the database because waiting five minutes is the one thing the
// product cannot do for a test.

test("a stale session is asked for the password and then gets the key", async ({ page, workspace }) => {
  // Signed in a moment ago, so the first key needs nothing more.
  await page.goto("/api-keys");
  await page.getByLabel("Name").fill("While fresh");
  await page.getByRole("button", { name: "Create key" }).click();
  await expect(page.getByRole("heading", { name: "Copy this key now" })).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();

  const aged = sql(
    `UPDATE sessions SET authenticated_at = now() - interval '10 minutes'
     WHERE user_id = (SELECT id FROM users WHERE email = $1) RETURNING id`,
    workspace.email,
  );
  expect(aged, "the session was not found to age").not.toEqual("");

  // Cancelling leaves the refusal on the screen, in the server's words.
  await page.getByLabel("Name").fill("After cancelling");
  await page.getByRole("button", { name: "Create key" }).click();
  const dialog = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(dialog).toBeVisible();
  await expectAccessible(page);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("alert")).toContainText("sign in again");
  await expect(page.getByRole("heading", { name: "Copy this key now" })).toBeHidden();

  // Asked again; a wrong password is refused where it was typed.
  await page.getByRole("button", { name: "Create key" }).click();
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Password").fill("not my password");
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog.getByRole("alert")).toContainText("not your current password");
  await expect(dialog).toBeVisible();

  // The right one, and the key arrives without pressing Create again.
  await dialog.getByLabel("Password").fill(workspace.password);
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("heading", { name: "Copy this key now" })).toBeVisible();
  // Listed under the name typed before the dialog: the same request, sent once more.
  await expect(page.getByRole("button", { name: "Revoke After cancelling" })).toBeVisible();

  // Fresh again: the next sensitive action goes straight through.
  await page.getByRole("button", { name: "Done" }).click();
  await page.getByLabel("Name").fill("Straight through");
  await page.getByRole("button", { name: "Create key" }).click();
  await expect(page.getByRole("heading", { name: "Copy this key now" })).toBeVisible();
  await expect(dialog).toBeHidden();
});
