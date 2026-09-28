import { test, expect, expectAccessible, closeSecret, createKey, createServer, installAdapter, pickOption } from "./fixtures";
import { sql } from "./db";

// Rotating a key is done by someone with a client in production: they need
// the new secret once, and to know how long they have before the old one
// stops. This drives that from the button to the MCP endpoint.

test("a key is rotated with a grace period and the old one stops after it", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();

  // A server to present the keys to. A keyless adapter, so no credentials.
  await installAdapter(page);
  const serverId = await createServer(page, "Rotation server", [/Deutsche Bundesbank Statistics/]);
  const listTools = (key: string) =>
    request.post(`/mcp/${serverId}`, {
      headers: { "X-API-Key": key, Accept: "application/json, text/event-stream" },
      data: { jsonrpc: "2.0", id: 1, method: "tools/list" },
    });

  const oldSecret = await createKey(page, "Rotating key");
  const oldPrefix = oldSecret.slice(4, 16);
  await closeSecret(page);

  // Asking first, and cancelling leaves everything as it was.
  await page.getByRole("button", { name: "Rotate Rotating key" }).click();
  await expect(page.getByLabel("Old key keeps working for")).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByLabel("Old key keeps working for")).toHaveCount(0);

  await page.getByRole("button", { name: "Rotate Rotating key" }).click();
  await pickOption(page, "Old key keeps working for", "1 hour");
  await page.getByRole("button", { name: "Rotate Rotating key" }).click();
  await expect(page.getByRole("heading", { name: "API key Rotating key rotated", exact: true })).toBeVisible();

  // The new secret, shown once, in the dialog a new key's secret is shown
  // in, with when the old one stops.
  const shown = page.getByRole("dialog", { name: "Copy this key now" });
  await expect(shown).toBeVisible();
  await expect(shown).toContainText(`smk_${oldPrefix}`);
  await expect(shown).toContainText(/stops working at/i);
  const newSecret = await shown.getByLabel("Secret", { exact: true }).inputValue();
  expect(newSecret).toMatch(/^smk_/);
  expect(newSecret).not.toBe(oldSecret);

  // Both work inside the grace period.
  expect((await listTools(oldSecret)).ok(), "the old key was refused inside its grace period").toBeTruthy();
  expect((await listTools(newSecret)).ok(), "the new key was refused").toBeTruthy();

  // Past the grace period only the new one does.
  sql(`UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE prefix = $1`, oldPrefix);
  expect((await listTools(oldSecret)).status()).toBe(401);
  expect((await listTools(newSecret)).ok(), "the new key stopped with the old one").toBeTruthy();

  // Reloading must not show the secret again, and the lapsed key is no
  // longer offered for rotation.
  await page.reload();
  await expect(page.getByText(newSecret)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Rotate Rotating key" })).toHaveCount(1);

  await page.goto("/settings/audit");
  await expect(page.getByText("apikey.rotate")).toBeVisible();
  await expect(page.getByText(newSecret)).toHaveCount(0);
});

test("revoking a key asks first, says so, and the key stops working", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();

  await installAdapter(page);
  const serverId = await createServer(page, "Revocation server", [/Deutsche Bundesbank Statistics/]);
  const listTools = (key: string) =>
    request.post(`/mcp/${serverId}`, {
      headers: { "X-API-Key": key, Accept: "application/json, text/event-stream" },
      data: { jsonrpc: "2.0", id: 1, method: "tools/list" },
    });

  const secret = await createKey(page, "Leaving key");
  await closeSecret(page);
  expect((await listTools(secret)).ok(), "the new key was refused").toBeTruthy();
  const row = page.getByRole("listitem").filter({ hasText: "Leaving key" });

  // Asking first, and changing one's mind revokes nothing.
  await page.getByRole("button", { name: "Revoke Leaving key", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Revoke Leaving key?" });
  await expect(dialog).toBeVisible();
  // Revoking is not deleting: no name to type before the button works.
  await expect(dialog.getByRole("textbox")).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Revoke", exact: true })).toBeEnabled();
  await expectAccessible(page);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  await expect(row.getByText("revoked", { exact: true })).toHaveCount(0);
  expect((await listTools(secret)).ok(), "cancelling revoked the key").toBeTruthy();

  await page.getByRole("button", { name: "Revoke Leaving key", exact: true }).click();
  const revoked = page.waitForResponse(
    (r) => /\/api\/v1\/api-keys\/[^/]+$/.test(r.url()) && r.request().method() === "DELETE",
  );
  await dialog.getByRole("button", { name: "Revoke", exact: true }).click();
  expect((await revoked).status()).toBeLessThan(300);
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("heading", { name: "API key Leaving key revoked", exact: true })).toBeVisible();
  await expect(row.getByText("revoked", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke Leaving key", exact: true })).toHaveCount(0);
  expect((await listTools(secret)).status()).toBe(401);
});
