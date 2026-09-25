import { test, expect, expectAccessible } from "./fixtures";
import { sql } from "./db";

// Rotating a key is done by someone with a client in production: they need
// the new secret once, and to know how long they have before the old one
// stops. This drives that from the button to the MCP endpoint.

test("a key is rotated with a grace period and the old one stops after it", async ({ page, request, workspace }) => {
  expect(workspace.email).toBeTruthy();

  // A server to present the keys to. A keyless adapter, so no credentials.
  await page.goto("/catalog");
  await page.getByRole("link", { name: /Deutsche Bundesbank Statistics/ }).click();
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);
  await page.goto("/servers");
  await page.getByLabel("Name").fill("Rotation server");
  await page.getByRole("checkbox", { name: /Deutsche Bundesbank Statistics/ }).check();
  await page.getByRole("button", { name: "Create server" }).click();
  const endpoint = await page.locator("code", { hasText: "/mcp/" }).first().innerText();
  const serverId = endpoint.trim().split("/mcp/")[1];
  const listTools = (key: string) =>
    request.post(`/mcp/${serverId}`, {
      headers: { "X-API-Key": key, Accept: "application/json, text/event-stream" },
      data: { jsonrpc: "2.0", id: 1, method: "tools/list" },
    });

  await page.goto("/api-keys");
  await page.getByLabel("Name").fill("Rotating key");
  await page.getByRole("button", { name: "Create key" }).click();
  await expect(page.getByRole("heading", { name: /copy this key now/i })).toBeVisible();
  const oldSecret = (await page.locator("code").first().innerText()).trim();
  const oldPrefix = oldSecret.slice(4, 16);
  await page.getByRole("button", { name: "Done" }).click();

  // Asking first, and cancelling leaves everything as it was.
  await page.getByRole("button", { name: "Rotate Rotating key" }).click();
  await expect(page.getByLabel("Old key keeps working for")).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByLabel("Old key keeps working for")).toHaveCount(0);

  await page.getByRole("button", { name: "Rotate Rotating key" }).click();
  await page.getByLabel("Old key keeps working for").selectOption({ label: "1 hour" });
  await page.getByRole("button", { name: "Rotate Rotating key" }).click();

  // The new secret, shown once, where a new key's secret is shown, with
  // when the old one stops.
  const shown = page.getByRole("alert").filter({ hasText: /copy this key now/i });
  await expect(shown).toBeVisible();
  await expect(shown).toContainText(`smk_${oldPrefix}`);
  await expect(shown).toContainText(/stops working at/i);
  const newSecret = (await shown.locator("code").first().innerText()).trim();
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
