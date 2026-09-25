import { test, expect, expectAccessible } from "./fixtures";

// Whether a server keeps a session per client is set from the server
// list. What a session does is covered by the Go tests; what matters here
// is that the setting can be changed from the screen, is stored, and
// tells the person changing it what it asks of the load balancer.

test("a server can be switched to stateful sessions and back", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  await page.goto("/servers");
  await page.getByLabel("Name").fill("Session server");
  await page.getByRole("button", { name: "Create server" }).click();
  const row = page.getByRole("listitem").filter({ hasText: "Session server" });
  const sessions = row.getByLabel("Sessions");
  await expect(sessions).toHaveValue("stateless");
  await expect(row.getByText(/sticky routing/)).toHaveCount(0);

  await sessions.selectOption("stateful");
  await expect(row.getByText(/sticky routing/)).toBeVisible();
  await expectAccessible(page);

  // Stored, not just shown: a reload reads it back, and so does the API.
  await page.reload();
  await expect(page.getByRole("listitem").filter({ hasText: "Session server" }).getByLabel("Sessions")).toHaveValue(
    "stateful",
  );
  const endpoint = await row.locator("code", { hasText: "/mcp/" }).innerText();
  const serverId = endpoint.trim().split("/mcp/")[1];
  const stored = await (await page.request.get(`/api/v1/servers/${serverId}`)).json();
  expect(stored.sessions).toBe("stateful");

  await row.getByLabel("Sessions").selectOption("stateless");
  await expect(row.getByText(/sticky routing/)).toHaveCount(0);
  await expect(row.getByLabel("Sessions")).toHaveValue("stateless");
});
