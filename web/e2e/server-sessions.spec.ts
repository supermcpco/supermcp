import { test, expect, expectAccessible, createServer, pickOption } from "./fixtures";

// Whether a server keeps a session per client is set from the server
// list. What a session does is covered by the Go tests; what matters here
// is that the setting can be changed from the screen, is stored, and
// tells the person changing it what it asks of the load balancer.

test("a server can be switched to stateful sessions and back", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  const serverId = await createServer(page, "Session server");
  const row = page.getByRole("listitem").filter({ hasText: "Session server" });
  const sessions = row.getByLabel("Sessions");
  await expect(sessions).toHaveText("Stateless: any replica answers");
  // Named by its label alone, not by the text of every option inside it.
  await expect(row.getByRole("combobox", { name: "Sessions", exact: true })).toBeVisible();
  await expect(row.getByText(/sticky routing/)).toHaveCount(0);

  await pickOption(page, sessions, "Stateful: can ask the client to confirm");
  await expect(page.getByRole("heading", { name: "Session server now uses stateful sessions", exact: true })).toBeVisible();
  await expect(row.getByText(/sticky routing/)).toBeVisible();
  await expectAccessible(page);

  // Stored, not just shown: a reload reads it back, and so does the API.
  await page.reload();
  await expect(page.getByRole("listitem").filter({ hasText: "Session server" }).getByLabel("Sessions")).toHaveText(
    "Stateful: can ask the client to confirm",
  );
  const stored = await (await page.request.get(`/api/v1/servers/${serverId}`)).json();
  expect(stored.sessions).toBe("stateful");

  await pickOption(page, row.getByLabel("Sessions"), "Stateless: any replica answers");
  await expect(page.getByRole("heading", { name: "Session server now uses stateless sessions", exact: true })).toBeVisible();
  await expect(row.getByText(/sticky routing/)).toHaveCount(0);
  await expect(row.getByLabel("Sessions")).toHaveText("Stateless: any replica answers");
});
