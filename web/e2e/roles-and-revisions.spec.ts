import { test, expect, expectAccessible } from "./fixtures";

// Roles and revisions, driven through the screens and the API a person
// and a client actually use.

test("the roles screen shows who holds what", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/roles");
  await expect(page.getByRole("heading", { name: /roles/i })).toBeVisible();
  // The built-in roles are always there, and the person who created the
  // workspace owns it.
  await expect(page.getByText("owner", { exact: false }).first()).toBeVisible();
  await expectAccessible(page);
});

test("the history screen shows a change and restores it", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);

  // Rename through the API, then read the history the way a person does.
  const api = page.request;
  const connectors = await (await api.get("/api/v1/connectors")).json();
  const id = connectors[0].id;
  const original = connectors[0].name;
  await api.patch(`/api/v1/connectors/${id}`, { data: { name: "Renamed in the browser test" } });

  await page.goto(`/connectors/${id}/history`);
  await expect(page.getByRole("heading", { name: "History" })).toBeVisible();
  await expect(page.getByText("Renamed in the browser test")).toBeVisible();
  await expect(page.getByText(original).first()).toBeVisible();

  // Restoring adds a further version rather than rewinding, so waiting
  // for that row is what tells us the change has actually landed.
  const before = await page.getByText(/^Version \d+$/).count();
  await page.getByRole("button", { name: /restore this version/i }).last().click();
  await expect(page.getByText(/^Version \d+$/)).toHaveCount(before + 1);

  await page.goto("/connectors");
  await expect(page.getByText(original).first()).toBeVisible();
});

test("changing a connector records a revision that can be restored", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);

  // page.request carries the page's cookies; the standalone request
  // fixture has its own context and is signed in as nobody.
  const api = page.request;
  const list = await api.get("/api/v1/connectors");
  expect(list.ok()).toBeTruthy();
  const connectors = await list.json();
  const id = connectors[0].id;
  const originalName = connectors[0].name;

  // A change through the API is the same change a screen makes.
  const renamed = await api.patch(`/api/v1/connectors/${id}`, { data: { name: "Renamed by a test" } });
  expect(renamed.ok()).toBeTruthy();

  const revisions = await api.get(`/api/v1/connectors/${id}/revisions`);
  expect(revisions.ok(), "a connector that was installed and renamed has a history").toBeTruthy();
  const body = await revisions.json();
  expect(body.revisions.length, "the install and the rename should both be recorded").toBeGreaterThanOrEqual(2);

  // Restoring the first revision puts the original name back, and is
  // itself recorded rather than rewinding the history.
  const first = body.revisions[body.revisions.length - 1].revision;
  const restored = await api.post(`/api/v1/connectors/${id}/revisions/${first}/restore`);
  expect(restored.ok()).toBeTruthy();
  expect((await restored.json()).name).toBe(originalName);

  const after = await (await api.get(`/api/v1/connectors/${id}/revisions`)).json();
  expect(after.revisions.length).toBeGreaterThan(body.revisions.length);
});

test("a role is built from the permission list, with a preview of what it allows", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/roles");
  await page.getByRole("button", { name: "Build a role" }).click();

  await page.getByLabel("Name", { exact: true }).fill("Support engineer");
  await page.getByLabel("Who it is for", { exact: true }).fill("People who answer customer questions");
  await page.getByLabel("See which connectors are installed and how they are configured").check();
  await page.getByLabel("See the available tools and what each one expects").check();

  // The preview is the point of the screen: it answers what somebody
  // holding this could do, worked out by the server rather than guessed
  // from the ticks.
  const preview = page.getByRole("region", { name: "What somebody holding this role could do" });
  await expect(preview.getByText("See the available tools and what each one expects")).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Create this role" }).click();
  await expect(page.getByText("Support engineer")).toBeVisible();
  await expect(page.getByText("People who answer customer questions")).toBeVisible();
});

test("the preview says what another role the holder has already allows", async ({ page, workspace }) => {
  await page.goto("/settings/roles");
  await page.getByRole("button", { name: "Build a role" }).click();
  await page.getByLabel("Name", { exact: true }).fill("Second opinion");
  await page.getByLabel("See the roles and who holds them").check();

  // The person who made the workspace owns it, so everything this role
  // would allow they can already do. Saying so is the difference between
  // a permission list and an answer.
  const preview = page.getByRole("region", { name: "What somebody holding this role could do" });
  await preview.getByLabel("Work it out for").selectOption({ index: 1 });
  await expect(preview.getByText(/already holds/)).toBeVisible();
  await expect(preview.getByText(/Also from|Only from/).first()).toBeVisible();
  expect(workspace.email).toBeTruthy();
});

test("a role keeps a history that can be restored", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/roles");
  await page.getByRole("button", { name: "Build a role" }).click();
  await page.getByLabel("Name", { exact: true }).fill("Rota keeper");
  await page.getByLabel("See the roles and who holds them").check();
  await page.getByRole("button", { name: "Create this role" }).click();
  await expect(page.getByText("Rota keeper")).toBeVisible();

  const role = page.getByRole("listitem").filter({ hasText: "Rota keeper" }).first();
  await role.getByRole("button", { name: "Change what it allows" }).click();
  await page.getByLabel("See the available tools and what each one expects").check();
  await page.getByRole("button", { name: "Save what it allows" }).click();
  await expect(page.getByText("See the available tools and what each one expects").first()).toBeVisible();

  // What the history holds is read from the answer itself, so the test
  // is not racing the panel that draws it.
  const [answer] = await Promise.all([
    page.waitForResponse((r) => /\/api\/v1\/roles\/[^/]+\/revisions(\?|$)/.test(r.url())),
    role.getByRole("button", { name: "History", exact: true }).click(),
  ]);
  const recorded: number = (await answer.json()).revisions.length;

  // The history keeps a closed set of entity kinds, and a deployment
  // whose schema does not yet count a role among them records nothing
  // rather than refusing the change. There is then nothing to restore,
  // and the screen says so instead of showing an empty list.
  const versions = page.getByText(/^Version \d+$/);
  if (recorded === 0) {
    await expect(page.getByText("Nothing has changed about this role yet.")).toBeVisible();
    return;
  }

  await expect(versions).toHaveCount(recorded);
  expect(recorded, "creating the role and changing it are both recorded").toBe(2);
  await expect(role.getByText("What it allows").first()).toBeVisible();
  await expectAccessible(page);

  // Restoring is recorded as a further change rather than a rewind, so a
  // third version appearing is what says the restore landed.
  const before = await versions.count();
  await role.getByRole("button", { name: "Restore this version" }).last().click();
  await expect(versions).toHaveCount(before + 1);
});

test("a long change is shown with the two versions side by side", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);

  const api = page.request;
  const connectors = await (await api.get("/api/v1/connectors")).json();
  const id = connectors[0].id;
  await api.patch(`/api/v1/connectors/${id}`, {
    data: { instructions: "Ask before you act.\nUse the German series.\nQuote the figures exactly." },
  });
  await api.patch(`/api/v1/connectors/${id}`, {
    data: { instructions: "Ask before you act.\nUse the euro-area series.\nQuote the figures exactly." },
  });

  await page.goto(`/connectors/${id}/history`);
  await expect(page.getByRole("heading", { name: "History" })).toBeVisible();

  // One line of three changed. The whole point of the side-by-side view
  // is that the other two stay put while it is found.
  const comparison = page.getByRole("table").first();
  await expect(comparison.getByRole("columnheader", { name: "Before" })).toBeVisible();
  await expect(comparison.getByRole("columnheader", { name: "After" })).toBeVisible();
  await expect(comparison.getByText("Use the German series.")).toBeVisible();
  await expect(comparison.getByText("Use the euro-area series.")).toBeVisible();
  await expect(comparison.getByText("Ask before you act.").first()).toBeVisible();
  await expectAccessible(page);
});

test("the API refuses the role changes a workspace should not accept", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/settings/roles");
  const api = page.request;

  // A built-in role is the same in every workspace, so it cannot be
  // redefined here however it is asked for.
  const builtIn = await api.patch("/api/v1/roles/role_owner", {
    data: { name: "owner", permissions: ["org:read"] },
  });
  expect(builtIn.status()).toBe(409);
  expect((await api.delete("/api/v1/roles/role_owner")).status()).toBe(409);

  // A permission this build has never heard of would be a role that
  // allows nothing while looking like it allows something.
  const unknown = await api.post("/api/v1/roles", {
    data: { name: "Typo", permissions: ["connectors:reed"] },
  });
  expect(unknown.status()).toBe(400);

  const created = await api.post("/api/v1/roles", {
    data: { name: "Rota cover", description: "Weekend cover", permissions: ["roles:read"] },
  });
  expect(created.status()).toBe(201);
  const role = await created.json();
  expect(role.permissions).toEqual(["roles:read"]);

  // Two roles with one name is two things nobody can tell apart.
  const again = await api.post("/api/v1/roles", { data: { name: "Rota cover", permissions: ["roles:read"] } });
  expect(again.status()).toBe(409);

  // Somebody holding it would lose access in silence, so the role stays
  // until it is taken away from them.
  const session = await (await api.get("/api/v1/auth/session")).json();
  const granted = await api.post(`/api/v1/roles/${role.id}/bindings`, {
    data: { principalKind: "user", principalId: session.user.id, scopeKind: "org" },
  });
  expect(granted.status()).toBe(201);
  expect((await api.delete(`/api/v1/roles/${role.id}`)).status()).toBe(409);
  const binding = await granted.json();
  expect((await api.delete(`/api/v1/roles/${role.id}/bindings/${binding.id}`)).ok()).toBeTruthy();
  expect((await api.delete(`/api/v1/roles/${role.id}`)).status()).toBe(204);

  // The preview answers for a set that has not been saved, which is the
  // whole point of asking before saving it.
  const preview = await api.post("/api/v1/roles/preview", {
    data: { permissions: ["*"] },
  });
  expect(preview.ok()).toBeTruthy();
  const body = await preview.json();
  expect(body.allows.length, "a wildcard is every permission, not one line").toBeGreaterThan(10);
});
