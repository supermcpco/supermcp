import { test, expect, expectAccessible } from "./fixtures";
import { sql } from "./db";

// A connector installed from the catalog is re-synced when the server
// carries a newer version of its adapter. A newer adapter only arrives
// with an upgrade of the binary, which a browser test cannot perform, so
// the older install is made by hand below: its catalog hash and one tool's
// text are put back to what an older binary would have written. That is
// the one step here the product cannot do to itself; everything else is
// done through the screens.

const staleTool = "bundesbank_get_exchange_rates";
const editedTool = "bundesbank_get_bund_yields";

test("an outdated catalog connector is badged, previewed and re-synced", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);
  const connectors = await (await page.request.get("/api/v1/connectors")).json();
  const connectorId = connectors[0].id as string;
  await expect(page.getByText("Deutsche Bundesbank Statistics")).toBeVisible();
  await expect(page.getByText("catalog update available")).toHaveCount(0);

  // Someone edits one catalog tool by hand; re-sync must leave it alone.
  await page.goto(`/connectors/${connectorId}/tools`);
  await page.getByRole("link", { name: `Edit ${editedTool}` }).click();
  await expect(page.getByRole("heading", { name: editedTool })).toBeVisible();
  await page.getByRole("textbox", { name: "Description", exact: true }).fill("Bund yields, as this workspace describes them.");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("status").getByText(/^Saved/)).toBeVisible();

  // What an older binary would have left behind.
  sql(`UPDATE connectors SET catalog_hash = 'older' WHERE id = $1`, connectorId);
  sql(
    `UPDATE tools SET definition = jsonb_set(definition, '{description}', '"The older description."')
     WHERE connector_id = $1 AND name = $2`,
    connectorId,
    staleTool,
  );

  await page.goto("/connectors");
  const row = page.getByRole("listitem").filter({ hasText: "Deutsche Bundesbank Statistics" });
  await expect(row.getByText("catalog update available")).toBeVisible();
  await row.getByRole("link", { name: "Tools" }).click();

  await expect(page.getByText(/carries a newer version of the catalog adapter/)).toBeVisible();
  await page.getByRole("button", { name: "Review re-sync" }).click();
  const review = page.getByRole("region", { name: "Re-sync with the catalog" });
  await expect(review.getByRole("heading", { name: "Tools to update (1)" })).toBeVisible();
  await expect(review.getByRole("listitem").filter({ hasText: staleTool })).toContainText("changes description");
  await expect(review.getByRole("heading", { name: "Left alone (1)" })).toBeVisible();
  await expect(review.getByRole("listitem").filter({ hasText: editedTool })).toContainText("edited by hand");
  await expect(review.getByRole("heading", { name: /Tools to (add|remove)/ })).toHaveCount(0);
  await expectAccessible(page);

  const applied = page.waitForResponse(
    (r) => r.url().endsWith(`/api/v1/connectors/${connectorId}/resync`) && r.request().method() === "POST",
  );
  await review.getByRole("button", { name: "Apply re-sync" }).click();
  expect((await applied).status()).toBe(200);
  await expect(page.getByRole("status").getByText("Re-synced with the catalog: 1 tool updated, 1 tool left alone.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Review re-sync" })).toHaveCount(0);

  // The stale tool has the catalog's text again; the edited one kept its own.
  const tools = await (await page.request.get(`/api/v1/connectors/${connectorId}/tools`)).json();
  const byName = new Map<string, { description: string }>(tools.map((t: { name: string; description: string }) => [t.name, t]));
  expect(byName.get(staleTool)?.description).not.toBe("The older description.");
  expect(byName.get(editedTool)?.description).toBe("Bund yields, as this workspace describes them.");

  await page.goto("/connectors");
  await expect(page.getByRole("heading", { name: "Connectors" })).toBeVisible();
  await expect(page.getByText("Deutsche Bundesbank Statistics")).toBeVisible();
  await expect(page.getByText("catalog update available")).toHaveCount(0);
});
