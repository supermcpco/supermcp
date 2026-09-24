import { test, expect, expectAccessible } from "./fixtures";
import type { Page } from "@playwright/test";

// Controls are found by role rather than by label text: a label that wraps
// a textarea also contains the textarea's initial text, so an exact label
// match fails on any field that already holds something.
//
// Tools are created, changed and deleted through the screens a person uses,
// and the API is only asked afterwards whether the change really landed.

async function installBundesbank(page: Page): Promise<string> {
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);
  const connectors = await (await page.request.get("/api/v1/connectors")).json();
  return connectors[0].id as string;
}

const catalogTool = "bundesbank_get_exchange_rates";
const customTool = "bundesbank_usd_rates_custom";

test("a catalog tool can be edited, shows it was, and its history restores it", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const connectorId = await installBundesbank(page);

  await page.goto("/connectors");
  await page.getByRole("link", { name: "Tools" }).first().click();
  await expect(page).toHaveURL(new RegExp(`/connectors/${connectorId}/tools`));
  await expect(page.getByRole("heading", { name: /^Tools/ })).toBeVisible();
  await expect(page.getByText(catalogTool, { exact: true }).first()).toBeVisible();
  // A catalog tool is switched off, never deleted.
  await expect(page.getByRole("button", { name: /^Delete/ })).toHaveCount(0);
  await expectAccessible(page);

  const tools = await (await page.request.get(`/api/v1/connectors/${connectorId}/tools`)).json();
  const tool = tools.find((t: { name: string }) => t.name === catalogTool);
  const original: string = tool.description;

  await page.getByRole("link", { name: `Edit ${catalogTool}` }).click();
  await expect(page.getByRole("heading", { name: catalogTool })).toBeVisible();
  await expect(page.getByText(/leaves your version alone/)).toBeVisible();

  const description = page.getByRole("textbox", { name: "Description", exact: true });
  await description.fill("Euro reference rates, edited in the browser test.");
  const preview = page.getByRole("region", { name: "What it would send" });
  await expect(preview.getByText(/redacted/)).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("status").getByText(/^Saved/)).toBeVisible();
  await expect(page.getByText("edited", { exact: true }).first()).toBeVisible();

  await page.getByRole("link", { name: "Tools", exact: true }).click();
  const row = page.getByRole("listitem").filter({ hasText: catalogTool });
  await expect(row.getByText("edited", { exact: true })).toBeVisible();

  await row.getByRole("link", { name: `History of ${catalogTool}` }).click();
  await expect(page.getByRole("heading", { name: "History" })).toBeVisible();
  const versions = page.getByText(/^Version \d+$/);
  await expect(versions).toHaveCount(2);
  await expectAccessible(page);

  // The first change also records the tool as it was installed, so the
  // oldest version is the catalog's own. A restore is a further change,
  // so one more version says it landed.
  await page.getByRole("button", { name: "Restore this version" }).last().click();
  await expect(versions).toHaveCount(3);
  const restored = await (await page.request.get(`/api/v1/tools/${tool.id}`)).json();
  expect(restored.description).toBe(original);
});

test("a custom tool is built with a live preview, edited as JSON and deleted", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const connectorId = await installBundesbank(page);

  await page.goto(`/connectors/${connectorId}/tools`);
  await page.getByRole("link", { name: "New tool" }).click();
  await expect(page.getByRole("heading", { name: "New tool" })).toBeVisible();

  await page.getByRole("textbox", { name: "Name", exact: true }).fill(customTool);
  await page.getByRole("textbox", { name: "Description", exact: true }).fill("Daily USD reference rate, made in the browser test.");
  await page.getByRole("textbox", { name: "Path", exact: true }).fill("/data/BBEX3/D.USD.EUR.BB.AC.000");

  // The preview is worked out from the unsaved draft, by the server.
  const preview = page.getByRole("region", { name: "What it would send" });
  await expect(preview.getByText(/GET https:\/\/[^ ]*bundesbank\.de/)).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Create tool" }).click();
  await expect(page.getByRole("heading", { name: customTool })).toBeVisible();
  const toolId = /\/tools\/([^/]+)$/.exec(new URL(page.url()).pathname)?.[1];
  expect(toolId).toBeTruthy();

  // The JSON view holds everything the form does, and more.
  await page.getByRole("button", { name: "JSON" }).click();
  const json = page.getByRole("textbox", { name: "Definition (JSON)", exact: true });
  const definition = JSON.parse(await json.inputValue());
  expect(definition.name).toBe(customTool);
  definition.description = "Changed in the JSON view.";
  await json.fill(JSON.stringify(definition, null, 2));
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("status").getByText(/^Saved/)).toBeVisible();
  const saved = await (await page.request.get(`/api/v1/tools/${toolId}`)).json();
  expect(saved.description).toBe("Changed in the JSON view.");
  expect(saved.source).toBe("custom");

  // Only a tool made here can be deleted, and it is asked about first.
  await page.getByRole("link", { name: "Tools", exact: true }).click();
  await page.getByRole("button", { name: `Delete ${customTool}` }).click();
  await expect(page.getByRole("heading", { name: `Delete ${customTool}?` })).toBeVisible();
  await page.getByRole("button", { name: `Delete ${customTool} for good` }).click();
  await expect(page.getByText(customTool)).toHaveCount(0);
  expect((await page.request.get(`/api/v1/tools/${toolId}`)).status()).toBe(404);
});

test("a definition that does not parse cannot be saved or switched away from", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const connectorId = await installBundesbank(page);

  await page.goto(`/connectors/${connectorId}/tools/new`);
  await page.getByRole("button", { name: "JSON" }).click();
  await page.getByRole("textbox", { name: "Definition (JSON)", exact: true }).fill('{ "name": ');
  await expect(page.getByRole("button", { name: "Create tool" })).toBeDisabled();
  await page.getByRole("button", { name: "Form" }).click();
  await expect(page.getByRole("alert").getByText(/does not parse/)).toBeVisible();
});
