import { test, expect, expectAccessible } from "./fixtures";

// Two screens an operator meets on their first bad day: the one that adds
// a connector from a document somebody sent them, and the one they open
// when they want to know whether this instance is healthy. Both are driven
// here the way a person drives them, because in both cases the API was
// already right while the screen was still wrong.

// A deliberately small document: two operations, one server, one API key.
// Written inline so a reader of this test can see exactly what the preview
// below is a preview of.
const openapiDoc = JSON.stringify({
  openapi: "3.1.0",
  info: {
    title: "Allotment Register",
    description: "Plots, tenants and the waiting list for a council allotment site.",
    version: "1.0.0",
  },
  servers: [{ url: "https://allotments.example.test/api" }],
  security: [{ apiKey: [] }],
  components: {
    securitySchemes: {
      apiKey: { type: "apiKey", in: "header", name: "X-Allotment-Key" },
    },
  },
  paths: {
    "/plots": {
      get: {
        operationId: "listPlots",
        summary: "List the plots on the site",
        description: "Every plot, with its size and whoever currently holds the tenancy.",
        parameters: [{ name: "vacant", in: "query", schema: { type: "boolean" } }],
        responses: { "200": { description: "The plots" } },
      },
    },
    "/plots/{plotId}/tenant": {
      put: {
        operationId: "assignTenant",
        summary: "Assign a plot to somebody on the waiting list",
        description: "Moves the named person off the waiting list and onto the plot.",
        parameters: [{ name: "plotId", in: "path", required: true, schema: { type: "string" } }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["personId"],
                properties: { personId: { type: "string" } },
              },
            },
          },
        },
        responses: { "200": { description: "The new tenancy" } },
      },
    },
  },
});

test("a document is previewed in full before anything is created", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  await page.goto("/connectors/import");
  await expect(page.getByRole("heading", { name: "Import an API description" })).toBeVisible();

  // Saying which format this is, rather than leaving it to be worked out.
  await page.getByRole("radio", { name: "OpenAPI", exact: true }).check();
  await page.getByLabel("OpenAPI document").fill(openapiDoc);
  await page.getByLabel("Connector name").fill("Allotments");
  await page.getByLabel("Tool name prefix").fill("allotments");
  await page.getByRole("button", { name: "Preview import" }).click();

  // The preview names what would be created, down to the individual tools.
  // Scoped to the preview, because the document in the textarea says some
  // of the same words and proves nothing about what was read out of it.
  const preview = page.getByRole("region", { name: "What this would create" });
  await expect(preview).toBeVisible();
  await expect(preview.getByText("https://allotments.example.test/api")).toBeVisible();
  await expect(preview.getByText("An API key, sent with every call.")).toBeVisible();
  await expect(preview.getByText("allotments_list_plots")).toBeVisible();
  await expect(preview.getByText("allotments_assign_tenant")).toBeVisible();
  await expect(preview.getByText("GET /plots", { exact: true })).toBeVisible();
  // The path is shown as the connector will store it, placeholders and all.
  // The preview shows the path as the document wrote it, not the template
  // it is stored as.
  await expect(preview.getByText("PUT /plots/{plotId}/tenant")).toBeVisible();
  await expectAccessible(page);

  // A preview is a dry run, so the workspace must still be empty.
  const before = await page.request.get("/api/v1/connectors");
  expect(before.ok()).toBeTruthy();
  expect((await before.json()) ?? [], "the dry run created a connector").toEqual([]);

  // The credential the document implies is collected on this same screen.
  await page.getByLabel("API_KEY").fill("not-a-real-key");
  await page.getByRole("button", { name: "Import connector" }).click();

  // An import lands on the connectors list, where someone looks for the
  // thing they just made.
  await expect(page).toHaveURL(/\/connectors$/);
  await expect(page.getByText("Allotments")).toBeVisible();
  await expect(page.getByText("2 tools", { exact: false })).toBeVisible();
  await expect(page.getByText("credentials missing")).toHaveCount(0);
});

test("a document with nowhere to call is stopped at the preview", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  // The same document with its servers removed: the importer cannot know
  // what to call, and that is a decision only a person can make.
  const homeless = JSON.parse(openapiDoc) as { servers?: unknown };
  delete homeless.servers;

  await page.goto("/connectors/import");
  // Left to work the format out for itself, which it can: the document
  // still says openapi even with its servers gone.
  await page.getByLabel("Document").fill(JSON.stringify(homeless));
  await page.getByRole("button", { name: "Preview import" }).click();

  await expect(page.getByRole("heading", { name: "You have to decide these first" })).toBeVisible();
  await expect(page.getByText(/document declares no servers/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "Import connector" })).toBeDisabled();

  // Answering it on the same screen is enough to get past it.
  await page.getByLabel("Base URL").fill("https://allotments.example.test/api");
  await page.getByRole("button", { name: "Preview import" }).click();
  await expect(page.getByRole("heading", { name: "You have to decide these first" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Import connector" })).toBeEnabled();
});

test("the status screen answers what an operator asks first", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();

  await page.goto("/status");
  await expect(page.getByRole("heading", { name: "Status" })).toBeVisible();

  await expect(page.getByText(/This instance is running version/)).toBeVisible();
  await expect(page.getByText(/The database is reachable/)).toBeVisible();
  await expect(page.getByText(/The audit trail verifies across \d+ events?/)).toBeVisible();
  await expect(page.getByText(/The catalog holds \d+ adapters ready to install/)).toBeVisible();
  await expect(page.getByText(/Last checked at/)).toBeVisible();
  await expectAccessible(page);
});
