import { test, expect, expectAccessible } from "./fixtures";

// A workspace's own detector, from the screen to a real call: the pattern
// is tried on its samples as it is typed, saved, picked by a rule beside
// the built-ins, and a tool call whose argument matches it is refused
// with the detector named and the value nowhere in sight.

// An invented contract id of the shape the detector is written for.
const contractId = "CN-482913";

test("a custom detector is tried, saved, added to a rule, and refuses a call that carries a match", async ({
  page,
  request,
  workspace,
}) => {
  expect(workspace.email).toBeTruthy();

  // A keyless adapter on a server, with a key: the shortest path to a call.
  await page.goto("/catalog/bundesbank");
  await page.getByRole("button", { name: "Install" }).click();
  await expect(page).toHaveURL(/\/connectors/);
  await page.goto("/servers");
  await page.getByLabel("Name").fill("Detector server");
  await page.getByRole("checkbox", { name: /Deutsche Bundesbank Statistics/ }).check();
  await page.getByRole("button", { name: "Create server" }).click();
  const endpoint = await page.locator("code", { hasText: "/mcp/" }).first().innerText();
  const serverId = endpoint.trim().split("/mcp/")[1];
  await page.goto("/api-keys");
  await page.getByLabel("Name").fill("Detector key");
  await page.getByRole("button", { name: "Create key" }).click();
  const secret = (await page.locator("code").first().innerText()).trim();

  // The detector, on its own tab.
  await page.goto("/settings/dlp");
  await page.getByRole("tab", { name: "Detectors" }).click();
  await expect(page).toHaveURL(/tab=detectors/);
  await expect(page.getByText(/No detectors of this workspace's own yet/)).toBeVisible();

  await page.getByLabel("Detector name").fill("contract_id");
  await page.getByLabel("Description").fill("Contract ids");
  await page.getByLabel("Pattern", { exact: true }).fill("\\bCN-\\d{6}\\b");
  await page.getByLabel("Samples it must match, one per line").fill(`${contractId}\nsee ${contractId}.`);
  await page.getByLabel("Samples it must not match, one per line").fill("CN-12345\nXCN-1234567");

  // Tried as it is typed: every sample comes back as its list expects.
  const tried = page.getByRole("region", { name: "What the pattern of the new detector matches" });
  await expect(tried.getByText(/^As expected/)).toHaveCount(4);
  await expect(tried.getByText("matches at bytes 4–13")).toBeVisible();
  await expect(tried.getByText(/Not as expected/)).toHaveCount(0);

  // A sample that disagrees is shown before anything is saved.
  await page.getByLabel("Samples it must not match, one per line").fill(`CN-12345\n${contractId}`);
  await expect(tried.getByText(/^Not as expected/)).toHaveCount(1);
  // And the server refuses to save it, naming the sample by position.
  const [refused] = await Promise.all([
    page.waitForResponse((r) => r.url().endsWith("/api/v1/dlp/detectors") && r.request().method() === "POST"),
    page.getByRole("button", { name: "Add the detector" }).click(),
  ]);
  expect(refused.status()).toBe(422);
  await expect(page.getByRole("alert").getByText("sample 2 of mustNotMatch matches the pattern")).toBeVisible();

  await page.getByLabel("Samples it must not match, one per line").fill("CN-12345\nXCN-1234567");
  await Promise.all([
    page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/dlp/detectors") && r.request().method() === "POST" && r.status() === 201,
    ),
    page.getByRole("button", { name: "Add the detector" }).click(),
  ]);
  const detector = page.getByRole("listitem").filter({ hasText: "Contract ids" }).first();
  await expect(detector.getByText("custom:contract_id", { exact: true })).toBeVisible();
  await expectAccessible(page);

  // The list does not carry the samples; the editor reads them on its own.
  await expect(detector.getByText("2 samples it must match, 2 it must not")).toBeVisible();
  await detector.getByRole("button", { name: "Change contract_id" }).click();
  const editor = page.getByRole("form", { name: "Change contract_id" });
  await expect(editor.getByLabel("Samples it must match, one per line")).toHaveValue(`${contractId}\nsee ${contractId}.`);
  await editor.getByRole("button", { name: "Cancel" }).click();

  // Its history already holds the version just saved.
  await detector.getByRole("button", { name: "History of contract_id" }).click();
  await expect(page.getByRole("region", { name: "History of contract_id" }).getByText("Version 1")).toBeVisible();

  // A rule picks it beside the built-ins.
  await page.getByRole("tab", { name: "Rules" }).click();
  await page.getByLabel("What it is for").fill("Contract ids stay inside");
  await page.getByLabel("What it does").selectOption("refuse");
  await page.getByRole("checkbox", { name: /custom:contract_id/ }).check();
  await Promise.all([
    page.waitForResponse((r) => r.url().endsWith("/api/v1/dlp/policies") && r.request().method() === "POST" && r.ok()),
    page.getByRole("button", { name: "Add the rule" }).click(),
  ]);
  const rule = page.getByRole("listitem").filter({ hasText: "Contract ids stay inside" }).first();
  await expect(rule.getByText(/custom:contract_id/)).toBeVisible();
  await expectAccessible(page);

  // A call whose argument carries a contract id is refused before it goes
  // anywhere, and the refusal names the detector, not the value.
  const connectors = await (await page.request.get("/api/v1/connectors")).json();
  const tools = await (await page.request.get(`/api/v1/connectors/${connectors[0].id}/tools`)).json();
  const toolName = tools.find((t: { name: string }) => t.name.endsWith("exchange_rates")).name;
  const call = await request.post(`/mcp/${serverId}`, {
    headers: { "X-API-Key": secret, Accept: "application/json, text/event-stream" },
    data: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: toolName, arguments: { currency: `renew ${contractId}` } },
    },
  });
  const answer = await call.text();
  expect(answer).toContain("custom:contract_id");
  expect(answer).toMatch(/data-loss policy refused/);
  expect(answer, "the refusal quotes the value it refused").not.toContain(contractId);

  // And the finding is on the audit trail, found by the detector's name.
  await page.goto("/settings/audit");
  await page.getByRole("searchbox", { name: "Search" }).fill('"custom:contract_id"');
  await expect(page.getByRole("row").filter({ hasText: toolName }).first()).toBeVisible();
  await expect(page.getByText(contractId)).toHaveCount(0);
});
