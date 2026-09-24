import { test, expect } from "./fixtures";

// The content security policy is enforced, not reported, so a page that
// would violate it breaks. That is only safe to ship if something checks
// every screen actually loads under it.

const screens = [
  "/",
  "/catalog",
  "/connectors",
  "/connectors/import",
  "/servers",
  "/api-keys",
  "/tool-calls",
  "/status",
  "/settings/security",
  "/settings/audit",
  "/settings/roles",
  "/settings/sso",
  "/settings/service-accounts",
];

test("every screen loads with no policy violation and no console error", async ({ page, workspace }) => {
  expect(workspace.email).toBeTruthy();
  const problems: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") problems.push(`${page.url()}: ${msg.text()}`);
  });
  page.on("pageerror", (err) => problems.push(`${page.url()}: ${err.message}`));

  for (const screen of screens) {
    const response = await page.goto(screen);
    expect(response?.status(), `${screen} did not load`).toBeLessThan(400);
    const policy = response?.headers()["content-security-policy"] ?? "";
    expect(policy, `${screen} was served without a content security policy`).toContain("default-src 'self'");
    expect(policy).toContain("frame-ancestors 'none'");
    await page.waitForLoadState("networkidle");
  }

  expect(problems, "a screen logged an error, which under an enforced policy usually means it was blocked").toEqual([]);
});

test("the security headers a browser relies on are present", async ({ request }) => {
  const res = await request.get("/");
  const h = res.headers();
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["referrer-policy"]).toBe("strict-origin-when-cross-origin");
});
