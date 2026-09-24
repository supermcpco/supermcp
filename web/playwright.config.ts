import { defineConfig, devices } from "@playwright/test";

// These tests drive the real binary against a real Postgres. There is no
// mocking layer: the point is to catch what the Go tests cannot see,
// which is everything between the API and what a person can actually
// click. Two bugs found by hand on 2026-09-22 — an unreachable catalog
// page and an Install button wired to nothing — were both of that kind.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["list"]] : [["list"]],
  timeout: 30_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: process.env.SUPERMCP_URL ?? "http://localhost:8099",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // The suite starts the binary itself so a developer runs one command and
  // CI runs the same one. SUPERMCP_URL skips this and uses an instance
  // that is already up.
  webServer: process.env.SUPERMCP_URL
    ? undefined
    : {
        command: "node e2e/start-server.mjs",
        url: "http://localhost:8099/readyz",
        reuseExistingServer: false,
        // It builds the interface and then the binary that embeds it, so
        // the first start on a cold runner is minutes, not seconds.
        timeout: 300_000,
        stdout: "pipe",
        stderr: "pipe",
      },
});
