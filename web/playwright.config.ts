import { defineConfig, devices } from "@playwright/test";
import { dbName, freePort } from "./e2e/isolation.mjs";

// Each checkout runs on a port and a database of its own, so two
// worktrees can run the suite at once. PLAYWRIGHT_PORT pins the port;
// otherwise one nobody holds is chosen here. Both are put in the
// environment because the web server and every worker inherit it, and a
// worker that loaded this file again would otherwise pick another port.
process.env.PLAYWRIGHT_PORT ??= String(await freePort());
process.env.PLAYWRIGHT_DB ??= dbName;
const local = `http://localhost:${process.env.PLAYWRIGHT_PORT}`;

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
    baseURL: process.env.SUPERMCP_URL ?? local,
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
        url: `${local}/readyz`,
        reuseExistingServer: false,
        // It builds the interface and then the binary that embeds it, so
        // the first start on a cold runner is minutes, not seconds.
        timeout: 300_000,
        stdout: "pipe",
        stderr: "pipe",
      },
});
