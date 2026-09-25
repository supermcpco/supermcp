// What keeps two checkouts' browser suites apart on one machine: the
// database each one drops and recreates, and the port its server listens
// on. With fixed values a second worktree's run dropped the first one's
// database from under it, or found 8099 taken.
//
// The database suffix is the one the Go tests use (internal/testdb):
// SUPERMCP_TEST_DB_SUFFIX when set, otherwise the first eight hex digits
// of the SHA-256 of the checkout's path, so one checkout always gets the
// same name and a leftover database says whose it is.
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { createServer } from "node:net";
import { resolve } from "node:path";

export const repo = realpathSync(resolve(import.meta.dirname, "..", ".."));

export function suffix() {
  const override = (process.env.SUPERMCP_TEST_DB_SUFFIX ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "")
    .slice(0, 20);
  if (override) return override;
  return createHash("sha256").update(repo).digest("hex").slice(0, 8);
}

// PLAYWRIGHT_DB, or supermcp_browser_<suffix>.
export const dbName = process.env.PLAYWRIGHT_DB ?? `supermcp_browser_${suffix()}`;

// Asks the kernel for a port nobody holds. There is a moment between
// closing this listener and the server binding it, which is why the
// server's own bind failing is still a failed run rather than a retry.
export function freePort() {
  return new Promise((ok, fail) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", fail);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => ok(port));
    });
  });
}
