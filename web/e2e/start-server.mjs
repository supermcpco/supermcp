// Starts supermcp on a private database for the browser suite, so a run
// never touches a developer's own instance and always begins from an
// empty workspace.
import { execFileSync, spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "..", "..");
const admin = process.env.PLAYWRIGHT_ADMIN_DATABASE_URL ?? "postgres://supermcp:supermcp@127.0.0.1:55432/postgres?sslmode=disable";
const dbName = process.env.PLAYWRIGHT_DB ?? "supermcp_browser";
const url = admin.replace("/postgres?", `/${dbName}?`);

// psql is not always on the path — a developer running Postgres in a
// container usually has no client installed — so fall back to running it
// inside the container. PLAYWRIGHT_PG_CONTAINER names it.
const container = process.env.PLAYWRIGHT_PG_CONTAINER ?? "supermcp-pg";
const psql = (target, sql) => {
  const args = [target, "-v", "ON_ERROR_STOP=1", "-tAc", sql];
  try {
    return execFileSync("psql", args, { stdio: ["ignore", "pipe", "inherit"] });
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
    const inside = target.replace("127.0.0.1:55432", "127.0.0.1:5432");
    return execFileSync(
      "docker",
      ["exec", "-e", "PGPASSWORD=supermcp", container, "psql", inside, "-v", "ON_ERROR_STOP=1", "-tAc", sql],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
  }
};

// A suite that inherits yesterday's rows is a suite that passes for the
// wrong reason.
psql(admin, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
psql(admin, `CREATE DATABASE ${dbName}`);

const env = {
  ...process.env,
  DATABASE_URL: url,
  ENCRYPTION_KEK: randomBytes(32).toString("base64"),
  SUPERMCP_LISTEN: ":8099",
  SUPERMCP_PUBLIC_URL: "http://localhost:8099",
  SUPERMCP_DEV: "true",
  SUPERMCP_OPEN_REGISTRATION: "true",
  SUPERMCP_LOG_FORMAT: "text",
  // The suite creates a workspace per test, which is exactly the shape of
  // traffic the register budget exists to stop. The limiter itself is
  // covered by its own tests and by a curl against a real instance; here
  // it would only be testing that a fixture can be rate limited.
  SUPERMCP_RATELIMIT_REGISTER: "1000/1m",
  SUPERMCP_RATELIMIT_SIGNIN: "1000/1m",
  SUPERMCP_RATELIMIT_API: "5000/1m",
};

// The binary embeds the built SPA, so building it alone would test
// whatever was last put in internal/web/dist — which is how a suite comes
// to pass against a screen nobody has any more.
execFileSync("pnpm", ["build"], { cwd: resolve(repo, "web"), stdio: "inherit" });
// The build empties that directory, and the binary embeds it: without the
// placeholder a fresh checkout does not compile, and a run here would
// otherwise delete it from the working tree.
writeFileSync(resolve(repo, "internal/web/dist/.gitkeep"), "");
execFileSync("go", ["build", "-o", "bin/supermcp", "./cmd/supermcp"], { cwd: repo, stdio: "inherit" });
execFileSync("bin/supermcp", ["migrate"], { cwd: repo, env, stdio: "inherit" });

const child = spawn("bin/supermcp", ["serve"], { cwd: repo, env, stdio: "inherit" });
const stop = () => child.kill("SIGTERM");
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
child.on("exit", (code) => process.exit(code ?? 0));
