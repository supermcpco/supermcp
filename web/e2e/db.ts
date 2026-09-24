import { execFileSync } from "node:child_process";

// Runs one statement against the suite's private database. Most specs
// never need this: they drive the product. It exists for the one thing
// the product cannot do to itself, which is make time pass.
const admin =
  process.env.PLAYWRIGHT_ADMIN_DATABASE_URL ?? "postgres://supermcp:supermcp@127.0.0.1:55432/postgres?sslmode=disable";
const dbName = process.env.PLAYWRIGHT_DB ?? "supermcp_browser";
const url = admin.replace("/postgres?", `/${dbName}?`);
const container = process.env.PLAYWRIGHT_PG_CONTAINER ?? "supermcp-pg";

export function sql(statement: string, ...params: string[]): string {
  // Parameters are spliced as quoted literals. The callers are specs with
  // values they made up, so this is convenience, not a security boundary.
  const text = params.reduce((acc, p, i) => acc.replaceAll(`$${i + 1}`, `'${p.replaceAll("'", "''")}'`), statement);
  const args = [url, "-v", "ON_ERROR_STOP=1", "-tAc", text];
  try {
    return execFileSync("psql", args, { stdio: ["ignore", "pipe", "inherit"] }).toString().trim();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    const inside = url.replace("127.0.0.1:55432", "127.0.0.1:5432");
    return execFileSync(
      "docker",
      ["exec", "-e", "PGPASSWORD=supermcp", container, "psql", inside, "-v", "ON_ERROR_STOP=1", "-tAc", text],
      { stdio: ["ignore", "pipe", "inherit"] },
    )
      .toString()
      .trim();
  }
}
