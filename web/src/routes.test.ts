import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Twice now a screen has disappeared because a route file became the
// parent of a nested route. TanStack renders a parent around its children,
// so a parent that draws a list and no outlet swallows every child route
// and shows the list instead. The fix is to name the list ".index"; this
// test is what stops the third time.
const routesDir = join(import.meta.dirname, "routes");

function routeFiles(): string[] {
  return readdirSync(routesDir).filter((f) => f.endsWith(".tsx") && !f.startsWith("__"));
}

/** The route path a file declares, from its own createFileRoute call. */
function declaredPath(file: string): string | null {
  const source = readFileSync(join(routesDir, file), "utf8");
  return /createFileRoute\("([^"]+)"\)/.exec(source)?.[1] ?? null;
}

describe("route files", () => {
  const files = routeFiles();

  it("every file declares the path its name implies", () => {
    for (const file of files) {
      const path = declaredPath(file);
      expect(path, `${file} has no createFileRoute call`).not.toBeNull();
    }
  });

  it("a route with children is either an index or renders an outlet", () => {
    const paths = new Map<string, string>();
    for (const file of files) {
      const path = declaredPath(file);
      if (path) paths.set(path, file);
    }
    for (const [path, file] of paths) {
      if (path.endsWith("/") || path === "/") continue;
      const hasChildren = [...paths.keys()].some((other) => other !== path && other.startsWith(`${path}/`));
      if (!hasChildren) continue;
      const source = readFileSync(join(routesDir, file), "utf8");
      expect(
        source.includes("<Outlet"),
        `${file} declares "${path}" and other files nest under it, so it is their layout. ` +
          `It must render an <Outlet /> or be renamed to the index route "${path}/".`,
      ).toBe(true);
    }
  });
});
