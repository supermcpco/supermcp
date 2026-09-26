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

/**
 * The route id a flat file name stands for: dots are slashes, and an
 * "index" segment is the trailing slash of its parent.
 */
function impliedPath(file: string): string {
  const segments = file.replace(/\.tsx$/, "").split(".");
  if (segments.at(-1) === "index") return `/${segments.slice(0, -1).join("/")}/`;
  return `/${segments.join("/")}`;
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
      expect(path, `${file} declares a route its file name does not`).toBe(impliedPath(file));
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

// There is one boundary between what an anonymous visitor can open and
// what needs a session, and it is the pathless layout a route sits under.
// A screen left outside `_app` would render for anybody, with no sidebar
// and every request refused; the lists below are what keeps that a
// decision rather than an accident.
describe("the authentication boundary", () => {
  const generated = readFileSync(join(import.meta.dirname, "routeTree.gen.ts"), "utf8");

  /** Every route id in the generated tree, from its FileRoutesById map. */
  function routeIds(): string[] {
    const body = /export interface FileRoutesById \{([\s\S]*?)\n\}/.exec(generated)?.[1] ?? "";
    return [...body.matchAll(/^\s*'([^']+)':/gm)].map((m) => m[1]);
  }

  // Signing in, creating a workspace, and accepting an invitation: the only
  // things somebody can do before they have a session.
  const publicRoutes = ["/_public/invite/$token", "/_public/login"];

  it("has a signed-in layout and a public one directly under the root", () => {
    const ids = routeIds();
    expect(ids).toContain("/_app");
    expect(ids).toContain("/_public");
    expect(generated).toMatch(/const AppRoute = AppRouteImport\.update\(\{\s*id: '\/_app',[\s\S]*?getParentRoute: \(\) => rootRouteImport/);
    expect(generated).toMatch(
      /const PublicRoute = PublicRouteImport\.update\(\{\s*id: '\/_public',[\s\S]*?getParentRoute: \(\) => rootRouteImport/,
    );
  });

  it("puts every route under one of the two layouts", () => {
    const outside = routeIds().filter(
      (id) => id !== "/_app" && id !== "/_public" && !id.startsWith("/_app/") && !id.startsWith("/_public/"),
    );
    expect(outside, "routes outside both layouts render with no session check and no frame").toEqual([]);
  });

  it("leaves exactly the intended routes public", () => {
    const open = routeIds()
      .filter((id) => id.startsWith("/_public/"))
      .sort();
    expect(open).toEqual(publicRoutes);
  });

  it("guards the signed-in layout before anything under it loads", () => {
    const layout = readFileSync(join(routesDir, "_app.tsx"), "utf8");
    expect(layout).toMatch(/beforeLoad:[^\n]*requireSession\(/);
  });

  it("draws the console's navigation only in the signed-in layout", () => {
    for (const file of ["__root.tsx", "_public.tsx"]) {
      const source = readFileSync(join(routesDir, file), "utf8");
      expect(source, `${file} must not render the sidebar`).not.toMatch(/<nav\b|<aside\b/);
    }
  });
});
