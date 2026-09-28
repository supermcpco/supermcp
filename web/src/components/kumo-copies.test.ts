import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

// A few components here stand in for Kumo ones that fall short in a way
// Kumo gives no prop to fix (a toast that is a dialog, a tooltip with no
// role, an input that cannot see its label). Each one was written against
// one Kumo version and says so in a "KUMO COPY" note at its top, along
// with the condition under which it can be deleted. This test is how
// whoever bumps Kumo learns to go and read those notes: it fails until
// every note names the installed version.

const componentsDir = import.meta.dirname;
const kumoPackage = join(componentsDir, "../../node_modules/@cloudflare/kumo/package.json");

/** The files that copy or work around Kumo, relative to src/components. */
const copies = [
  "shell/toaster.tsx",
  "shell/named-tooltip.tsx",
  "shell/rail-button.tsx",
  "tooltip.tsx",
  "labelled-input.tsx",
  "select.tsx",
  "../app.css",
];

function installedKumo(): string {
  const { version } = JSON.parse(readFileSync(kumoPackage, "utf8")) as { version: string };
  return version;
}

function notedVersion(file: string): string | undefined {
  const source = readFileSync(join(componentsDir, file), "utf8");
  return /KUMO COPY: written against @cloudflare\/kumo (\S+?)[\s(]/.exec(source)?.[1];
}

describe("Kumo copies", () => {
  it.each(copies)("%s names the Kumo version it was written against", (file) => {
    expect(notedVersion(file), `${file} has no "KUMO COPY: written against @cloudflare/kumo <version>" note`).toBeDefined();
  });

  it("were all checked against the installed Kumo", () => {
    const installed = installedKumo();
    const stale = copies.filter((file) => notedVersion(file) !== installed);
    expect(
      stale,
      `@cloudflare/kumo is now ${installed}. Read the KUMO COPY note at the top of each file below: ` +
        `delete the copy if the new Kumo does what it stands in for, otherwise check it still matches ` +
        `and set its note to ${installed}. Files: ${stale.join(", ")}`,
    ).toEqual([]);
  });

  it("app.css hides the scrollbar under the class Base UI still uses", () => {
    // With CSPProvider disableStyleElements (main.tsx), Base UI leaves this
    // rule to the page. If it renames the class, Sidebar.Content grows a
    // native scrollbar beside its own, and nothing else would notice.
    const kumoDir = dirname(kumoPackage);
    const baseUiPackage = createRequire(kumoPackage).resolve("@base-ui/react/package.json", { paths: [kumoDir] });
    const styles = readFileSync(join(dirname(baseUiPackage), "utils/styles.js"), "utf8");
    const className = /DISABLE_SCROLLBAR_CLASS_NAME = ['"]([\w-]+)['"]/.exec(styles)?.[1];
    expect(className).toBe("base-ui-disable-scrollbar");
    const css = readFileSync(join(componentsDir, "../app.css"), "utf8");
    expect(css).toContain(`.${className} {\n  scrollbar-width: none;\n}`);
    expect(css).toContain(`.${className}::-webkit-scrollbar {\n  display: none;\n}`);
  });
});
