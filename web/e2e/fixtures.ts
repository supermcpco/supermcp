import { test as base, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

// A workspace per test file, created through the real sign-up form. The
// alternative, seeding the database, would test a state the product can
// never actually be in.
export interface Workspace {
  email: string;
  password: string;
  org: string;
}

export const test = base.extend<{ workspace: Workspace }>({
  workspace: async ({ page }, use, testInfo) => {
    const unique = `${Date.now()}-${testInfo.workerIndex}-${Math.floor(Math.random() * 1e6)}`;
    const workspace: Workspace = {
      email: `browser-${unique}@example.test`,
      password: "Correct Horse Battery 9",
      org: `Browser ${unique}`,
    };
    await signUp(page, workspace);
    await use(workspace);
  },
});

export { expect };

/** Creates an account through the form a first visitor sees. */
export async function signUp(page: Page, w: Workspace) {
  await page.goto("/login");
  await page.getByRole("button", { name: /create a new workspace/i }).click();
  await page.getByLabel("Email").fill(w.email);
  await page.getByLabel("Password").fill(w.password);
  await page.getByLabel("Workspace name").fill(w.org);
  await page.getByRole("button", { name: /create workspace/i }).click();
  // The overview renders for anonymous visitors too, so it proves nothing.
  // The workspace name in the sidebar only appears for a session.
  await expect(page.getByText(w.org, { exact: false })).toBeVisible();
}

/** Signs in an existing account. */
export async function signIn(page: Page, w: Workspace) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(w.email);
  await page.getByLabel("Password").fill(w.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByText(w.org, { exact: false })).toBeVisible();
}

/**
 * Fails on the accessibility rules that stop someone using a page at all:
 * unusable contrast, controls with no name, a form field with no label.
 * Best-practice rules are left out so the check stays actionable.
 */
export async function expectAccessible(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(
    serious.map((v) => `${v.id}: ${v.help} (${v.nodes.length} places, e.g. ${v.nodes[0]?.target.join(" ")})`),
    "the page has accessibility faults that would stop someone using it",
  ).toEqual([]);
}
