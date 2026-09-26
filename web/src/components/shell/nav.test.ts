import { describe, expect, it } from "vitest";
import { navGroups, visibleGroups } from "./nav";

// The built-in roles as the database seeds them (migration 00002).
const viewer = ["org:read", "connectors:read", "tools:read", "tools:invoke", "servers:read", "roles:read", "apikeys:self:manage"];
const auditor = ["org:read", "connectors:read", "tools:read", "servers:read", "roles:read", "audit:read", "audit:export"];
const consumer = ["tools:read", "tools:invoke"];
const owner = ["*"];

/** The same test the session hook applies. */
const holding = (perms: string[]) => (p: string) => perms.some((h) => h === p || h === "*");

const labels = (perms: string[]) =>
  Object.fromEntries(visibleGroups(holding(perms)).map((g) => [g.label, g.items.map((i) => i.label)]));

describe("visibleGroups", () => {
  it("shows an owner every group and every item", () => {
    const seen = visibleGroups(holding(owner));
    expect(seen).toEqual(navGroups);
  });

  it("shows a viewer no Settings group", () => {
    const seen = labels(viewer);
    expect(Object.keys(seen)).toEqual(["Build", "Operate"]);
    expect(seen.Build).toEqual(["Overview", "Catalog", "Connectors", "MCP servers"]);
    // A viewer may neither ask for approval nor decide one.
    expect(seen.Operate).toEqual(["API keys", "Tool calls", "Analytics", "Status"]);
  });

  it("shows an auditor the audit trail and nothing else under Settings", () => {
    expect(labels(auditor).Settings).toEqual(["Audit trail"]);
  });

  it("shows approvals to somebody who may only ask for them", () => {
    expect(labels([...viewer, "approvals:request"]).Operate).toContain("Approvals");
  });

  it("keeps the screens that need nothing for somebody who holds almost nothing", () => {
    expect(labels(consumer)).toEqual({ Build: ["Overview", "Catalog"], Operate: ["Status"] });
  });

  it("drops a group that is left with no items", () => {
    const groups = [{ label: "Empty", items: [{ to: "/status", label: "Status", icon: navGroups[0].items[0].icon, needs: "x:y" }] }] as const;
    expect(visibleGroups(holding(viewer), groups)).toEqual([]);
  });
});
