import { describe, expect, it } from "vitest";
import { firstSettingsTab, settingsTabFor, visibleSettingsTabs } from "./settings-tabs";

// The built-in roles as the database seeds them (migration 00002).
const viewer = ["org:read", "connectors:read", "tools:read", "tools:invoke", "servers:read", "roles:read", "apikeys:self:manage"];
const auditor = ["org:read", "connectors:read", "tools:read", "servers:read", "roles:read", "audit:read", "audit:export"];
const consumer = ["tools:read", "tools:invoke"];

const holding = (perms: string[]) => (p: string) => perms.some((h) => h === p || h === "*");
const labels = (perms: string[]) => visibleSettingsTabs(holding(perms)).map((t) => t.label);

describe("settings tabs", () => {
  it("shows an owner every tab, in order", () => {
    expect(labels(["*"])).toEqual([
      "Members",
      "Roles",
      "Security",
      "Audit",
      "Data-loss rules",
      "Single sign-on",
      "Service accounts",
      "Instance",
    ]);
  });

  it("shows a viewer only the tabs they may read", () => {
    expect(labels(viewer)).toEqual(["Members", "Roles", "Security", "Data-loss rules", "Instance"]);
  });

  it("shows an auditor the audit trail", () => {
    expect(labels(auditor)).toContain("Audit");
    expect(labels(auditor)).not.toContain("Single sign-on");
  });

  it("leaves somebody who holds almost nothing their own security and the instance", () => {
    expect(labels(consumer)).toEqual(["Security", "Instance"]);
  });

  it("opens on the first tab the person may read", () => {
    expect(firstSettingsTab(holding(["*"]))).toBe("/settings/members");
    expect(firstSettingsTab(holding(consumer))).toBe("/settings/security");
  });

  it("keeps a tab open on the pages beneath it", () => {
    expect(settingsTabFor("/settings/audit/retention")?.label).toBe("Audit");
    expect(settingsTabFor("/settings/audit")?.label).toBe("Audit");
    expect(settingsTabFor("/settings/service-accounts")?.label).toBe("Service accounts");
    expect(settingsTabFor("/settings")).toBeUndefined();
  });
});
