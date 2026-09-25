import { describe, expect, it } from "vitest";
import type { ResyncDto } from "../api";
import { notAppliedNote, resyncSummary, skipReason } from "./resync";

const empty: ResyncDto = {
  connectorId: "c",
  catalogSlug: "s",
  installedHash: "a",
  bundledHash: "b",
  outdated: true,
  version: 1,
  add: [],
  update: [],
  remove: [],
  skipped: [],
  relabel: [],
  fields: [],
  notApplied: [],
  missingCredentials: [],
};

describe("resyncSummary", () => {
  it("says when nothing changes", () => {
    expect(resyncSummary(empty)).toBe("no tool or setting changed");
  });

  it("counts each kind of change", () => {
    const r: ResyncDto = {
      ...empty,
      add: [{ name: "a" }, { name: "b" }],
      update: [{ name: "c", changed: ["description"] }],
      fields: [{ field: "instructions", before: "x", after: "y" }],
      skipped: [{ name: "d", toolId: "t", reason: "edited", change: "update" }],
      relabel: [{ name: "e", toolId: "u" }],
      notApplied: [{ field: "transport", before: "{}", after: "{}" }],
    };
    expect(resyncSummary(r)).toBe(
      "2 tools added, 1 tool updated, 1 setting replaced, 1 tool marked as the catalog's, 1 tool left alone",
    );
  });
});

describe("skipReason", () => {
  it("names what the catalog would have done to an edited tool", () => {
    expect(skipReason({ name: "a", toolId: "t", reason: "edited", change: "remove" })).toContain("would have removed");
    expect(skipReason({ name: "a", toolId: "t", reason: "edited", change: "update" })).toContain("would have updated");
  });

  it("explains a name clash with a tool made here", () => {
    expect(skipReason({ name: "a", toolId: "t", reason: "custom", change: "add" })).toContain("made here");
  });
});

describe("notAppliedNote", () => {
  it("names the settings and says they are left alone", () => {
    const note = notAppliedNote(["transport", "auth"]);
    expect(note).toContain("transport and authentication");
    expect(note).toContain("never changes");
  });
});
