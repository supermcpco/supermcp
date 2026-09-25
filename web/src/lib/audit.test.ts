import { describe, expect, it } from "vitest";
import { auditExportHref, auditSearchMax, parseAuditSearch } from "./audit";

describe("parseAuditSearch", () => {
  it("keeps a known category, an actor and a search", () => {
    expect(parseAuditSearch({ category: "admin", actor: "u_1", q: "connector.created" })).toEqual({
      category: "admin",
      actor: "u_1",
      q: "connector.created",
    });
  });

  it("drops what it does not know and what is blank", () => {
    expect(parseAuditSearch({ category: "everything", actor: "  ", q: "" })).toEqual({});
    expect(parseAuditSearch({ category: 3, actor: ["u_1"], q: { a: 1 } })).toEqual({});
    expect(parseAuditSearch({})).toEqual({});
  });

  it("reads a search of digits alone, which the router hands over as a number", () => {
    expect(parseAuditSearch({ q: 404 })).toEqual({ q: "404" });
  });

  it("cuts a search to what the server takes", () => {
    const q = parseAuditSearch({ q: "a".repeat(auditSearchMax + 50) }).q;
    expect(q).toHaveLength(auditSearchMax);
  });
});

describe("auditExportHref", () => {
  it("is the bare export with no filters", () => {
    expect(auditExportHref({})).toBe("/api/v1/audit/export");
  });

  it("carries every filter the screen shows, escaped", () => {
    expect(auditExportHref({ category: "auth", actor: "u_1", q: '"api key" -revoked' })).toBe(
      "/api/v1/audit/export?category=auth&actorId=u_1&q=%22api+key%22+-revoked",
    );
  });
});
