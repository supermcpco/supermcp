import { describe, expect, it } from "vitest";
import { errorRate, formatMs, groupName, parseAnalyticsSearch, ranges, usageWindow } from "./analytics";

describe("parseAnalyticsSearch", () => {
  it("keeps a known range and dimension", () => {
    expect(parseAnalyticsSearch({ range: "30d", by: "server" })).toEqual({ range: "30d", by: "server" });
  });

  it("drops what it does not know, so the defaults apply", () => {
    expect(parseAnalyticsSearch({ range: "1y", by: "principal" })).toEqual({});
    expect(parseAnalyticsSearch({ range: 7, by: ["tool"] })).toEqual({});
    expect(parseAnalyticsSearch({})).toEqual({});
  });
});

describe("usageWindow", () => {
  const now = new Date("2026-03-01T12:30:15.250Z");
  const day = 24 * 60 * 60 * 1000;

  it("ends at the next whole minute, so reads a few seconds apart ask the same thing", () => {
    expect(usageWindow("7d", now).to).toBe("2026-03-01T12:31:00.000Z");
    expect(usageWindow("7d", new Date("2026-03-01T12:30:59.000Z"))).toEqual(usageWindow("7d", now));
  });

  it("ends now when now is a whole minute", () => {
    expect(usageWindow("24h", new Date("2026-03-01T12:30:00.000Z")).to).toBe("2026-03-01T12:30:00.000Z");
  });

  it.each([
    ["24h", 1],
    ["7d", 7],
    ["30d", 30],
    ["90d", 90],
  ] as const)("%s spans exactly %i days, never more than the server allows", (range, days) => {
    const w = usageWindow(range, now);
    expect(Date.parse(w.to) - Date.parse(w.from)).toBe(days * day);
  });

  it("offers every range it can compute", () => {
    for (const r of ranges) expect(() => usageWindow(r, now)).not.toThrow();
  });
});

describe("formatting", () => {
  it("says a missing latency as a dash and a long one in seconds", () => {
    expect(formatMs(undefined)).toBe("–");
    expect(formatMs(12.4)).toBe("12 ms");
    expect(formatMs(12_345)).toBe("12.3 s");
  });

  it("gives an error rate only when there were calls", () => {
    expect(errorRate(0, 0)).toBe("–");
    expect(errorRate(4, 1)).toBe("25%");
    expect(errorRate(3, 1)).toBe("33.3%");
  });

  it("names rows the server could not", () => {
    expect(groupName("tool", "t_1", "search")).toBe("search");
    expect(groupName("server", "", "")).toBe("No MCP server");
    expect(groupName("server", "srv_gone", "")).toBe("srv_gone (deleted)");
    expect(groupName("connector", "", "")).toBe("Unknown");
  });
});
