import { describe, expect, it } from "vitest";
import { callsQuery, isFiltered, nextSearch, parseActivitySearch, statusLabel, widerRange } from "./activity";

describe("parseActivitySearch", () => {
  it("keeps the tab, the call filters and the analytics choices", () => {
    expect(parseActivitySearch({ tab: "analytics", range: "30d", by: "connector" })).toEqual({
      tab: "analytics",
      range: "30d",
      by: "connector",
    });
    expect(
      parseActivitySearch({ status: "denied", q: "echo", connector: "c1", server: "s1", period: "24h" }),
    ).toEqual({ status: "denied", q: "echo", connector: "c1", server: "s1", period: "24h" });
  });

  it("keeps the calls' period apart from the analytics' one", () => {
    expect(parseActivitySearch({ period: "7d", range: "30d" })).toEqual({ period: "7d", range: "30d" });
  });

  it("leaves the defaults out, so the screen as first opened is plain /activity", () => {
    expect(parseActivitySearch({ tab: "calls", status: "all", q: "  ", connector: "", period: "" })).toEqual({});
    expect(parseActivitySearch({})).toEqual({});
  });

  it("drops what it does not know", () => {
    expect(parseActivitySearch({ tab: "logs", status: "ok", q: 3, range: "1y", period: "1y", server: 4 })).toEqual({});
    // The old in-browser "failed" filter has no one outcome on the server.
    expect(parseActivitySearch({ status: "failed" })).toEqual({});
  });
});

describe("nextSearch", () => {
  it("changes one part and keeps the rest", () => {
    expect(nextSearch({ tab: "analytics", range: "30d" }, { by: "connector" })).toEqual({
      tab: "analytics",
      range: "30d",
      by: "connector",
    });
  });

  it("drops a choice set back to its default", () => {
    expect(nextSearch({ tab: "analytics", range: "30d", by: "server" }, { tab: "calls", range: "7d", by: "tool" })).toEqual(
      {},
    );
    expect(nextSearch({ status: "error", q: "echo", period: "24h" }, { status: undefined, q: "", period: undefined })).toEqual(
      {},
    );
  });
});

describe("callsQuery", () => {
  const now = new Date("2026-09-28T12:00:30Z");

  it("asks for the plain latest calls when nothing is filtered", () => {
    expect(callsQuery({}, 100, now)).toEqual({ limit: 100 });
    expect(isFiltered({})).toBe(false);
    expect(isFiltered({ q: "  " })).toBe(false);
  });

  it("sends each filter as the server's parameter", () => {
    expect(callsQuery({ status: "denied", q: " echo ", connector: "c1", server: "s1" }, 100, now)).toEqual({
      limit: 100,
      status: "denied",
      q: "echo",
      connectorId: "c1",
      serverId: "s1",
    });
    expect(isFiltered({ connector: "c1" })).toBe(true);
  });

  it("turns a period into a window ending at the next whole minute", () => {
    expect(callsQuery({ period: "24h" }, 100, now)).toEqual({
      limit: 100,
      since: "2026-09-27T12:01:00.000Z",
      until: "2026-09-28T12:01:00.000Z",
    });
    expect(isFiltered({ period: "7d" })).toBe(true);
  });
});

describe("statusLabel", () => {
  it("says each status in words and passes an unknown one through", () => {
    expect(["success", "error", "timeout", "denied", "queued"].map(statusLabel)).toEqual([
      "Succeeded",
      "Failed",
      "Timed out",
      "Refused",
      "queued",
    ]);
  });
});

describe("widerRange", () => {
  it("steps to the next longer period and stops at the longest", () => {
    expect(widerRange("24h")).toBe("7d");
    expect(widerRange("30d")).toBe("90d");
    expect(widerRange("90d")).toBeUndefined();
  });
});
