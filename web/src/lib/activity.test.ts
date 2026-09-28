import { describe, expect, it } from "vitest";
import { filterCalls, nextSearch, parseActivitySearch, statusLabel, widerRange } from "./activity";

describe("parseActivitySearch", () => {
  it("keeps the tab, the call filters and the analytics choices", () => {
    expect(parseActivitySearch({ tab: "analytics", range: "30d", by: "connector" })).toEqual({
      tab: "analytics",
      range: "30d",
      by: "connector",
    });
    expect(parseActivitySearch({ status: "failed", q: "echo" })).toEqual({ status: "failed", q: "echo" });
  });

  it("leaves the defaults out, so the screen as first opened is plain /activity", () => {
    expect(parseActivitySearch({ tab: "calls", status: "all", q: "  " })).toEqual({});
    expect(parseActivitySearch({})).toEqual({});
  });

  it("drops what it does not know", () => {
    expect(parseActivitySearch({ tab: "logs", status: "ok", q: 3, range: "1y" })).toEqual({});
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
    expect(nextSearch({ status: "failed", q: "echo" }, { status: undefined, q: "" })).toEqual({});
  });
});

describe("filterCalls", () => {
  const calls = [
    { id: "1", toolName: "bundesbank_get_exchange_rates", status: "success" },
    { id: "2", toolName: "analytics_echo", status: "denied" },
    { id: "3", toolName: "Analytics_Card", status: "timeout" },
    { id: "4", toolName: "analytics_echo", status: "error" },
  ];
  const ids = (search: Parameters<typeof filterCalls>[1]) => filterCalls(calls, search).map((c) => c.id);

  it("returns every call with no filter", () => {
    expect(ids({})).toEqual(["1", "2", "3", "4"]);
  });

  it("counts every call that did not succeed as failed", () => {
    expect(ids({ status: "failed" })).toEqual(["2", "3", "4"]);
    expect(ids({ status: "success" })).toEqual(["1"]);
  });

  it("finds a tool by any part of its name, ignoring case and surrounding space", () => {
    expect(ids({ q: " ANALYTICS " })).toEqual(["2", "3", "4"]);
    expect(ids({ q: "card" })).toEqual(["3"]);
    expect(ids({ q: "nothing like it" })).toEqual([]);
  });

  it("applies both filters together", () => {
    expect(ids({ status: "failed", q: "echo" })).toEqual(["2", "4"]);
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
