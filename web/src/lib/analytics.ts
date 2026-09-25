// Helpers for the analytics screen, kept apart from the component so the
// window arithmetic and the wording can be tested without a browser.

/** The windows the range picker offers, in the order it shows them. */
export const ranges = ["24h", "7d", "30d", "90d"] as const;
export type Range = (typeof ranges)[number];

/** What the top list can be broken down by. */
export const dimensions = ["tool", "connector", "server"] as const;
export type Dimension = (typeof dimensions)[number];

export const defaultRange: Range = "7d";
export const defaultDimension: Dimension = "tool";

const hour = 60 * 60 * 1000;
const rangeMs: Record<Range, number> = {
  "24h": 24 * hour,
  "7d": 7 * 24 * hour,
  "30d": 30 * 24 * hour,
  "90d": 90 * 24 * hour,
};

export const rangeLabels: Record<Range, string> = {
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
  "90d": "Last 90 days",
};

export const dimensionLabels: Record<Dimension, string> = {
  tool: "Tool",
  connector: "Connector",
  server: "MCP server",
};

export interface AnalyticsSearch {
  range?: Range;
  by?: Dimension;
}

/**
 * The screen's search parameters, with anything unknown dropped. The
 * defaults are left out rather than filled in, so the address of the
 * screen as first opened stays plain /analytics.
 */
export function parseAnalyticsSearch(search: Record<string, unknown>): AnalyticsSearch {
  const out: AnalyticsSearch = {};
  if (typeof search.range === "string" && (ranges as readonly string[]).includes(search.range)) {
    out.range = search.range as Range;
  }
  if (typeof search.by === "string" && (dimensions as readonly string[]).includes(search.by)) {
    out.by = search.by as Dimension;
  }
  return out;
}

/**
 * The window to ask the server for. It ends at the next whole minute, so
 * two reads a few seconds apart ask the same question, and it is exactly
 * as long as the range, which the server bounds at 90 days. The bucket is
 * left to the server, which picks hours for a day and days for longer.
 */
export function usageWindow(range: Range, now: Date): { from: string; to: string } {
  const minute = 60 * 1000;
  const to = Math.ceil(now.getTime() / minute) * minute;
  return { from: new Date(to - rangeMs[range]).toISOString(), to: new Date(to).toISOString() };
}

/** A bucket's start as a chart axis shows it, in the viewer's own time zone. */
export function bucketLabel(start: string, bucket: "hour" | "day"): string {
  const d = new Date(start);
  if (bucket === "hour") {
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}

/** A latency for a person to read; a missing one is a dash. */
export function formatMs(ms: number | undefined): string {
  if (ms === undefined) return "–";
  if (ms >= 10_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.round(ms)} ms`;
}

/** The share of calls that failed, as a percentage with one decimal. */
export function errorRate(calls: number, errors: number): string {
  if (calls === 0) return "–";
  const pct = (errors / calls) * 100;
  return `${pct === Math.round(pct) ? pct.toFixed(0) : pct.toFixed(1)}%`;
}

/** "1 call", "3 calls". */
export function plural(n: number, noun: string): string {
  return `${n.toLocaleString()} ${n === 1 ? noun : `${noun}s`}`;
}

/**
 * What a row of the top list is called. The server names what still
 * exists and what a tool was called by; what is left is a server that no
 * longer exists, or calls that went through no server at all.
 */
export function groupName(by: Dimension, id: string, name: string): string {
  if (name) return name;
  if (by === "server" && !id) return "No MCP server";
  return id ? `${id} (deleted)` : "Unknown";
}

/**
 * How often the screen asks again. A day's figures move by the minute; a
 * quarter's barely move in an hour, and each read of one is a heavy query.
 */
export function refreshInterval(range: Range): number {
  switch (range) {
    case "24h":
      return 30_000;
    case "7d":
      return 60_000;
    default:
      return 5 * 60_000;
  }
}

/** refreshInterval in words, for "checks again every …". */
export function refreshLabel(range: Range): string {
  const seconds = refreshInterval(range) / 1000;
  if (seconds < 60) return `${seconds} seconds`;
  return seconds === 60 ? "minute" : `${seconds / 60} minutes`;
}

/**
 * The breakdowns a viewer may pick. The server breakdown names MCP
 * servers, which only servers:read may see, so without it the choice is
 * not offered and a link asking for it falls back to the default.
 */
export function allowedDimensions(canReadServers: boolean): readonly Dimension[] {
  return canReadServers ? dimensions : dimensions.filter((d) => d !== "server");
}
