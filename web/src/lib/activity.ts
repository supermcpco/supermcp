// Helpers for the activity screen: which tab is open, and the filters on
// the list of calls, kept apart from the components so they can be tested
// without a browser.

import {
  defaultDimension,
  defaultRange,
  parseAnalyticsSearch,
  ranges,
  usageWindow,
  type AnalyticsSearch,
  type Range,
} from "./analytics";

export const tabs = ["calls", "analytics"] as const;
export type Tab = (typeof tabs)[number];

export const defaultTab: Tab = "calls";

/**
 * The status filter on the list of calls: every call, or the calls with
 * one outcome. The server filters, and it knows the four outcomes a call
 * can have; "failed" alone is an error the tool itself reported.
 */
export const statusFilters = ["all", "success", "error", "timeout", "denied"] as const;
export type StatusFilter = (typeof statusFilters)[number];
export type CallStatus = Exclude<StatusFilter, "all">;

export const statusFilterLabels: Record<StatusFilter, string> = {
  all: "All calls",
  success: "Succeeded",
  error: "Failed",
  timeout: "Timed out",
  denied: "Refused",
};

export interface CallsSearch {
  status?: CallStatus;
  /** Part of a tool's name. */
  q?: string;
  /** A connector's id. */
  connector?: string;
  /** An MCP server's id. */
  server?: string;
  /** How far back the list reaches; left out, it is the latest calls whenever made. */
  period?: Range;
}

export type ActivitySearch = { tab?: Exclude<Tab, "calls"> } & CallsSearch & AnalyticsSearch;

const text = (v: unknown) => (typeof v === "string" && v.trim() !== "" ? v : undefined);

/**
 * The screen's search parameters, with anything unknown dropped and the
 * defaults left out, so the screen as first opened is plain /activity.
 * The analytics parameters are read by the analytics helper, so an old
 * /analytics address carries its period and breakdown over unchanged.
 * The calls tab keeps a period of its own, `period`, because its default
 * is no period at all where the analytics' is a week.
 */
export function parseActivitySearch(search: Record<string, unknown>): ActivitySearch {
  const out: ActivitySearch = { ...parseAnalyticsSearch(search) };
  if (search.tab === "analytics") out.tab = "analytics";
  const status = search.status;
  if (typeof status === "string" && status !== "all" && (statusFilters as readonly string[]).includes(status)) {
    out.status = status as CallStatus;
  }
  const q = text(search.q);
  if (q) out.q = q;
  const connector = text(search.connector);
  if (connector) out.connector = connector;
  const server = text(search.server);
  if (server) out.server = server;
  if (typeof search.period === "string" && (ranges as readonly string[]).includes(search.period)) {
    out.period = search.period as Range;
  }
  return out;
}

/**
 * The search after a change to part of it, with the defaults dropped
 * again: switching back to the first tab or the default period leaves
 * the address as it was before anything was picked.
 */
export function nextSearch(prev: ActivitySearch, change: { [K in keyof ActivitySearch]?: unknown }): ActivitySearch {
  const out = parseActivitySearch({ ...prev, ...change });
  if (out.range === defaultRange) delete out.range;
  if (out.by === defaultDimension) delete out.by;
  return out;
}

/** Whether any filter is set; the server treats a filtered list as a search. */
export function isFiltered({ status, q, connector, server, period }: CallsSearch): boolean {
  return (
    status !== undefined || (q?.trim() ?? "") !== "" || connector !== undefined || server !== undefined || period !== undefined
  );
}

/** What the list of calls asks the server for. */
export interface CallsQuery {
  limit: number;
  status?: CallStatus;
  q?: string;
  connectorId?: string;
  serverId?: string;
  since?: string;
  until?: string;
}

/**
 * The query for the list of calls. With no filter it is the plain latest
 * `limit` calls, which the server answers without counting it against
 * the analytics limits; each filter adds its parameter and nothing else.
 * The period ends at the next whole minute, as the analytics' does, so
 * two reads a moment apart ask the same question.
 */
export function callsQuery(search: CallsSearch, limit: number, now: Date): CallsQuery {
  const out: CallsQuery = { limit };
  if (search.status) out.status = search.status;
  const q = search.q?.trim();
  if (q) out.q = q;
  if (search.connector) out.connectorId = search.connector;
  if (search.server) out.serverId = search.server;
  if (search.period) {
    const { from, to } = usageWindow(search.period, now);
    out.since = from;
    out.until = to;
  }
  return out;
}

/** A call's status in words; one the screen does not know is shown as sent. */
export function statusLabel(status: string): string {
  switch (status) {
    case "success":
      return "Succeeded";
    case "error":
      return "Failed";
    case "timeout":
      return "Timed out";
    case "denied":
      return "Refused";
    default:
      return status;
  }
}

/** The next longer period, or none when the range is already the longest. */
export function widerRange(range: Range): Range | undefined {
  const i = ranges.indexOf(range);
  return i >= 0 && i < ranges.length - 1 ? ranges[i + 1] : undefined;
}
