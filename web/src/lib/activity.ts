// Helpers for the activity screen: which tab is open, and the filters on
// the list of calls, kept apart from the components so they can be tested
// without a browser.

import {
  defaultDimension,
  defaultRange,
  parseAnalyticsSearch,
  ranges,
  type AnalyticsSearch,
  type Range,
} from "./analytics";

export const tabs = ["calls", "analytics"] as const;
export type Tab = (typeof tabs)[number];

export const defaultTab: Tab = "calls";

/**
 * The status filter on the list of calls. A call either succeeded or it
 * did not; "failed" is every call that did not, which is how the
 * analytics tab counts errors (error, timeout or refused by a rule).
 */
export const statusFilters = ["all", "success", "failed"] as const;
export type StatusFilter = (typeof statusFilters)[number];

export const statusFilterLabels: Record<StatusFilter, string> = {
  all: "All calls",
  success: "Succeeded",
  failed: "Failed",
};

export interface CallsSearch {
  status?: Exclude<StatusFilter, "all">;
  /** Part of a tool's name. */
  q?: string;
}

export type ActivitySearch = { tab?: Exclude<Tab, "calls"> } & CallsSearch & AnalyticsSearch;

/**
 * The screen's search parameters, with anything unknown dropped and the
 * defaults left out, so the screen as first opened is plain /activity.
 * The analytics parameters are read by the analytics helper, so an old
 * /analytics address carries its period and breakdown over unchanged.
 */
export function parseActivitySearch(search: Record<string, unknown>): ActivitySearch {
  const out: ActivitySearch = { ...parseAnalyticsSearch(search) };
  if (search.tab === "analytics") out.tab = "analytics";
  if (search.status === "success" || search.status === "failed") out.status = search.status;
  if (typeof search.q === "string" && search.q.trim() !== "") out.q = search.q;
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

/** The fields of a call the filters look at. */
interface Call {
  toolName: string;
  status: string;
}

/**
 * The calls that pass the filters. The API returns the latest calls and
 * takes no filter of its own, so this works over the rows already loaded.
 * The name matches anywhere in the tool's name, ignoring case.
 */
export function filterCalls<T extends Call>(calls: readonly T[], { status, q }: CallsSearch): T[] {
  const needle = q?.trim().toLowerCase() ?? "";
  return calls.filter((c) => {
    if (status === "success" && c.status !== "success") return false;
    if (status === "failed" && c.status === "success") return false;
    return needle === "" || c.toolName.toLowerCase().includes(needle);
  });
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
