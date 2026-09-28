import type { ReactElement, ReactNode } from "react";
import { Tabs } from "@cloudflare/kumo";

/** One tab: what it is called, and the link that opens it. */
export interface RouteTab {
  value: string;
  label: string;
  /** A router `<Link>` to the tab's address; Kumo renders the tab as it. */
  link: ReactElement;
}

/**
 * A strip of tabs where each tab is an address. The router, not the tab
 * strip, decides which one is open, so a link or a reload lands on the
 * same tab and the back button steps between them. Kumo's Tabs gives the
 * strip its look and its arrow-key movement; each tab is still a link,
 * which opens in a new browser tab like any other.
 *
 * There are two kinds, and a screen uses them the same way everywhere:
 *
 * - A screen's own tabs (Settings, Activity, a connector) are Kumo's
 *   underline strip at its default size, across the width of the page.
 * - Tabs inside one of those tabs (the audit trail's Log, Retention and
 *   Shipping; the data-loss rules and detectors) are `nested`: Kumo's
 *   segmented control, as wide as its tabs and no wider, so it reads as a
 *   switch within the section rather than as a second strip of the screen.
 *
 * `label` names the tab list for a screen reader ("Settings, tab list").
 * Kumo's Tabs takes no name of its own, so it is set on the list element
 * once it is drawn; Kumo never sets or clears that attribute itself.
 */
export function RouteTabs({
  tabs,
  value,
  label,
  nested = false,
}: {
  tabs: readonly RouteTab[];
  value: string;
  label: string;
  nested?: boolean;
}) {
  return (
    <div
      ref={(el) => el?.querySelector('[role="tablist"]')?.setAttribute("aria-label", label)}
      className={nested ? "justify-self-start" : undefined}
    >
      <Tabs
        variant={nested ? "segmented" : "underline"}
        value={value}
        tabs={tabs.map((t) => ({ value: t.value, label: t.label, render: t.link, nativeButton: false }))}
      />
    </div>
  );
}

/**
 * What a tab strip opens. It is named after the tab it belongs to, so a
 * screen reader announces "Members, tab panel" on the way in.
 */
export function TabPanel({ label, children, className = "grid gap-6" }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div role="tabpanel" aria-label={label} className={className}>
      {children}
    </div>
  );
}
