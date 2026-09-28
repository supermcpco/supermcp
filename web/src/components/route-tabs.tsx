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
 */
export function RouteTabs({
  tabs,
  value,
  size = "base",
}: {
  tabs: readonly RouteTab[];
  value: string;
  size?: "base" | "sm";
}) {
  return (
    <Tabs
      variant={size === "sm" ? "segmented" : "underline"}
      size={size}
      value={value}
      className="self-start"
      tabs={tabs.map((t) => ({ value: t.value, label: t.label, render: t.link, nativeButton: false }))}
    />
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
