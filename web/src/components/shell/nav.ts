import type { Icon } from "@phosphor-icons/react";
import {
  ChartLine,
  GearSix,
  Key,
  Plugs,
  SealCheck,
  SquaresFour,
  Stack,
  Storefront,
} from "@phosphor-icons/react";
import type { LinkProps } from "@tanstack/react-router";

export interface NavItem {
  to: NonNullable<LinkProps["to"]>;
  label: string;
  icon: Icon;
  /**
   * The permission the screen's first read asks the server for. A list
   * means any one of them will do; none means everyone signed in.
   */
  needs?: string | readonly string[];
}

export interface NavGroup {
  label: string;
  items: readonly NavItem[];
}

/**
 * Every screen the sidebar leads to, in the order it shows them.
 *
 * An item is listed exactly when the person can open its screen without
 * being refused: `needs` is what the screen's first read asks the server
 * for. Write controls are the screens' own business, and each hides them
 * from somebody who may only read. Settings is one screen of tabs, and
 * its Security tab (your own password) needs nothing, so it is listed
 * for everyone; which of its tabs a person sees is decided on the screen.
 */
export const navGroups: readonly NavGroup[] = [
  {
    label: "Build",
    items: [
      { to: "/", label: "Overview", icon: SquaresFour },
      { to: "/catalog", label: "Catalog", icon: Storefront },
      { to: "/connectors", label: "Connectors", icon: Plugs, needs: "connectors:read" },
      { to: "/servers", label: "MCP servers", icon: Stack, needs: "servers:read" },
    ],
  },
  {
    label: "Operate",
    items: [
      { to: "/api-keys", label: "API keys", icon: Key, needs: "apikeys:self:manage" },
      // Calls and analytics, as two tabs; both read with connectors:read.
      { to: "/activity", label: "Activity", icon: ChartLine, needs: "connectors:read" },
      // Somebody who may only ask sees their own requests there; an
      // approver sees the queue.
      { to: "/approvals", label: "Approvals", icon: SealCheck, needs: ["approvals:request", "approvals:decide"] },
    ],
  },
  {
    label: "Settings",
    items: [{ to: "/settings", label: "Settings", icon: GearSix }],
  },
];

/**
 * Whether somebody may open a screen that needs `needs`: nothing, one
 * permission, or any one of a list. The sidebar and the settings tabs
 * both ask it, so the two cannot disagree about what a person may read.
 */
export function mayOpen(can: (permission: string) => boolean, needs?: string | readonly string[]): boolean {
  if (needs === undefined) return true;
  const any: readonly string[] = typeof needs === "string" ? [needs] : needs;
  return any.some(can);
}

/**
 * The groups as one person sees them: items they lack the permission for
 * are left out, and a group left with nothing is left out with them.
 */
export function visibleGroups(can: (permission: string) => boolean, groups: readonly NavGroup[] = navGroups): NavGroup[] {
  const allowed = (item: NavItem) => mayOpen(can, item.needs);
  return groups
    .map((g) => ({ ...g, items: g.items.filter(allowed) }))
    .filter((g) => g.items.length > 0);
}
