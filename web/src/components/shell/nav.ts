import type { Icon } from "@phosphor-icons/react";
import {
  ChartLine,
  ClipboardText,
  Key,
  ListChecks,
  Plugs,
  Pulse,
  Robot,
  SealCheck,
  ShieldCheck,
  ShieldWarning,
  SignIn,
  SquaresFour,
  Stack,
  Storefront,
  Users,
  UsersThree,
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
 * from somebody who may only read. Single sign-on and service accounts
 * have no read-only view, so they need the permission to manage them.
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
      { to: "/tool-calls", label: "Tool calls", icon: ListChecks, needs: "connectors:read" },
      { to: "/analytics", label: "Analytics", icon: ChartLine, needs: "connectors:read" },
      // Somebody who may only ask sees their own requests there; an
      // approver sees the queue.
      { to: "/approvals", label: "Approvals", icon: SealCheck, needs: ["approvals:request", "approvals:decide"] },
      { to: "/status", label: "Status", icon: Pulse },
    ],
  },
  {
    label: "Settings",
    items: [
      { to: "/settings/members", label: "Members", icon: Users, needs: "org:read" },
      // Your own password and sessions: anyone signed in.
      { to: "/settings/security", label: "Security", icon: ShieldCheck },
      { to: "/settings/audit", label: "Audit trail", icon: ClipboardText, needs: "audit:read" },
      { to: "/settings/dlp", label: "Data-loss rules", icon: ShieldWarning, needs: "connectors:read" },
      { to: "/settings/roles", label: "Roles", icon: UsersThree, needs: "roles:read" },
      { to: "/settings/sso", label: "Single sign-on", icon: SignIn, needs: "idp:manage" },
      { to: "/settings/service-accounts", label: "Service accounts", icon: Robot, needs: "serviceaccounts:manage" },
    ],
  },
];

/**
 * The groups as one person sees them: items they lack the permission for
 * are left out, and a group left with nothing is left out with them.
 */
export function visibleGroups(can: (permission: string) => boolean, groups: readonly NavGroup[] = navGroups): NavGroup[] {
  const allowed = (item: NavItem) => {
    if (item.needs === undefined) return true;
    const needs: readonly string[] = typeof item.needs === "string" ? [item.needs] : item.needs;
    return needs.some(can);
  };
  return groups
    .map((g) => ({ ...g, items: g.items.filter(allowed) }))
    .filter((g) => g.items.length > 0);
}
