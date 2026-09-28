import { mayOpen } from "../components/shell/nav";

/** The addresses the settings tabs live at. */
export type SettingsPath =
  | "/settings/members"
  | "/settings/roles"
  | "/settings/security"
  | "/settings/audit"
  | "/settings/dlp"
  | "/settings/sso"
  | "/settings/service-accounts"
  | "/settings/instance";

export interface SettingsTab {
  to: SettingsPath;
  label: string;
  /**
   * What the tab's first read asks the server for, as in the sidebar: a
   * tab somebody may not read is not shown to them. Single sign-on and
   * service accounts have no read-only view, so they need the permission
   * to manage them.
   */
  needs?: string | readonly string[];
}

/** Every settings tab, in the order the strip shows them. */
export const settingsTabs: readonly SettingsTab[] = [
  { to: "/settings/members", label: "Members", needs: "org:read" },
  { to: "/settings/roles", label: "Roles", needs: "roles:read" },
  // Your own name, password and sessions: anyone signed in. The address
  // is the one it had as "Security", so older links still land on it.
  { to: "/settings/security", label: "Account" },
  { to: "/settings/audit", label: "Audit", needs: "audit:read" },
  { to: "/settings/dlp", label: "Data-loss rules", needs: "connectors:read" },
  { to: "/settings/sso", label: "Single sign-on", needs: "idp:manage" },
  { to: "/settings/service-accounts", label: "Service accounts", needs: "serviceaccounts:manage" },
  // Whether this instance is up and whole: anyone signed in.
  { to: "/settings/instance", label: "Instance" },
];

/** The tabs one person sees. Account and Instance need nothing, so it is never empty. */
export function visibleSettingsTabs(can: (permission: string) => boolean): SettingsTab[] {
  return settingsTabs.filter((t) => mayOpen(can, t.needs));
}

/** Where `/settings` sends somebody: the first tab they may read. */
export function firstSettingsTab(can: (permission: string) => boolean): SettingsPath {
  return visibleSettingsTabs(can)[0]?.to ?? "/settings/security";
}

/** Which tab an address belongs to; a page beneath a tab keeps it open. */
export function settingsTabFor(pathname: string): SettingsTab | undefined {
  return settingsTabs.find((t) => pathname === t.to || pathname.startsWith(`${t.to}/`));
}
