import { Sidebar, Text, useSidebar } from "@cloudflare/kumo";
import { Hexagon, List } from "@phosphor-icons/react";
import { useSession } from "../../lib/session";
import { NavGroups } from "./nav-groups";
import { UserMenu } from "./user-menu";

/** The width below which the sidebar is a sheet (Tailwind's lg). */
export const sidebarBreakpoint = 1024;

/**
 * The application's sidebar, for use inside `Sidebar.Provider`. From
 * 1024px up it sits beside the content and collapses to a rail of icons;
 * below that Kumo renders it as a sheet that the top bar's Menu button
 * opens. The navigation scrolls on a short window while the person's own
 * block stays pinned underneath it, so signing out never scrolls away.
 */
export function AppSidebar() {
  const { session } = useSession();
  const { isMobile } = useSidebar();
  const workspace = session?.organization?.name ?? "No workspace";
  return (
    // On a narrow screen the sheet is the menu the top bar's button opens,
    // so it carries that button's name.
    <Sidebar aria-label={isMobile ? "Menu" : "Sidebar"}>
      <Sidebar.Header className="gap-2">
        <span className="grid size-8 shrink-0 place-items-center">
          <Hexagon size={20} weight="duotone" aria-hidden />
        </span>
        <span className="grid min-w-0 flex-1 transition-opacity group-data-[state=collapsed]/sidebar:opacity-0">
          <Text as="span" bold>
            supermcp
          </Text>
          <span className="truncate" title={workspace}>
            <Text as="span" variant="secondary">
              {workspace}
            </Text>
          </span>
        </span>
        {isMobile && <Sidebar.Close />}
      </Sidebar.Header>
      {/* Not Sidebar.Content: that is Base UI's ScrollArea, which injects a
          <style> element the content security policy (style-src 'self')
          refuses. A plain scrolling column with Kumo's own spacing does
          the same job without widening the policy. */}
      <div className="min-h-0 min-w-0 flex-1 overflow-x-hidden overflow-y-auto px-[11px] py-3 transition-[padding] duration-(--sidebar-animation-duration) group-not-data-[state=collapsed]/sidebar:px-3.5">
        <NavGroups />
      </div>
      <Sidebar.Footer className="h-auto flex-col items-stretch gap-1 py-2">
        <UserMenu />
        {!isMobile && <Sidebar.Trigger />}
      </Sidebar.Footer>
    </Sidebar>
  );
}

/**
 * What stands in for the sidebar below 1024px: the product's name and the
 * button that opens the navigation as a sheet. Kumo hands focus back to
 * the button when the sheet is put away with Escape.
 */
export function TopBar() {
  const { isMobile, openMobile } = useSidebar();
  if (!isMobile) return null;
  return (
    <header className="flex shrink-0 items-center gap-2 border-b border-kumo-line px-3 py-2">
      <Sidebar.Trigger aria-label="Menu" aria-expanded={openMobile}>
        <List size={20} aria-hidden />
      </Sidebar.Trigger>
      <Text as="span" variant="heading3">
        supermcp
      </Text>
    </header>
  );
}
