import { useMatchRoute } from "@tanstack/react-router";
import { Sidebar, useSidebar } from "@cloudflare/kumo";
import { useSession } from "../../lib/session";
import { visibleGroups } from "./nav";

/**
 * The primary navigation: one landmark, a heading per group, and only
 * the screens this person's permissions let them use. On a narrow screen,
 * where the list is a sheet over the content, picking a screen puts the
 * sheet away.
 */
export function NavGroups() {
  const { can } = useSession();
  const { isMobile, setOpenMobile } = useSidebar();
  const matchRoute = useMatchRoute();
  const groups = visibleGroups(can);
  return (
    <nav aria-label="Primary" className="flex min-w-0 flex-col">
      {groups.map((g) => {
        const heading = `nav-group-${g.label.toLowerCase()}`;
        return (
          <Sidebar.Group key={g.label}>
            <Sidebar.GroupLabel>
              <h2 id={heading}>{g.label}</h2>
            </Sidebar.GroupLabel>
            <Sidebar.Menu aria-labelledby={heading}>
              {g.items.map(({ to, label, icon }) => (
                <Sidebar.MenuButton
                  key={to}
                  href={to}
                  icon={icon}
                  tooltip={label}
                  // The overview is current only on itself; every other
                  // screen stays current on the pages beneath it.
                  active={Boolean(matchRoute({ to, fuzzy: to !== "/" }))}
                  onClick={isMobile ? () => setOpenMobile(false) : undefined}
                >
                  {label}
                </Sidebar.MenuButton>
              ))}
            </Sidebar.Menu>
          </Sidebar.Group>
        );
      })}
    </nav>
  );
}
