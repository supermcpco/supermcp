import { Link } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";
import { useSession } from "../../lib/session";
import { visibleGroups } from "./nav";

/**
 * The primary navigation: one landmark, a heading per group, and only
 * the screens this person's permissions let them use. `onNavigate` is
 * how the drawer closes itself once somebody has picked a screen.
 */
export function NavGroups({ onNavigate }: { onNavigate?: () => void }) {
  const { can } = useSession();
  const groups = visibleGroups(can);
  return (
    <nav aria-label="Primary" className="grid gap-5">
      {groups.map((g) => {
        const heading = `nav-group-${g.label.toLowerCase()}`;
        return (
          <div key={g.label} className="grid gap-1">
            <div className="px-2">
              <Text as="h2" variant="secondary" id={heading}>
                {g.label}
              </Text>
            </div>
            <ul aria-labelledby={heading} className="grid gap-0.5">
              {g.items.map(({ to, label, icon: Icon }) => (
                <li key={to}>
                  <Link
                    to={to}
                    onClick={onNavigate}
                    className="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-kumo-tint"
                    activeProps={{ className: "bg-kumo-tint font-medium", "aria-current": "page" }}
                    activeOptions={{ exact: to === "/" }}
                  >
                    <span className="h-lh flex items-center">
                      <Icon size={16} aria-hidden />
                    </span>
                    <Text as="span">{label}</Text>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </nav>
  );
}
