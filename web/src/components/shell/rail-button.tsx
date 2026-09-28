import { Sidebar, useSidebar, type SidebarMenuButtonProps } from "@cloudflare/kumo";
import { NamedTooltip } from "./named-tooltip";

type RailButtonProps = Omit<SidebarMenuButtonProps, "tooltip" | "children"> & {
  /** What the entry says, and what its tooltip says on the icon rail. */
  label: string;
};

/**
 * A sidebar entry that names itself in a tooltip while the sidebar is a
 * rail of icons. Kumo's MenuButton does the same from its `tooltip` prop,
 * but takes only a string and draws it in a popup with no role, so a
 * screen reader user never learns it is a tooltip. This wraps the same
 * Kumo Tooltip around the same button, shown under the same condition,
 * with the text inside an element whose role is `tooltip`.
 */
export function RailButton({ label, ...props }: RailButtonProps) {
  const { state, peekable } = useSidebar();
  return (
    <Sidebar.MenuItem>
      <NamedTooltip
        label={label}
        side="right"
        disabled={state !== "collapsed" || peekable}
        render={<Sidebar.MenuButton {...props}>{label}</Sidebar.MenuButton>}
      />
    </Sidebar.MenuItem>
  );
}
