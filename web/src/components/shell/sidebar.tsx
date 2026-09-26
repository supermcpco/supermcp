import { Text } from "@cloudflare/kumo";
import { Drawer } from "./drawer";
import { NavGroups } from "./nav-groups";
import { UserMenu } from "./user-menu";

/**
 * The column itself: navigation that scrolls when the window is short,
 * and the person's own block pinned underneath it so signing out never
 * scrolls away.
 */
function Column({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="min-h-0 flex-1 overflow-y-auto px-3 py-4">
        <NavGroups onNavigate={onNavigate} />
      </div>
      <div className="shrink-0 border-t border-kumo-line px-3 py-3">
        <UserMenu />
      </div>
    </div>
  );
}

/**
 * The application's sidebar. From 1024px up it sits beside the content;
 * below that it becomes a top bar whose Menu button opens it as a drawer.
 * The parent lays the two out as a column on narrow screens and a row on
 * wide ones.
 */
export function Sidebar() {
  return (
    <>
      <aside className="hidden h-full w-56 shrink-0 flex-col border-r border-kumo-line lg:flex">
        <div className="shrink-0 px-5 pt-4">
          <Text as="span" variant="heading3">
            supermcp
          </Text>
        </div>
        <Column />
      </aside>
      <Drawer>{(close) => <Column onNavigate={close} />}</Drawer>
    </>
  );
}
