import { createFileRoute, Link, Outlet, useLocation } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";
import { useSession } from "../lib/session";
import { settingsTabFor, visibleSettingsTabs } from "../lib/settings-tabs";
import { RouteTabs, TabPanel } from "../components/route-tabs";

/**
 * Settings: one screen, a tab per part. Each tab keeps the address it had
 * when it was a screen of its own, so a link or a bookmark to any of them
 * still lands there, now with the strip above it. A tab the person may not
 * read is not in the strip; its address still opens, and says why there
 * is nothing to see.
 */
export const Route = createFileRoute("/_app/settings")({
  component: SettingsLayout,
});

function SettingsLayout() {
  const { can } = useSession();
  const pathname = useLocation({ select: (l) => l.pathname });
  const tabs = visibleSettingsTabs(can);
  const current = settingsTabFor(pathname);
  const shown = current && tabs.includes(current) ? current.to : "";

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Settings
        </Text>
        <Text>Who is in this workspace, what they may do, and how it is kept safe.</Text>
      </div>

      <RouteTabs
        value={shown}
        tabs={tabs.map((t) => ({ value: t.to, label: t.label, link: <Link to={t.to} /> }))}
      />

      <TabPanel label={current?.label ?? "Settings"} className="grid gap-8">
        <Outlet />
      </TabPanel>
    </div>
  );
}
