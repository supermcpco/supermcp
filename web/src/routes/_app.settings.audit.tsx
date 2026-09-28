import { createFileRoute, Link, Outlet, useLocation } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";
import { useSession } from "../lib/session";
import { Help, HeadingWithHelp } from "../components/help";
import { RouteTabs, TabPanel, type RouteTab } from "../components/route-tabs";

/**
 * The audit trail: its log, what it keeps and for how long, and where a
 * copy of it goes. Each is a tab with its own address beneath this one.
 */
export const Route = createFileRoute("/_app/settings/audit")({
  component: AuditLayout,
});

type View = "log" | "retention" | "shipping";

function AuditLayout() {
  const { can } = useSession();
  const pathname = useLocation({ select: (l) => l.pathname });
  const view: View = pathname.endsWith("/retention") ? "retention" : pathname.endsWith("/shipping") ? "shipping" : "log";

  if (!can("audit:read")) {
    return <Text>You do not have permission to read the audit trail for this workspace.</Text>;
  }

  const tabs: RouteTab[] = [
    { value: "log", label: "Log", link: <Link to="/settings/audit" /> },
    { value: "retention", label: "Retention", link: <Link to="/settings/audit/retention" /> },
  ];
  // Where the trail is shipped is read with the permission to export it.
  if (can("audit:export")) {
    tabs.push({ value: "shipping", label: "Shipping", link: <Link to="/settings/audit/shipping" /> });
  }
  const label = { log: "Log", retention: "Retention", shipping: "Shipping" }[view];

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <HeadingWithHelp
          heading={
            <Text as="h2" variant="heading3">
              Audit trail
            </Text>
          }
          help={
            <Help about="the audit trail">
              <Text>Every sign-in, change and tool call is recorded, in the order it happened.</Text>
              <Text>
                Each entry carries the hash of the one before it, so a deleted or edited row breaks the chain and can
                be detected.
              </Text>
            </Help>
          }
        />
        <Text>Every sign-in, change and tool call, chained so tampering shows.</Text>
      </div>

      <RouteTabs size="sm" value={view} tabs={tabs} />

      <TabPanel label={label} className="grid gap-8">
        <Outlet />
      </TabPanel>
    </div>
  );
}
