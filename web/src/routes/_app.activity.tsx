import { lazy, Suspense } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { Tabs, Text } from "@cloudflare/kumo";
import { CallsPanel } from "../components/activity-calls";
import { defaultTab, nextSearch, parseActivitySearch, type ActivitySearch, type Tab } from "../lib/activity";
import { useSession } from "../lib/session";
import { Loading } from "../lib/ui";

// The charts bring ECharts, most of the screen's weight, which the calls
// tab has no use for; it is fetched when the analytics tab first opens.
const AnalyticsPanel = lazy(() =>
  import("../components/activity-analytics").then((m) => ({ default: m.AnalyticsPanel })),
);

export const Route = createFileRoute("/_app/activity")({
  // Which tab is open, and its filters, live in the URL, so a link or a
  // reload lands on the same view. /tool-calls and /analytics lead here.
  validateSearch: parseActivitySearch,
  component: Activity,
});

const tabLabels: Record<Tab, string> = { calls: "Calls", analytics: "Analytics" };

function Activity() {
  const { can } = useSession();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const tab: Tab = search.tab ?? defaultTab;

  // Both tabs read with the same permission, so either both are there or
  // the screen says why neither is.
  if (!can("connectors:read")) {
    return <Text>You do not have permission to see this workspace's tool calls.</Text>;
  }

  // A filter or a period is a refinement of the view, not a place to go
  // back to, so it replaces the entry; a tab is a place, so it adds one.
  const change = (next: { [K in keyof ActivitySearch]?: unknown }, replace: boolean) =>
    navigate({ search: (prev) => nextSearch(prev, next), replace });

  return (
    <div className="grid gap-6">
      <Text as="h1" variant="heading" size="lg">
        Activity
      </Text>

      <Tabs
        variant="underline"
        value={tab}
        onValueChange={(v) => change({ tab: v }, false)}
        tabs={[
          { value: "calls", label: tabLabels.calls },
          { value: "analytics", label: tabLabels.analytics },
        ]}
      />

      <div role="tabpanel" aria-label={tabLabels[tab]}>
        {tab === "analytics" ? (
          <Suspense fallback={<Loading />}>
            <AnalyticsPanel search={search} onSearch={(next) => change(next, true)} />
          </Suspense>
        ) : (
          <CallsPanel search={search} onSearch={(next) => change(next, true)} />
        )}
      </div>
    </div>
  );
}
