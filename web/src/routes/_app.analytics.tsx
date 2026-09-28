import { createFileRoute, redirect } from "@tanstack/react-router";
import { parseAnalyticsSearch } from "../lib/analytics";

// The analytics are a tab of the activity screen now. The old address
// stays, with its period and breakdown, so bookmarks still land on them.
export const Route = createFileRoute("/_app/analytics")({
  validateSearch: parseAnalyticsSearch,
  beforeLoad: ({ search }) => {
    throw redirect({ to: "/activity", search: { ...search, tab: "analytics" }, replace: true });
  },
});
