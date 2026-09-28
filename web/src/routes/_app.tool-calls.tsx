import { createFileRoute, redirect } from "@tanstack/react-router";

// The calls are a tab of the activity screen now. The old address stays
// so bookmarks and links to it still land on them.
export const Route = createFileRoute("/_app/tool-calls")({
  beforeLoad: () => {
    throw redirect({ to: "/activity", replace: true });
  },
});
