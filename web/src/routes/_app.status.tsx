import { createFileRoute, redirect } from "@tanstack/react-router";

/**
 * The instance's status used to be a screen of its own. It is the
 * Instance tab of the settings now; the old address still leads there.
 */
export const Route = createFileRoute("/_app/status")({
  beforeLoad: () => {
    throw redirect({ to: "/settings/instance", replace: true });
  },
});
