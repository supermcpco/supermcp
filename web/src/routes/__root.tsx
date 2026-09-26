import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";

interface RouterContext {
  queryClient: QueryClient;
}

// Nothing is drawn here. Which frame a screen gets, the signed-in shell or
// the sign-in card, is decided by the pathless layout it sits under:
// `_app` for the console, `_public` for the pages somebody reaches before
// they have a session.
export const Route = createRootRouteWithContext<RouterContext>()({
  component: Outlet,
});
