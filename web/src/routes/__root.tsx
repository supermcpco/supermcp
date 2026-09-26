import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";
import { LinkProvider } from "@cloudflare/kumo";
import { AppLink } from "../components/shell/app-link";
import { Toaster } from "../components/shell/toaster";

interface RouterContext {
  queryClient: QueryClient;
}

// No frame is drawn here. Which frame a screen gets, the signed-in shell or
// the sign-in card, is decided by the pathless layout it sits under:
// `_app` for the console, `_public` for the pages somebody reaches before
// they have a session. The toaster sits above both, so a confirmation
// outlives the move from one to the other ("You have signed out").
// Kumo's links (the sidebar's among them) go through the router from here
// down, which is why this is inside the router rather than in main.tsx.
export const Route = createRootRouteWithContext<RouterContext>()({
  component: Root,
});

function Root() {
  return (
    <LinkProvider component={AppLink}>
      <Outlet />
      <Toaster />
    </LinkProvider>
  );
}
