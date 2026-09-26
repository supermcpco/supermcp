import { useEffect, useState } from "react";
import { createFileRoute, Outlet, useRouter } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Sidebar, Text } from "@cloudflare/kumo";
import { requireSession, useSession } from "../lib/session";
import { Loading } from "../lib/ui";
import { ChangePassword } from "../components/change-password";
import { AppSidebar, sidebarBreakpoint, TopBar } from "../components/shell/sidebar";
import { readSidebarOpen, storeSidebarOpen } from "../components/shell/sidebar-state";

/**
 * Everything that needs a session. The guard runs before any screen under
 * it loads, so an anonymous visitor is sent to sign in, with the way back
 * in `next`, instead of being shown a console of refusals.
 */
export const Route = createFileRoute("/_app")({
  beforeLoad: ({ context, location }) => requireSession(context.queryClient, location.href),
  component: Shell,
});

function Shell() {
  // Read once: Kumo takes it as the starting state and reports each change,
  // which is stored so a reload keeps the sidebar as it was left. The open
  // state is not controlled from here because in Kumo a controlled `open`
  // also drives the narrow-screen sheet, which would then open by itself on
  // every load and overwrite the wide-screen choice.
  const [startOpen] = useState(readSidebarOpen);
  return (
    <Sidebar.Provider
      collapsible="icon"
      mobileBreakpoint={sidebarBreakpoint}
      defaultOpen={startOpen}
      onOpenChange={storeSidebarOpen}
      className="h-full bg-kumo-base text-kumo-default"
    >
      <AppSidebar />
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="min-h-0 min-w-0 flex-1 overflow-y-auto px-6 py-5">
          <SessionGate>
            <PasswordAgeGate>
              <Outlet />
            </PasswordAgeGate>
          </SessionGate>
        </main>
      </div>
    </Sidebar.Provider>
  );
}

/**
 * The guard answers when a screen is opened; this answers while it stays
 * open. The session is asked again when the tab regains focus, and if it
 * ended elsewhere meanwhile (a sign-out in another tab, an expiry) the
 * guard is run again, which sends the visitor to sign in with the way
 * back, rather than leaving them on a screen that refuses every request.
 */
function SessionGate({ children }: { children: React.ReactNode }) {
  const { signedIn, loading } = useSession();
  const router = useRouter();
  const ended = !loading && !signedIn;
  useEffect(() => {
    if (ended) void router.invalidate();
  }, [ended, router]);
  if (loading || ended) return <Loading />;
  return <>{children}</>;
}

/**
 * Stands in for every screen while the password is past the workspace's
 * maximum age. The server refuses everything else until it is changed, so
 * showing the screens would only show a column of refusals.
 */
function PasswordAgeGate({ children }: { children: React.ReactNode }) {
  const { session } = useSession();
  const qc = useQueryClient();
  if (!session?.passwordExpired) return <>{children}</>;
  return (
    <div className="grid max-w-2xl gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Your password has expired
        </Text>
        <Text>This workspace requires passwords to be changed regularly. Choose a new one to carry on.</Text>
      </div>
      <ChangePassword
        onChanged={() => qc.invalidateQueries()}
      />
    </div>
  );
}
