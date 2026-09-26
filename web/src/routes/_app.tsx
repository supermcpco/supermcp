import { useEffect } from "react";
import { createFileRoute, Outlet, useRouter } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { requireSession, useSession } from "../lib/session";
import { Loading } from "../lib/ui";
import { ChangePassword } from "../components/change-password";
import { Sidebar } from "../components/shell/sidebar";

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
  return (
    <div className="flex h-full flex-col bg-kumo-base text-kumo-default lg:flex-row">
      <Sidebar />
      <main className="min-h-0 min-w-0 flex-1 overflow-y-auto px-6 py-5">
        <div className="max-w-6xl">
          <SessionGate>
            <PasswordAgeGate>
              <Outlet />
            </PasswordAgeGate>
          </SessionGate>
        </div>
      </main>
    </div>
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
