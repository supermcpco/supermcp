import { createRootRouteWithContext, Link, Outlet, useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { logoutMutation } from "../api/@tanstack/react-query.gen";
import type { QueryClient } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import {
  ChartLine,
  ClipboardText,
  FileArrowUp,
  Key,
  ListChecks,
  Plugs,
  Pulse,
  Robot,
  ShieldCheck,
  ShieldWarning,
  SignIn,
  SealCheck,
  SquaresFour,
  Stack,
  Users,
  UsersThree,
  Storefront,
} from "@phosphor-icons/react";
import { useSession } from "../lib/session";
import { ChangePassword } from "../components/change-password";

interface RouterContext {
  queryClient: QueryClient;
}

export const Route = createRootRouteWithContext<RouterContext>()({
  component: Shell,
});

const nav = [
  { to: "/", label: "Overview", icon: SquaresFour },
  { to: "/catalog", label: "Catalog", icon: Storefront },
  { to: "/connectors", label: "Connectors", icon: Plugs },
  { to: "/connectors/import", label: "Import an API", icon: FileArrowUp },
  { to: "/servers", label: "MCP servers", icon: Stack },
  { to: "/api-keys", label: "API keys", icon: Key },
  { to: "/tool-calls", label: "Tool calls", icon: ListChecks },
  { to: "/analytics", label: "Analytics", icon: ChartLine },
  { to: "/approvals", label: "Approvals", icon: SealCheck },
  { to: "/status", label: "Status", icon: Pulse },
] as const;

const settingsNav = [
  { to: "/settings/members", label: "Members", icon: Users },
  { to: "/settings/security", label: "Security", icon: ShieldCheck },
  { to: "/settings/audit", label: "Audit trail", icon: ClipboardText },
  { to: "/settings/dlp", label: "Data-loss rules", icon: ShieldWarning },
  { to: "/settings/roles", label: "Roles", icon: UsersThree },
  { to: "/settings/sso", label: "Single sign-on", icon: SignIn },
  { to: "/settings/service-accounts", label: "Service accounts", icon: Robot },
] as const;

function Shell() {
  return (
    <div className="flex h-full bg-kumo-base text-kumo-default">
      <aside className="flex w-56 shrink-0 flex-col border-r border-kumo-line px-3 py-4">
        <div className="px-2 pb-4">
          <Text as="span" variant="heading3">
            supermcp
          </Text>
        </div>
        <WorkspaceBadge />
        <nav aria-label="Primary" className="grid gap-0.5">
          {nav.map(({ to, label, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              className="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-kumo-tint"
              activeProps={{ className: "bg-kumo-tint font-medium", "aria-current": "page" }}
              activeOptions={{ exact: to === "/" }}
            >
              <span className="h-lh flex items-center">
                <Icon size={16} aria-hidden />
              </span>
              <Text as="span">{label}</Text>
            </Link>
          ))}
        </nav>
        <div className="px-2 pt-5 pb-1">
          <Text as="span" variant="secondary">
            Settings
          </Text>
        </div>
        <nav aria-label="Settings" className="grid gap-0.5">
          {settingsNav.map(({ to, label, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              className="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-kumo-tint"
              activeProps={{ className: "bg-kumo-tint font-medium", "aria-current": "page" }}
            >
              <span className="h-lh flex items-center">
                <Icon size={16} aria-hidden />
              </span>
              <Text as="span">{label}</Text>
            </Link>
          ))}
        </nav>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto px-6 py-5">
        <PasswordAgeGate>
          <Outlet />
        </PasswordAgeGate>
      </main>
    </div>
  );
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

/**
 * Who is signed in, to which workspace, and the way out. Somebody sharing
 * a machine needs that last part, and a product that can only be left by
 * clearing cookies is a product that keeps sessions it should not.
 */
function WorkspaceBadge() {
  const { session, signedIn } = useSession();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const signOut = useMutation({
    ...logoutMutation(),
    onSuccess: async () => {
      qc.clear();
      await navigate({ to: "/login", search: {} });
    },
  });

  if (!signedIn) {
    return (
      <div className="px-2 pb-3">
        <Link to="/login" search={{}} className="underline">
          <Text as="span" variant="secondary">
            Sign in
          </Text>
        </Link>
      </div>
    );
  }
  return (
    <div className="grid gap-0.5 px-2 pb-3">
      <Text as="span" variant="secondary">
        {session?.organization?.name ?? "No workspace"}
      </Text>
      <span className="truncate">
        <Text as="span" variant="secondary">
          {session?.user?.email}
        </Text>
      </span>
      <button
        type="button"
        className="justify-self-start underline"
        onClick={() => signOut.mutate({})}
        disabled={signOut.isPending}
      >
        <Text as="span" variant="secondary">
          Sign out
        </Text>
      </button>
    </div>
  );
}
