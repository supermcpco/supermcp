import { useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { redirect, useRouter } from "@tanstack/react-router";
import { sessionOptions } from "../api/@tanstack/react-query.gen";
import type { SessionBody } from "../api/types.gen";

/**
 * How the session is asked for, by the hook and by the router's guard
 * alike, so both read the same cache entry.
 *
 * It goes stale in seconds and is asked again when the tab comes back into
 * view: a tab left open across a sign-out elsewhere, or opened before the
 * instance's first account was created, would otherwise keep acting on
 * what was true when it loaded.
 */
export function sessionQuery() {
  return { ...sessionOptions(), retry: false, staleTime: 5_000, refetchOnWindowFocus: true } as const;
}

/** Whether a session body belongs to somebody signed in. */
export function isSignedIn(session: SessionBody | undefined): boolean {
  return !!session && !session.anonymous;
}

/**
 * The session as the router's guards see it. Cached data answers at once
 * so moving between screens does not wait on the network; stale data is
 * checked again in the background.
 */
export function ensureSession(queryClient: QueryClient): Promise<SessionBody> {
  return queryClient.ensureQueryData({ ...sessionQuery(), revalidateIfStale: true });
}

/**
 * The guard for a screen that needs somebody signed in. An anonymous
 * visitor is sent to sign in, with `href` as the place to come back to.
 */
export async function requireSession(queryClient: QueryClient, href: string): Promise<SessionBody> {
  const session = await ensureSession(queryClient);
  if (!isSignedIn(session)) throw redirect({ to: "/login", search: { next: href } });
  return session;
}

/**
 * The signed-in user, their organisation and what they may do.
 *
 * Screens under the signed-in layout never see `loading` or an anonymous
 * session: the layout's guard has already answered both before they render.
 */
export function useSession() {
  const q = useQuery(sessionQuery());
  return {
    ...q,
    session: q.data,
    loading: q.isPending,
    signedIn: isSignedIn(q.data),
    can: (permission: string) =>
      !!q.data?.permissions?.some((p) => p === permission || p === "*"),
  };
}

/**
 * Drops cached state after sign-in, sign-out, registration or an org
 * switch, then runs the router's guards again against the new session, so
 * a screen that needs a session and no longer has one sends its visitor to
 * sign in.
 */
export function useRefreshSession() {
  const qc = useQueryClient();
  const router = useRouter();
  return async () => {
    await qc.invalidateQueries();
    await router.invalidate();
  };
}
