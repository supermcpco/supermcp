import { useQuery, useQueryClient } from "@tanstack/react-query";
import { sessionOptions } from "../api/@tanstack/react-query.gen";

/**
 * The signed-in user, their organisation and what they may do.
 *
 * `loading` matters as much as `signedIn`: until the session has come
 * back, nobody is signed in as far as this hook can tell, and a screen
 * that acts on that shows a sign-in prompt to someone who is already
 * signed in. Screens wait for `loading` to clear before deciding.
 */
export function useSession() {
  const q = useQuery({ ...sessionOptions(), retry: false });
  return {
    ...q,
    session: q.data,
    loading: q.isPending,
    signedIn: !!q.data && !q.data.anonymous,
    can: (permission: string) =>
      !!q.data?.permissions?.some((p) => p === permission || p === "*"),
  };
}

/** Drops cached session state after sign-in, sign-out or an org switch. */
export function useRefreshSession() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries();
}
