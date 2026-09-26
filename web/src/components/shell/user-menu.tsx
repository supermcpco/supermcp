import { useNavigate } from "@tanstack/react-router";
import { hashKey, useMutation, useQueryClient } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { logoutMutation, sessionQueryKey } from "../../api/@tanstack/react-query.gen";
import { useRefreshSession, useSession } from "../../lib/session";
import { message } from "../../lib/errors";
import { toast } from "./toast";

/**
 * Who is signed in, to which workspace, and the way out. Somebody sharing
 * a machine needs that last part, and a product that can only be left by
 * clearing cookies is a product that keeps sessions it should not.
 *
 * It only renders inside the signed-in layout, whose guard has already
 * made sure there is a session.
 */
export function UserMenu() {
  const { session } = useSession();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const refresh = useRefreshSession();
  const signOut = useMutation({
    ...logoutMutation(),
    onSuccess: async () => {
      // Off the console first, so nothing under it renders against a
      // session that has ended; then drop everything the last person could
      // see, and ask again who (nobody) is here.
      await navigate({ to: "/login", search: {} });
      const current = hashKey(sessionQueryKey());
      qc.removeQueries({ predicate: (q) => q.queryHash !== current });
      await refresh();
      toast("You have signed out.");
    },
    onError: (e) => toast(message(e), { kind: "error" }),
  });

  return (
    <div className="grid gap-0.5 px-2">
      <span className="truncate" title={session?.organization?.name}>
        <Text as="span" bold>
          {session?.organization?.name ?? "No workspace"}
        </Text>
      </span>
      <span className="truncate" title={session?.user?.email}>
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
