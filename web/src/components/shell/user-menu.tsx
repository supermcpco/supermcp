import { useNavigate } from "@tanstack/react-router";
import { hashKey, useMutation, useQueryClient } from "@tanstack/react-query";
import { Sidebar, Text } from "@cloudflare/kumo";
import { SignOut } from "@phosphor-icons/react";
import { logoutMutation, sessionQueryKey } from "../../api/@tanstack/react-query.gen";
import { useRefreshSession, useSession } from "../../lib/session";
import { message } from "../../lib/errors";
import { toast } from "./toast";
import { RailButton } from "./rail-button";
import { TruncatedText } from "./named-tooltip";

/**
 * Who is signed in and the way out. Somebody sharing a machine needs that
 * last part, and a product that can only be left by clearing cookies is a
 * product that keeps sessions it should not.
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

  const email = session?.user?.email ?? "";
  return (
    // Pinned under the scrolling navigation, with the navigation's own
    // padding so Sign out lines up with the entries above it, expanded or
    // as a rail. The address has no room on the rail; the tooltip on Sign
    // out is what remains there.
    <div className="shrink-0 border-t border-kumo-line px-[11px] py-2 transition-[padding] duration-(--sidebar-animation-duration) group-not-data-[state=collapsed]/sidebar:px-3.5">
      <div className="px-3 pb-1 group-data-[state=collapsed]/sidebar:hidden">
        <TruncatedText text={email}>
          <Text as="span" variant="secondary">
            {email}
          </Text>
        </TruncatedText>
      </div>
      <Sidebar.Menu>
        <RailButton icon={SignOut} label="Sign out" onClick={() => signOut.mutate({})} disabled={signOut.isPending} />
      </Sidebar.Menu>
    </div>
  );
}
