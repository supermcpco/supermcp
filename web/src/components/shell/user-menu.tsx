import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { logoutMutation } from "../../api/@tanstack/react-query.gen";
import { useSession } from "../../lib/session";
import { message } from "../../lib/errors";
import { toast } from "./toast";

/**
 * Who is signed in, to which workspace, and the way out. Somebody sharing
 * a machine needs that last part, and a product that can only be left by
 * clearing cookies is a product that keeps sessions it should not.
 */
export function UserMenu() {
  const { session, signedIn } = useSession();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const signOut = useMutation({
    ...logoutMutation(),
    onSuccess: async () => {
      qc.clear();
      toast("You have signed out.");
      await navigate({ to: "/login", search: {} });
    },
    onError: (e) => toast(message(e), { kind: "error" }),
  });

  if (!signedIn) return null;
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
