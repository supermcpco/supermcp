import { createFileRoute, useSearch } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";
import { ReauthPrompt } from "../components/reauth-prompt";
import { safeNext } from "../lib/members";
import { reauthError } from "../lib/reauth-errors";
import { useSession } from "../lib/session";
import { Loading, SignInFirst } from "../lib/ui";

/**
 * Proving it is you again, as a page. The server sends a browser here
 * when there is no screen of ours to open a dialog on: the OAuth consent
 * page, and the return from a provider that did not confirm a recent
 * sign-in. `next` is where to go once confirmed; it may be a page the
 * server renders, so leaving is a full navigation.
 */
export const Route = createFileRoute("/reauth")({
  component: Reauth,
  validateSearch: (search: Record<string, unknown>): { next?: string; error?: string } => ({
    ...(typeof search.next === "string" ? { next: search.next } : {}),
    ...(typeof search.error === "string" ? { error: search.error } : {}),
  }),
});

function Reauth() {
  const search = useSearch({ from: "/reauth" });
  const { signedIn, loading } = useSession();
  const next = safeNext(search.next);
  const problem = reauthError(search.error);

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;
  return (
    <div className="grid max-w-md gap-4">
      <Text as="h1" variant="heading2">
        Confirm it is you
      </Text>
      {problem && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{problem}</Text>
        </div>
      )}
      <ReauthPrompt next={next} onConfirmed={() => window.location.assign(next)} />
      <a href={next} className="underline">
        <Text as="span" variant="secondary">
          Go back without confirming
        </Text>
      </a>
    </div>
  );
}
