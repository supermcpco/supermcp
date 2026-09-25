import { createFileRoute } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";
import { useSession } from "../lib/session";
import { Loading, SignInFirst } from "../lib/ui";

export const Route = createFileRoute("/settings/members")({
  component: Members,
});

function Members() {
  const { signedIn, can, loading } = useSession();

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;
  if (!can("org:read")) return <Text>You do not have permission to see the members of this workspace.</Text>;

  return (
    <div className="grid gap-1.5">
      <Text as="h1" variant="heading2">
        Members
      </Text>
      <Text variant="secondary">Managing members and invitations is coming.</Text>
    </div>
  );
}
