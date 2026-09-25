import { createFileRoute } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";

// Public, like /login: the person opening an invite link may have no
// account yet. The token stays in the page URL only; the API receives it in
// a POST body.
export const Route = createFileRoute("/invite/$token")({
  component: Invite,
});

function Invite() {
  return (
    <div className="grid gap-1.5">
      <Text as="h1" variant="heading2">
        Invitation
      </Text>
      <Text variant="secondary">Accepting invitations is coming.</Text>
    </div>
  );
}
