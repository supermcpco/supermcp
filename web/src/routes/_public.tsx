import { createFileRoute, Outlet } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";

/**
 * The frame for pages somebody reaches without a session, or on the way to
 * one: signing in, creating a workspace, accepting an invitation. One card
 * and the product's name; the console's navigation would only lead to
 * pages that send them straight back here.
 */
export const Route = createFileRoute("/_public")({
  component: PublicLayout,
});

function PublicLayout() {
  return (
    <div className="flex min-h-full flex-col items-center justify-center gap-6 bg-kumo-base px-4 py-10 text-kumo-default">
      <Text as="span" variant="heading3">
        supermcp
      </Text>
      <main className="grid w-full max-w-md rounded-lg px-6 py-8 ring ring-kumo-line">
        <Outlet />
      </main>
    </div>
  );
}
