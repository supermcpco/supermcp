import { createFileRoute, redirect } from "@tanstack/react-router";
import { ensureSession, permits } from "../lib/session";
import { firstSettingsTab } from "../lib/settings-tabs";

/**
 * `/settings` on its own opens the first tab the person may read. The
 * session is already in the cache by the time this runs (the signed-in
 * layout's guard put it there), so the redirect costs no request.
 */
export const Route = createFileRoute("/_app/settings/")({
  beforeLoad: async ({ context }) => {
    const session = await ensureSession(context.queryClient);
    throw redirect({ to: firstSettingsTab(permits(session)), replace: true });
  },
});
