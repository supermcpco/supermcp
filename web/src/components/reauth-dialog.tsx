import { useSyncExternalStore } from "react";
import { Dialog, DialogRoot, DialogTitle } from "@cloudflare/kumo";
import type { ReauthGate } from "../lib/reauth";
import { ReauthPrompt } from "./reauth-prompt";

/**
 * The question the gate asks: prove it is still you. A password session
 * answers here and the refused action goes through without the person
 * doing it again. A single sign-on session leaves the page for its
 * provider and repeats the action when it comes back.
 */
export function ReauthDialog({ gate }: { gate: ReauthGate }) {
  const open = useSyncExternalStore(gate.subscribe, gate.open);
  return (
    <DialogRoot open={open} onOpenChange={(next) => !next && gate.answer(false)}>
      {/* Mounted per question, so a password typed last time is not still there. */}
      {open && (
        <Dialog className="grid max-w-md gap-4 p-6">
          <DialogTitle className="text-lg font-semibold">Confirm it is you</DialogTitle>
          <ReauthPrompt
            next={window.location.pathname + window.location.search}
            onConfirmed={() => gate.answer(true)}
            onCancel={() => gate.answer(false)}
          />
        </Dialog>
      )}
    </DialogRoot>
  );
}
