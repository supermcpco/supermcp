import { useState, useSyncExternalStore } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Dialog, DialogDescription, DialogRoot, DialogTitle, Input, Text } from "@cloudflare/kumo";
import { reauthenticateMutation, sessionQueryKey } from "../api/@tanstack/react-query.gen";
import { message } from "../lib/errors";
import type { ReauthGate } from "../lib/reauth";
import { useSession } from "../lib/session";

/**
 * The question the gate asks: prove it is still you. A password session
 * answers with its password, here, and the refused action goes through
 * without the person doing it again. A single sign-on session has no
 * password to give, so it is sent back through its provider; that leaves
 * the page, and the person repeats the action when they come back.
 */
export function ReauthDialog({ gate }: { gate: ReauthGate }) {
  const open = useSyncExternalStore(gate.subscribe, gate.open);
  return (
    <DialogRoot open={open} onOpenChange={(next) => !next && gate.answer(false)}>
      {/* Mounted per question, so a password typed last time is not still there. */}
      {open && <ReauthForm onDone={(ok) => gate.answer(ok)} />}
    </DialogRoot>
  );
}

function ReauthForm({ onDone }: { onDone: (confirmed: boolean) => void }) {
  const { session } = useSession();
  const qc = useQueryClient();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const confirm = useMutation({
    ...reauthenticateMutation(),
    onSuccess: async () => {
      setPassword("");
      await qc.invalidateQueries({ queryKey: sessionQueryKey() });
      onDone(true);
    },
    onError: (e) => setError(message(e)),
  });

  const signIn = session?.signIn;
  const viaProvider = signIn && signIn.method !== "password";
  const here = window.location.pathname + window.location.search;

  return (
    <Dialog className="grid max-w-md gap-4 p-6">
      <DialogTitle className="text-lg font-semibold">Confirm it is you</DialogTitle>
      {viaProvider ? (
        <>
          <DialogDescription>
            This action needs a sign-in from the last few minutes.{" "}
            {signIn.providerName
              ? `Sign in again with ${signIn.providerName}, then repeat the action.`
              : "Sign in again, then repeat the action."}
          </DialogDescription>
          <div className="flex gap-2">
            <a
              href={
                signIn.reauthUrl
                  ? `${signIn.reauthUrl}&next=${encodeURIComponent(here)}`
                  : `/login?next=${encodeURIComponent(here)}`
              }
              className="rounded-md px-4 py-2 text-center ring ring-kumo-line hover:bg-kumo-tint"
            >
              <Text as="span">
                {signIn.providerName ? `Sign in again with ${signIn.providerName}` : "Sign in again"}
              </Text>
            </a>
            <Button onClick={() => onDone(false)}>Cancel</Button>
          </div>
        </>
      ) : (
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            confirm.mutate({ body: { password } });
          }}
        >
          <DialogDescription>
            This action needs a sign-in from the last few minutes. Enter your password to continue.
          </DialogDescription>
          <label className="grid gap-1.5">
            <Text as="span">Password</Text>
            <Input
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {error && (
            <div role="alert">
              <Text>{error}</Text>
            </div>
          )}
          <div className="flex gap-2">
            <Button type="submit" variant="primary" disabled={confirm.isPending || !password}>
              {confirm.isPending ? "Checking…" : "Confirm"}
            </Button>
            <Button onClick={() => onDone(false)}>Cancel</Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
