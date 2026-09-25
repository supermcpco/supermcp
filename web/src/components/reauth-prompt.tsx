import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import { reauthenticateMutation, sessionQueryKey } from "../api/@tanstack/react-query.gen";
import { message } from "../lib/errors";
import { useSession } from "../lib/session";

/**
 * What proving it is you again looks like for this session. A password
 * session types its password here. A single sign-on session is sent back
 * through its provider, which leaves the page and returns to `next`. A
 * provider that never says when the person authenticated (GitHub) cannot
 * make a session fresh at all, and the person is told what they can do
 * instead. Used by the dialog and by the /reauth page.
 */
export function ReauthPrompt({
  next,
  onConfirmed,
  onCancel,
}: {
  /** Where a provider sign-in comes back to. */
  next: string;
  onConfirmed: () => void | Promise<void>;
  onCancel?: () => void;
}) {
  const { session } = useSession();
  const qc = useQueryClient();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const confirm = useMutation({
    ...reauthenticateMutation(),
    onSuccess: async () => {
      setPassword("");
      await qc.invalidateQueries({ queryKey: sessionQueryKey() });
      await onConfirmed();
    },
    onError: (e) => setError(message(e)),
  });

  const signIn = session?.signIn;
  const cancel = onCancel && <Button onClick={onCancel}>Cancel</Button>;
  const passwordSignIn = `/login?next=${encodeURIComponent(next)}`;

  if (signIn && signIn.method !== "password" && !signIn.canReauth) {
    const provider = signIn.providerName ?? "Your sign-in provider";
    return (
      <div className="grid gap-4">
        <Text>
          {provider} does not say when you last signed in, so signing in with it again cannot confirm it is you. Sign
          in with your password if your account has one, or ask an administrator to make this change.
        </Text>
        <div className="flex flex-wrap gap-2">
          <a href={passwordSignIn} className="rounded-md px-4 py-2 text-center ring ring-kumo-line hover:bg-kumo-tint">
            <Text as="span">Sign in with a password</Text>
          </a>
          {cancel}
        </div>
      </div>
    );
  }

  if (signIn && signIn.method !== "password") {
    const provider = signIn.providerName;
    return (
      <div className="grid gap-4">
        <Text>
          This action needs a sign-in from the last few minutes.{" "}
          {provider ? `Sign in again with ${provider}, then repeat the action.` : "Sign in again, then repeat the action."}
        </Text>
        <div className="flex flex-wrap gap-2">
          <a
            href={signIn.reauthUrl ? `${signIn.reauthUrl}&next=${encodeURIComponent(next)}` : passwordSignIn}
            className="rounded-md px-4 py-2 text-center ring ring-kumo-line hover:bg-kumo-tint"
          >
            <Text as="span">{provider ? `Sign in again with ${provider}` : "Sign in again"}</Text>
          </a>
          {cancel}
        </div>
      </div>
    );
  }

  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        confirm.mutate({ body: { password } });
      }}
    >
      <Text>This action needs a sign-in from the last few minutes. Enter your password to continue.</Text>
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
        {cancel}
      </div>
    </form>
  );
}
