import { useState } from "react";
import { useMutation, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import { changePasswordMutation } from "../api/@tanstack/react-query.gen";
import { message } from "../lib/errors";

/**
 * Changing your own password. The security screen shows it, and so does
 * the shell in place of every other screen when the workspace's maximum
 * age has passed: until the password changes, nothing else will answer.
 */
export function ChangePassword({
  onChanged,
  intro = "Changing it signs out every other device.",
}: {
  onChanged?: (qc: QueryClient) => Promise<unknown>;
  intro?: string;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();

  const change = useMutation({
    ...changePasswordMutation(),
    onSuccess: async () => {
      setCurrent("");
      setNext("");
      setDone(true);
      setError(null);
      await onChanged?.(qc);
    },
    onError: (e) => {
      setDone(false);
      setError(message(e));
    },
  });

  return (
    <section className="grid gap-3">
      <div className="grid gap-1">
        <Text as="h2" variant="heading3">
          Change your password
        </Text>
        <Text variant="secondary">{intro}</Text>
      </div>
      <form
        className="flex max-w-3xl flex-wrap items-end gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate({ body: { currentPassword: current, newPassword: next } });
        }}
      >
        <label className="grid flex-1 gap-1.5">
          <Text as="span">Current password</Text>
          <Input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </label>
        <label className="grid flex-1 gap-1.5">
          <Text as="span">New password</Text>
          <Input
            required
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
          />
        </label>
        <Button type="submit" variant="primary" disabled={change.isPending || !next}>
          Change password
        </Button>
      </form>
      {done && (
        <div role="status">
          <Text>Password changed. Other devices have been signed out.</Text>
        </div>
      )}
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
    </section>
  );
}
