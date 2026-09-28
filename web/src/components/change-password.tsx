import { useId, useState } from "react";
import { useMutation, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import { changePasswordMutation } from "../api/@tanstack/react-query.gen";
import { message } from "../lib/errors";
import { toast } from "./shell/toast";
import { LabelledInput } from "./labelled-input";

/**
 * Changing your own password. The account screen shows it, and so does
 * the shell in place of every other screen when the workspace's maximum
 * age has passed: until the password changes, nothing else will answer.
 */
export function ChangePassword({
  onChanged,
  intro = "Changing it signs out every other device.",
  level = "h2",
}: {
  onChanged?: (qc: QueryClient) => Promise<unknown>;
  intro?: string;
  /** The heading's level where it is shown: a section of a tab sits a level lower. */
  level?: "h2" | "h3";
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();
  const headingId = useId();

  const change = useMutation({
    ...changePasswordMutation(),
    onSuccess: async () => {
      // The toast is the only confirmation, so it carries the consequence too.
      toast("Password changed, and your other devices have been signed out");
      setCurrent("");
      setNext("");
      setError(null);
      await onChanged?.(qc);
    },
    onError: (e) => setError(message(e)),
  });

  return (
    // Held to the width the other forms are, wherever it is shown.
    <section className="grid max-w-3xl gap-3" aria-labelledby={headingId}>
      <div className="grid gap-1">
        <Text as={level} variant="heading" id={headingId}>
          Change your password
        </Text>
        <Text variant="secondary">{intro}</Text>
      </div>
      <form
        className="flex flex-wrap items-end gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate({ body: { currentPassword: current, newPassword: next } });
        }}
      >
        <LabelledInput
          labelClassName="grid min-w-48 max-w-sm flex-1 gap-1.5"
          label="Current password"
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
        />
        <LabelledInput
          labelClassName="grid min-w-48 max-w-sm flex-1 gap-1.5"
          label="New password"
          required
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
        <Button type="submit" variant="primary" disabled={change.isPending || !next}>
          Change password
        </Button>
      </form>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
    </section>
  );
}
