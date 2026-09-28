import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  auditGetPolicyOptions,
  auditGetPolicyQueryKey,
  auditGetRetentionOptions,
  auditGetRetentionQueryKey,
  auditLegalHoldMutation,
  auditLegalHoldReleaseMutation,
  auditSetPolicyMutation,
  auditSetRetentionMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { message } from "../lib/errors";
import { toast } from "../components/shell/toast";
import { Help, HeadingWithHelp } from "../components/help";

/**
 * What the trail keeps and for how long: the days an event keeps its
 * content, the hold that stops that for an investigation, and how much
 * of a tool call's input and output is kept in the first place.
 */
export const Route = createFileRoute("/_app/settings/audit/retention")({
  component: AuditRetention,
});

function AuditRetention() {
  return (
    <>
      <Retention />
      <LegalHold />
      <PayloadPolicy />
    </>
  );
}

/** How long the workspace's events keep their content. */
function Retention() {
  const { can } = useSession();
  const qc = useQueryClient();
  const retention = useQuery({ ...auditGetRetentionOptions(), retry: false });
  // null while the field shows the stored value; a string once edited.
  const [draft, setDraft] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    ...auditSetRetentionMutation(),
    onSuccess: async (r) => {
      setDraft(null);
      setError(null);
      toast(`Events now keep their content for ${r.days} days`);
      await qc.invalidateQueries({ queryKey: auditGetRetentionQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });
  const editable = can("audit:policy:manage");

  const r = retention.data;
  if (!r) return null;
  const value = draft ?? String(r.days);
  const days = Number(value);
  const valid = Number.isInteger(days) && days >= r.minDays && days <= r.maxDays;

  return (
    <section className="grid gap-3">
      <div className="grid gap-1.5">
        <HeadingWithHelp
          heading={
            <Text as="h3" variant="heading">
              How long it is kept
            </Text>
          }
          help={
            <Help about="retention">
              <Text>
                Past this many days an event loses its content, but stays in the chain so it can still be verified.
              </Text>
              <Text>
                The event itself is deleted later, once no workspace on this instance keeps it any longer, and never
                while it is under a hold.
              </Text>
            </Help>
          }
        />
        <Text variant="secondary">How many days an event keeps its content.</Text>
      </div>
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) save.mutate({ body: { days } });
        }}
      >
        <label className="grid gap-1">
          <Text as="span">Days</Text>
          <Input
            type="number"
            inputMode="numeric"
            min={r.minDays}
            max={r.maxDays}
            step={1}
            value={value}
            onChange={(e) => setDraft(e.currentTarget.value)}
            disabled={!editable || save.isPending}
            aria-describedby="retention-range"
            aria-invalid={!valid}
            required
          />
        </label>
        {editable && (
          <Button type="submit" disabled={!valid || draft === null || save.isPending}>
            Save
          </Button>
        )}
      </form>
      <div id="retention-range">
        <Text variant="secondary">
          {`Between ${r.minDays} and ${r.maxDays} days. `}
          {r.configured ? "" : `This workspace is on the default of ${r.defaultDays} days.`}
        </Text>
      </div>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
    </section>
  );
}

/** A hold stops retention deleting what an investigation still needs. */
function LegalHold() {
  const { can } = useSession();
  const [from, setFrom] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const onError = (e: unknown) => setError(message(e));
  const place = useMutation({
    ...auditLegalHoldMutation(),
    onSuccess: (r) => {
      setError(null);
      toast(`${r.held} events are now held`);
    },
    onError,
  });
  const release = useMutation({
    ...auditLegalHoldReleaseMutation(),
    onSuccess: (r) => {
      setError(null);
      toast(`${r.held} events were released from the hold`);
    },
    onError,
  });

  if (!can("audit:export")) return null;
  const body = { from: from ? new Date(from).toISOString() : "", reason };

  return (
    <section className="grid gap-3">
      <div className="grid gap-1.5">
        <Text as="h3" variant="heading">
          Hold against deletion
        </Text>
        <Text variant="secondary">Keeps everything from a date onwards, whatever retention says, until it is released.</Text>
      </div>
      <div className="flex flex-wrap items-end gap-2">
        <label className="grid gap-1">
          <Text as="span">From</Text>
          <Input type="date" value={from} onChange={(e) => setFrom(e.currentTarget.value)} />
        </label>
        <label className="grid gap-1">
          <Text as="span">Why</Text>
          <Input value={reason} onChange={(e) => setReason(e.currentTarget.value)} placeholder="Recorded with the hold" />
        </label>
        <Button onClick={() => place.mutate({ body })} disabled={!from || place.isPending}>
          Hold
        </Button>
        <Button variant="secondary" onClick={() => release.mutate({ body })} disabled={!from || release.isPending}>
          Release
        </Button>
      </div>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
    </section>
  );
}
/** How much of a tool call's input and output the workspace keeps. */
function PayloadPolicy() {
  const { can } = useSession();
  const qc = useQueryClient();
  const policy = useQuery({ ...auditGetPolicyOptions(), retry: false });
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    ...auditSetPolicyMutation(),
    onSuccess: async (_, vars) => {
      setError(null);
      toast(`Tool calls now record: ${modes.find((m) => m.id === vars.body.mode)?.label ?? vars.body.mode}`);
      await qc.invalidateQueries({ queryKey: auditGetPolicyQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });
  const editable = can("audit:policy:manage");
  const current = policy.data?.mode ?? "metadata";

  const modes: { id: "none" | "metadata" | "masked" | "full"; label: string; detail: string }[] = [
    { id: "none", label: "Nothing", detail: "Only that the call happened." },
    { id: "metadata", label: "Shapes", detail: "Which arguments were given and of what kind, never their values." },
    { id: "masked", label: "Masked values", detail: "The values, with cards, addresses and secrets redacted." },
    { id: "full", label: "Everything", detail: "The arguments and the response as they were." },
  ];

  return (
    <section className="grid gap-3">
      <div className="grid gap-1">
        <Text as="h3" variant="heading">
          What tool calls record
        </Text>
        <Text variant="secondary">How much of what a call sent and got back is kept with it; the call itself always is.</Text>
      </div>
      <div className="grid gap-2">
        {modes.map((m) => (
          <label key={m.id} className="flex items-baseline gap-3 rounded-lg px-5 py-3 ring ring-kumo-line">
            <input
              type="radio"
              name="payload-mode"
              value={m.id}
              checked={current === m.id}
              disabled={!editable || save.isPending}
              onChange={() => save.mutate({ body: { mode: m.id } })}
            />
            <span className="grid gap-0.5">
              <Text as="span" bold>
                {m.label}
              </Text>
              <Text as="span" variant="secondary">
                {m.detail}
              </Text>
            </span>
          </label>
        ))}
      </div>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
    </section>
  );
}

