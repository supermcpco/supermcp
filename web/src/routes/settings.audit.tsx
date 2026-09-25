import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  auditGetPolicyOptions,
  auditGetPolicyQueryKey,
  auditGetRetentionOptions,
  auditGetRetentionQueryKey,
  auditListOptions,
  auditSetPolicyMutation,
  auditSetRetentionMutation,
  auditVerifyOptions,
  auditExportersCreateMutation,
  auditExportersDeleteMutation,
  auditExportersListOptions,
  auditExportersListQueryKey,
  auditLegalHoldMutation,
  auditLegalHoldReleaseMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge, Loading, SignInFirst } from "../lib/ui";
import { message } from "../lib/errors";

export const Route = createFileRoute("/settings/audit")({
  component: AuditTrail,
});

const categories = ["", "auth", "admin", "tool", "authz", "secrets", "system"] as const;

function AuditTrail() {
  const { signedIn, can, loading } = useSession();
  const [category, setCategory] = useState("");
  const [actor, setActor] = useState("");
  const allowed = can("audit:read");

  const events = useQuery({
    ...auditListOptions({ query: { category: category || undefined, actorId: actor || undefined, limit: 100 } }),
    enabled: signedIn && allowed,
    retry: false,
    // The writer batches, so an event lands a moment after the action that
    // caused it. A screen that only loads once shows an empty trail to
    // someone who just did something, which reads as "nothing was
    // recorded".
    refetchInterval: 5_000,
    refetchOnWindowFocus: true,
  });

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;
  if (!allowed) {
    return <Text>You do not have permission to read the audit trail for this workspace.</Text>;
  }

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Audit trail
        </Text>
        <Text>
          Every sign-in, change and tool call, in the order it happened. Each entry carries the hash of the one before
          it, so a deleted or edited row can be detected.
        </Text>
      </div>

      <ChainStatus />

      <div className="flex flex-wrap items-end gap-3">
        <label className="grid gap-1.5">
          <Text as="span">Category</Text>
          <select
            className="rounded-md border border-kumo-line bg-kumo-base px-3 py-2"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
          >
            {categories.map((c) => (
              <option key={c} value={c}>
                {c === "" ? "Everything" : c}
              </option>
            ))}
          </select>
        </label>
        <label className="grid flex-1 gap-1.5">
          <Text as="span">Actor</Text>
          <Input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="User id" />
        </label>
        <a
          className="rounded-md px-4 py-2 ring ring-kumo-line hover:bg-kumo-tint"
          href={`/api/v1/audit/export${category ? `?category=${encodeURIComponent(category)}` : ""}`}
        >
          <Text as="span">Export</Text>
        </a>
      </div>

      <table className="w-full text-left">
        <thead>
          <tr className="border-b border-kumo-line">
            <th className="py-2 pr-4">
              <Text as="span" variant="secondary">
                When
              </Text>
            </th>
            <th className="py-2 pr-4">
              <Text as="span" variant="secondary">
                Action
              </Text>
            </th>
            <th className="py-2 pr-4">
              <Text as="span" variant="secondary">
                Who
              </Text>
            </th>
            <th className="py-2 pr-4">
              <Text as="span" variant="secondary">
                On what
              </Text>
            </th>
            <th className="py-2">
              <Text as="span" variant="secondary">
                Outcome
              </Text>
            </th>
          </tr>
        </thead>
        <tbody>
          {events.data?.events?.map((e) => (
            <tr key={e.id} className="border-b border-kumo-line align-top">
              <td className="py-2 pr-4 whitespace-nowrap">
                <Text as="span" variant="secondary">
                  {new Date(e.time).toLocaleString()}
                </Text>
              </td>
              <td className="py-2 pr-4">
                <span className="font-mono text-[0.9em]">{e.action}</span>
              </td>
              <td className="py-2 pr-4">
                <Text as="span">{e.actorDisplay || e.actorId || e.actorKind}</Text>
              </td>
              <td className="py-2 pr-4">
                <Text as="span" variant="secondary">
                  {e.targetDisplay || e.targetId || ""}
                </Text>
              </td>
              <td className="py-2">
                <Badge>{e.outcome}</Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {events.data?.events?.length === 0 && <Text variant="secondary">Nothing recorded yet.</Text>}

      <PayloadPolicy />
      <Retention />
      <Destinations />
      <LegalHold />
    </div>
  );
}

/** Says whether the chain still verifies, which is the whole point of it. */
function ChainStatus() {
  const verify = useQuery({ ...auditVerifyOptions(), retry: false, refetchInterval: 30_000 });
  if (verify.isPending) return null;
  const v = verify.data;
  if (!v) return null;
  return (
    <div className="rounded-lg px-5 py-4 ring ring-kumo-line" role="status">
      <div className="flex flex-wrap items-center gap-2">
        <Text as="span" bold>
          {v.valid ? "The chain is intact" : "The chain is broken"}
        </Text>
        <Badge>{v.checked === 1 ? "1 event checked" : `${v.checked} events checked`}</Badge>
      </div>
      <Text variant="secondary">
        {v.valid
          ? `${v.scrubbed ? `${v.scrubbed} of them had their content removed under a retention rule. ` : ""}Sequence ${v.firstSeq} to ${v.lastSeq} verifies against its hashes${v.anchors ? ` and ${v.anchors === 1 ? "1 checkpoint" : `${v.anchors} checkpoints`}` : ""}.`
          : `${v.explanation ?? "A record does not follow the one before it."} First break at sequence ${v.brokenAt}.`}
      </Text>
    </div>
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
    onSuccess: () => qc.invalidateQueries({ queryKey: auditGetPolicyQueryKey() }),
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
        <Text as="h2" variant="heading3">
          What a tool call records
        </Text>
        <Text variant="secondary">
          The fact of a call is always recorded. This decides how much of what was sent and returned is kept with it.
        </Text>
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

/** How long the workspace's events keep their content. */
function Retention() {
  const { can } = useSession();
  const qc = useQueryClient();
  const retention = useQuery({ ...auditGetRetentionOptions(), retry: false });
  // null while the field shows the stored value; a string once edited.
  const [draft, setDraft] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const save = useMutation({
    ...auditSetRetentionMutation(),
    onSuccess: async (r) => {
      setDraft(null);
      setError(null);
      setNote(`Events now keep their content for ${r.days} days.`);
      await qc.invalidateQueries({ queryKey: auditGetRetentionQueryKey() });
    },
    onError: (e) => {
      setNote(null);
      setError(message(e));
    },
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
        <Text as="h2" variant="heading3">
          How long it is kept
        </Text>
        <Text>
          Past this many days an event loses its content, but stays in the chain so it can still be verified. The
          event itself is deleted later, once no workspace on this instance keeps it any longer, and never while it
          is under a hold.
        </Text>
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
      {note && (
        <div role="status">
          <Text variant="secondary">{note}</Text>
        </div>
      )}
    </section>
  );
}

/** Where a copy of the trail is delivered, so a SIEM can hold it too. */
function Destinations() {
  const { can } = useSession();
  const canSee = can("audit:export");
  const canManage = can("org:settings:manage");
  const qc = useQueryClient();
  const list = useQuery({ ...auditExportersListOptions(), enabled: canSee, retry: false });
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: auditExportersListQueryKey() });
  const onError = (e: unknown) => setError(message(e));
  const add = useMutation({
    ...auditExportersCreateMutation(),
    onSuccess: async () => {
      setUrl("");
      setSecret("");
      setError(null);
      await refresh();
    },
    onError,
  });
  const remove = useMutation({ ...auditExportersDeleteMutation(), onSuccess: refresh, onError });

  if (!canSee) return null;
  const rows = list.data?.exporters ?? [];

  return (
    <section className="grid gap-3">
      <div className="grid gap-1.5">
        <Text as="h2" variant="heading3">
          Where it is shipped
        </Text>
        <Text>
          Each batch is POSTed and signed with HMAC-SHA256 in X-Supermcp-Signature, so a receiver can tell a delivery
          from anything else that reaches the same address. Delivery resumes where it stopped.
        </Text>
      </div>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
      <ul className="grid gap-2">
        {rows.map((e) => (
          <li key={e.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="grid gap-1">
              <div className="flex flex-wrap items-center gap-2">
                <Text as="span" bold>
                  {e.url || "(unreadable configuration)"}
                </Text>
                {!e.enabled && <Badge>off</Badge>}
                {e.consecutiveFailures > 0 && <Badge>{e.consecutiveFailures} failures</Badge>}
              </div>
              <Text as="span" variant="secondary">
                delivered up to #{e.cursorSeq}
                {e.lastOkAt ? ` · last succeeded ${new Date(e.lastOkAt).toLocaleString()}` : " · nothing delivered yet"}
                {e.lastError ? ` · ${e.lastError}` : ""}
              </Text>
            </div>
            {canManage && (
              <Button variant="secondary" onClick={() => remove.mutate({ path: { id: e.id } })} disabled={remove.isPending}>
                Stop
              </Button>
            )}
          </li>
        ))}
      </ul>
      {rows.length === 0 && <Text variant="secondary">The trail is not being shipped anywhere.</Text>}
      {canManage && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate({ body: { url, secret, enabled: true } });
          }}
        >
          <label className="grid gap-1">
            <Text as="span">Destination</Text>
            <Input value={url} onChange={(e) => setUrl(e.currentTarget.value)} placeholder="https://siem.example/ingest" required />
          </label>
          <label className="grid gap-1">
            <Text as="span">Signing secret (never shown again)</Text>
            <Input value={secret} onChange={(e) => setSecret(e.currentTarget.value)} minLength={16} required type="password" />
          </label>
          <Button type="submit" disabled={add.isPending}>
            Ship the trail here
          </Button>
        </form>
      )}
    </section>
  );
}

/** A hold stops retention deleting what an investigation still needs. */
function LegalHold() {
  const { can } = useSession();
  const [from, setFrom] = useState("");
  const [reason, setReason] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const onError = (e: unknown) => setNote(message(e));
  const place = useMutation({
    ...auditLegalHoldMutation(),
    onSuccess: (r) => setNote(`${r.held} events are now held.`),
    onError,
  });
  const release = useMutation({
    ...auditLegalHoldReleaseMutation(),
    onSuccess: (r) => setNote(`${r.held} events were released.`),
    onError,
  });

  if (!can("audit:export")) return null;
  const body = { from: from ? new Date(from).toISOString() : "", reason };

  return (
    <section className="grid gap-3">
      <div className="grid gap-1.5">
        <Text as="h2" variant="heading3">
          Hold against deletion
        </Text>
        <Text>
          Retention removes the content of old events and eventually the events themselves. A hold stops that for
          everything from the date you give onwards, and it stays until somebody releases it.
        </Text>
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
      {note && <Text variant="secondary">{note}</Text>}
    </section>
  );
}
