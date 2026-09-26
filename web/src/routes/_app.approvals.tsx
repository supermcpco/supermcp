import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  approvalPoliciesCreateMutation,
  approvalPoliciesDeleteMutation,
  approvalPoliciesListOptions,
  approvalPoliciesListQueryKey,
  approvalPoliciesRevisionsListOptions,
  approvalPoliciesRevisionsListQueryKey,
  approvalPoliciesRevisionsRestoreMutation,
  approvalsApproveMutation,
  approvalsGetOptions,
  approvalsListOptions,
  approvalsListQueryKey,
  approvalsRejectMutation,
  connectorsListOptions,
} from "../api/@tanstack/react-query.gen";
import type { ApprovalPolicy, ApprovalRequest } from "../api";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";
import { message } from "../lib/errors";
import { HistoryPanel } from "../components/revisions";

export const Route = createFileRoute("/_app/approvals")({
  component: Approvals,
});

function Approvals() {
  const { signedIn, can } = useSession();
  const canDecide = can("approvals:decide");
  const qc = useQueryClient();

  // Somebody who may only ask sees their own requests; an approver sees
  // the queue. Asking for the queue without the permission is a refusal,
  // not an empty list, so the two are separate requests.
  const waiting = useQuery({
    ...approvalsListOptions({ query: { state: "pending", mine: !canDecide } }),
    enabled: signedIn,
    retry: false,
    refetchInterval: 15_000,
  });
  const recent = useQuery({
    ...approvalsListOptions({ query: { state: "any", mine: !canDecide, limit: 25 } }),
    enabled: signedIn,
    retry: false,
  });

  const [reason, setReason] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: approvalsListQueryKey({ query: { state: "pending", mine: !canDecide } }) });
    await qc.invalidateQueries({ queryKey: approvalsListQueryKey({ query: { state: "any", mine: !canDecide, limit: 25 } }) });
  };
  const onError = (e: unknown) => setError(message(e));

  const approve = useMutation({ ...approvalsApproveMutation(), onSuccess: refresh, onError });
  const reject = useMutation({ ...approvalsRejectMutation(), onSuccess: refresh, onError });

  const pending = waiting.data?.approvals ?? [];
  const history = (recent.data?.approvals ?? []).filter((r) => r.state !== "pending");

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Approvals
        </Text>
        <Text>
          {canDecide
            ? "Tool calls a rule has held until somebody agrees to them. Approving replays the arguments that were approved, not whatever is asked for next."
            : "The calls you have made that are waiting on somebody else."}
        </Text>
      </div>

      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}

      <section className="grid gap-2">
        <Text as="h2" variant="heading3">
          Waiting
        </Text>
        {waiting.isPending && <Loading />}
        {!waiting.isPending && pending.length === 0 && <Text variant="secondary">Nothing is waiting.</Text>}
        {pending.map((r) => (
          <div key={r.id} className="grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
            <Summary request={r} />
            <Arguments id={r.id} />
            {canDecide && (
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  aria-label={`Why, for ${r.toolName}`}
                  placeholder="Why (recorded with the decision)"
                  value={reason[r.id] ?? ""}
                  onChange={(e) => setReason({ ...reason, [r.id]: e.currentTarget.value })}
                />
                <Button
                  onClick={() => approve.mutate({ path: { id: r.id }, body: { reason: reason[r.id] ?? "" } })}
                  disabled={approve.isPending || reject.isPending}
                >
                  Approve
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => reject.mutate({ path: { id: r.id }, body: { reason: reason[r.id] ?? "" } })}
                  disabled={approve.isPending || reject.isPending}
                >
                  Refuse
                </Button>
              </div>
            )}
          </div>
        ))}
      </section>

      <Rules />

      <section className="grid gap-2">
        <Text as="h2" variant="heading3">
          Decided
        </Text>
        {history.length === 0 && <Text variant="secondary">Nothing has been decided yet.</Text>}
        <ul className="grid gap-2">
          {history.map((r) => (
            <li key={r.id} className="rounded-lg px-5 py-4 ring ring-kumo-line">
              <Summary request={r} />
              {r.reason && r.state === "cancelled" && (
                <RequesterNote label="Why the requester withdrew it" text={r.reason} />
              )}
              {r.reason && r.state !== "cancelled" && (
                <Text variant="secondary">
                  {r.state === "rejected" ? "Refused" : "Approved"}: {r.reason}
                </Text>
              )}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

/** Which calls are held, and by what. Without a rule nothing is ever
 *  held, which is the first thing somebody looking at an empty queue
 *  needs to know. */
function Rules() {
  const { can } = useSession();
  const canManage = can("org:settings:manage");
  const canRestore = canManage && can("revisions:rollback");
  const qc = useQueryClient();
  const rules = useQuery({ ...approvalPoliciesListOptions(), retry: false });
  const [history, setHistory] = useState<string | null>(null);
  const connectors = useQuery({ ...connectorsListOptions(), retry: false });

  const [name, setName] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [trigger, setTrigger] = useState<"destructive" | "tool">("destructive");
  const [toolName, setToolName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: approvalPoliciesListQueryKey() });
  const onError = (e: unknown) => setError(message(e));
  const add = useMutation({
    ...approvalPoliciesCreateMutation(),
    onSuccess: async () => {
      setName("");
      setToolName("");
      setError(null);
      await refresh();
    },
    onError,
  });
  const remove = useMutation({ ...approvalPoliciesDeleteMutation(), onSuccess: refresh, onError });

  const list = rules.data?.policies ?? [];
  const names = new Map((connectors.data ?? []).map((c) => [c.id, c.name]));

  return (
    <section className="grid gap-3">
      <div className="grid gap-1.5">
        <Text as="h2" variant="heading3">
          What gets held
        </Text>
        <Text>
          A rule decides which calls wait for a person. Without one, nothing is ever held. A held call is answered
          straight away with the identifier of the request it raised, and runs when somebody approves it and the caller
          asks again with that identifier.
        </Text>
      </div>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
      <ul className="grid gap-2">
        {list.map((r) => (
          <li key={r.id} className="grid gap-4 rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="grid gap-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Text as="span" bold>
                    {r.name}
                  </Text>
                  <Badge>{r.trigger === "tool" ? r.toolName : r.trigger}</Badge>
                  {!r.enabled && <Badge>off</Badge>}
                </div>
                <Text as="span" variant="secondary">
                  {r.scope === "organization"
                    ? "every connector"
                    : `${r.scope}: ${names.get(r.scopeId ?? "") ?? r.scopeId}`}{" "}
                  · an answer lapses after {Math.round(r.ttlSeconds / 60)} minutes
                </Text>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="secondary"
                  onClick={() => setHistory((current) => (current === r.id ? null : r.id))}
                  aria-expanded={history === r.id}
                  aria-label={`${history === r.id ? "Hide the history of" : "History of"} ${r.name}`}
                >
                  {history === r.id ? "Hide history" : "History"}
                </Button>
                {canManage && (
                  <Button
                    variant="secondary"
                    onClick={() => remove.mutate({ path: { id: r.id } })}
                    disabled={remove.isPending}
                    aria-label={`Delete ${r.name}`}
                  >
                    Delete
                  </Button>
                )}
              </div>
            </div>
            {history === r.id && <RuleHistory rule={r} canRestore={canRestore} onRestored={refresh} />}
          </li>
        ))}
      </ul>
      {list.length === 0 && <Text variant="secondary">No rules, so no call is ever held.</Text>}
      {canManage && (
        <form
          className="grid max-w-3xl gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate({
              body: {
                name,
                scope: scopeId ? "connector" : "organization",
                scopeId: scopeId || undefined,
                trigger,
                toolName: trigger === "tool" ? toolName : undefined,
                effect: "require",
                ttlSeconds: 3600,
                enabled: true,
              },
            });
          }}
        >
          <label className="grid gap-1">
            <Text as="span">What it is for</Text>
            <Input value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={200} />
          </label>
          <div className="flex flex-wrap gap-3">
            <label className="grid gap-1">
              <Text as="span">Where it applies</Text>
              <select className={selectClass} value={scopeId} onChange={(e) => setScopeId(e.currentTarget.value)}>
                <option value="">Every connector</option>
                {(connectors.data ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1">
              <Text as="span">Which calls</Text>
              <select
                className={selectClass}
                value={trigger}
                onChange={(e) => setTrigger(e.currentTarget.value as typeof trigger)}
              >
                <option value="destructive">Anything that changes something</option>
                <option value="tool">One tool, by name</option>
              </select>
            </label>
            {trigger === "tool" && (
              <label className="grid gap-1">
                <Text as="span">Tool name</Text>
                <Input value={toolName} onChange={(e) => setToolName(e.currentTarget.value)} required />
              </label>
            )}
          </div>
          <div>
            <Button type="submit" disabled={add.isPending || name.trim() === "" || (trigger === "tool" && toolName.trim() === "")}>
              Add the rule
            </Button>
          </div>
        </form>
      )}
    </section>
  );
}

function Summary({ request }: { request: ApprovalRequest }) {
  const lapses = new Date(request.expiresAt);
  return (
    <div className="grid gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <Text as="span" bold>
          {request.toolName}
        </Text>
        <Badge>{request.state}</Badge>
        {request.policyName && <Badge>{request.policyName}</Badge>}
      </div>
      <Text as="span" variant="secondary">
        {request.requesterDisplay || request.requestedBy} · asked {new Date(request.createdAt).toLocaleString()}
        {request.state === "pending" ? ` · lapses ${lapses.toLocaleString()}` : ""}
      </Text>
      {request.acknowledgedAt && (
        <Text as="span" variant="secondary">
          {request.requesterDisplay || request.requestedBy} confirmed from their client that they asked for this call.
          Confirming is not an approval.
        </Text>
      )}
      {request.acknowledgement && <RequesterNote label="Note from the requester" text={request.acknowledgement} />}
    </div>
  );
}

/**
 * Text the person who asked for the call wrote. It is shown apart from the
 * product's own sentences, and labelled as theirs and unchecked, so that it
 * cannot pass for anything supermcp says.
 */
function RequesterNote({ label, text }: { label: string; text: string }) {
  return (
    <figure className="grid gap-1 rounded-md bg-kumo-tint px-3 py-2">
      <figcaption>
        <Text as="span" variant="secondary">
          {label} (their words, not verified)
        </Text>
      </figcaption>
      <blockquote className="break-words whitespace-pre-wrap">
        <Text as="span">{text}</Text>
      </blockquote>
    </figure>
  );
}

/** What the call would run with. An approver who cannot see this is
 *  agreeing to a name, not to a call — but unsealing the arguments is
 *  privileged and recorded, so it happens when somebody asks for it
 *  rather than on every list. */
function Arguments({ id }: { id: string }) {
  const [asked, setAsked] = useState(false);
  const detail = useQuery({ ...approvalsGetOptions({ path: { id } }), enabled: asked, retry: false });

  if (!asked) {
    return (
      <div>
        <Button variant="secondary" onClick={() => setAsked(true)}>
          Show what it would run
        </Button>
      </div>
    );
  }
  if (detail.isPending) return <Loading />;
  if (detail.error) return <Text variant="secondary">{message(detail.error)}</Text>;
  return <Args args={detail.data?.args} />;
}

function Args({ args }: { args?: Record<string, unknown> }) {
  const entries = Object.entries(args ?? {});
  if (entries.length === 0) return <Text variant="secondary">No arguments.</Text>;
  return (
    <dl className="grid gap-1 border-t border-kumo-line pt-2">
      {entries.map(([key, value]) => (
        <div key={key} className="flex flex-wrap items-baseline gap-2">
          <dt className="font-mono text-[0.9em]">{key}</dt>
          <dd>
            <Text as="span">{typeof value === "string" ? value : JSON.stringify(value)}</Text>
          </dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * Every change to one rule, and the version it can be put back to. Rules
 * are read on every call, so a restore governs the next one.
 */
function RuleHistory({
  rule,
  canRestore,
  onRestored,
}: {
  rule: ApprovalPolicy;
  canRestore: boolean;
  onRestored: () => Promise<void>;
}) {
  const qc = useQueryClient();
  const key = { path: { id: rule.id } };
  const revisions = useQuery({ ...approvalPoliciesRevisionsListOptions(key), retry: false });
  const restore = useMutation({
    ...approvalPoliciesRevisionsRestoreMutation(),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: approvalPoliciesRevisionsListQueryKey(key) });
      await onRestored();
    },
  });
  return (
    <HistoryPanel
      label={`History of ${rule.name}`}
      intro="Every change to this rule, newest first. Restoring an earlier version is recorded as a further change, and the next call is held, or not, by the restored rule."
      loading={revisions.isPending}
      revisions={revisions.data?.revisions ?? []}
      error={restore.error ? message(restore.error) : revisions.error ? message(revisions.error) : null}
      canRestore={canRestore}
      restoring={restore.isPending}
      onRestore={(revision) => restore.mutate({ path: { id: rule.id, revision } })}
      empty="Nothing has changed about this rule since the history began."
    />
  );
}
