import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, DeleteResource, Input, Text } from "@cloudflare/kumo";
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
import { toast } from "../components/shell/toast";
import { EmptyState, FormDialog, HeaderWithAction } from "../components/form-dialog";
import { About, HeadingWithAbout } from "../components/about";
import { LabelledInput } from "../components/labelled-input";

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

  const pending = waiting.data?.approvals ?? [];
  const toolOf = (id: string) => pending.find((r) => r.id === id)?.toolName ?? "the tool";
  const approve = useMutation({
    ...approvalsApproveMutation(),
    onSuccess: async (_, vars) => {
      toast(`Call to ${toolOf(vars.path.id)} approved`);
      setError(null);
      await refresh();
    },
    onError,
  });
  const reject = useMutation({
    ...approvalsRejectMutation(),
    onSuccess: async (_, vars) => {
      toast(`Call to ${toolOf(vars.path.id)} refused`);
      setError(null);
      await refresh();
    },
    onError,
  });

  const history = (recent.data?.approvals ?? []).filter((r) => r.state !== "pending");

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <HeadingWithAbout
          heading={
            <Text as="h1" variant="heading" size="lg">
              Approvals
            </Text>
          }
          about={
            <About label="About approvals">
              <p>A rule decides which tool calls wait for a person. Without one, nothing is ever held.</p>
              <p>
                A held call is answered straight away with the identifier of the request it raised. It runs when
                somebody approves it and the caller asks again with that identifier.
              </p>
              <p>Approving replays the arguments that were approved, not whatever is asked for next.</p>
            </About>
          }
        />
        <Text>
          {canDecide
            ? "Tool calls a rule has held until somebody agrees to them."
            : "The calls you have made that are waiting on somebody else."}
        </Text>
      </div>

      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}

      <section className="grid gap-2">
        <Text as="h2" variant="heading">
          Waiting
        </Text>
        {waiting.isPending && <Loading />}
        {waiting.isSuccess && pending.length === 0 && (
          <EmptyState title="Nothing is waiting" as="h3">
            {canDecide ? "A call a rule holds shows up here until somebody decides it." : "None of your calls is held."}
          </EmptyState>
        )}
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

      {/* Reading the rules takes the power to decide; somebody who may only
          ask would be told there are none. */}
      {canDecide && <Rules />}

      <section className="grid gap-2">
        <Text as="h2" variant="heading">
          Decided
        </Text>
        {recent.isPending && <Loading />}
        {recent.isSuccess && history.length === 0 && (
          <EmptyState title="Nothing decided yet" as="h3">
            Approved, refused and withdrawn calls are listed here.
          </EmptyState>
        )}
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
  const [adding, setAdding] = useState(false);
  // The rule a person asked to delete, held until they confirm it.
  const [deleting, setDeleting] = useState<ApprovalPolicy | null>(null);
  const [deleteError, setDeleteError] = useState<string | undefined>();

  const refresh = () => qc.invalidateQueries({ queryKey: approvalPoliciesListQueryKey() });
  const add = useMutation({
    ...approvalPoliciesCreateMutation(),
    onSuccess: async (_, vars) => {
      toast(`Rule ${vars.body.name} added`);
      setName("");
      setToolName("");
      setError(null);
      setAdding(false);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });
  const remove = useMutation({
    ...approvalPoliciesDeleteMutation(),
    onSuccess: async (_, vars) => {
      const gone = rules.data?.policies?.find((r) => r.id === vars.path.id)?.name;
      toast(gone ? `Rule ${gone} deleted` : "Rule deleted");
      setDeleting(null);
      await refresh();
    },
    onError: (e) => setDeleteError(message(e)),
  });

  const list = rules.data?.policies ?? [];
  const names = new Map((connectors.data ?? []).map((c) => [c.id, c.name]));
  const addRule = canManage ? (
    <Button variant="primary" onClick={() => setAdding(true)}>
      Add rule
    </Button>
  ) : null;

  return (
    <section className="grid gap-3" aria-labelledby="held-heading">
      <HeaderWithAction action={addRule}>
        <Text as="h2" variant="heading" id="held-heading">
          Rules
        </Text>
        <Text>A rule decides which calls wait for a person.</Text>
      </HeaderWithAction>
      {rules.isPending && <Loading />}
      {rules.isError && (
        <div role="alert">
          <Text>{message(rules.error)}</Text>
        </div>
      )}
      {rules.isSuccess && list.length === 0 && (
        <EmptyState title="No rules yet" as="h3" action={addRule}>
          Without a rule, no call is ever held.
        </EmptyState>
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
                    onClick={() => {
                      setDeleteError(undefined);
                      setDeleting(r);
                    }}
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
      {canManage && (
        <DeleteResource
          open={deleting !== null}
          onOpenChange={(next) => !next && !remove.isPending && setDeleting(null)}
          resourceType="Rule"
          resourceName={deleting?.name ?? ""}
          deleteButtonText="Delete rule"
          isDeleting={remove.isPending}
          errorMessage={deleteError}
          onDelete={() => {
            if (deleting) remove.mutate({ path: { id: deleting.id } });
          }}
        />
      )}
      {canManage && (
        <FormDialog
          open={adding}
          onOpenChange={(open) => {
            setAdding(open);
            setError(null);
          }}
          title="Add a rule"
          submitLabel="Add rule"
          pending={add.isPending}
          canSubmit={name.trim() !== "" && !(trigger === "tool" && toolName.trim() === "")}
          error={error}
          onSubmit={() =>
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
            })
          }
        >
          <LabelledInput labelClassName="grid gap-1" label="What it is for" value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={200} />
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
            <LabelledInput labelClassName="grid gap-1" label="Tool name" value={toolName} onChange={(e) => setToolName(e.currentTarget.value)} required />
          )}
        </FormDialog>
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
    onSuccess: async (_, vars) => {
      toast(`Rule ${rule.name} restored to version ${vars.path.revision}`);
      await qc.invalidateQueries({ queryKey: approvalPoliciesRevisionsListQueryKey(key) });
      await onRestored();
    },
  });
  return (
    <HistoryPanel
      label={`History of ${rule.name}`}
      intro="Every change to this rule, newest first; a restored version decides the next call."
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
