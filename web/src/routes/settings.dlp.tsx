import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  connectorsListOptions,
  dlpDetectorsOptions,
  dlpPoliciesListOptions,
  dlpPoliciesListQueryKey,
  dlpPoliciesRevisionsListOptions,
  dlpPoliciesRevisionsListQueryKey,
  dlpPoliciesRevisionsRestoreMutation,
  dlpPolicyCreateMutation,
  dlpPolicyDeleteMutation,
  dlpPolicyUpdateMutation,
} from "../api/@tanstack/react-query.gen";
import type { ScanPolicy } from "../api";
import { useSession } from "../lib/session";
import { Badge, Loading, SignInFirst } from "../lib/ui";
import { message } from "../lib/errors";
import { HistoryPanel } from "../components/revisions";

export const Route = createFileRoute("/settings/dlp")({
  component: Dlp,
});

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

function Dlp() {
  const { signedIn, can, loading } = useSession();
  const canRead = can("connectors:read");
  const canManage = can("dlp:manage");
  const canRestore = canManage && can("revisions:rollback");
  const qc = useQueryClient();

  const policies = useQuery({ ...dlpPoliciesListOptions(), enabled: signedIn && canRead, retry: false });
  const detectors = useQuery({ ...dlpDetectorsOptions(), enabled: signedIn && canRead, retry: false });
  const connectors = useQuery({ ...connectorsListOptions(), enabled: signedIn && canRead, retry: false });

  const [name, setName] = useState("");
  const [connectorId, setConnectorId] = useState("");
  const [scan, setScan] = useState<"arguments" | "result" | "both">("both");
  const [action, setAction] = useState<"allow" | "mask" | "refuse">("mask");
  const [chosen, setChosen] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [history, setHistory] = useState<string | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: dlpPoliciesListQueryKey() });
  const onError = (e: unknown) => setError(message(e));
  const create = useMutation({
    ...dlpPolicyCreateMutation(),
    onSuccess: async () => {
      setName("");
      setChosen([]);
      setError(null);
      await refresh();
    },
    onError,
  });
  const remove = useMutation({ ...dlpPolicyDeleteMutation(), onSuccess: refresh, onError });

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;

  const list = policies.data?.policies ?? [];
  const names = new Map((connectors.data ?? []).map((c) => [c.id, c.name]));
  // A scope holds one rule, so the form can say which rule is in the way
  // before anybody presses the button.
  const occupying = list.find((p) => (p.connectorId ?? "") === connectorId);

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Data-loss rules
        </Text>
        <Text>
          What a tool call may carry. A rule reads the arguments on the way out, the result on the way back, or both,
          and either records what it finds, masks it, or refuses the call. One rule applies per scope: the most specific
          wins.
        </Text>
      </div>

      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}

      <section className="grid gap-2">
        <Text as="h2" variant="heading3">
          Rules
        </Text>
        {policies.isPending && <Loading />}
        {!policies.isPending && list.length === 0 && (
          <Text variant="secondary">No rules yet, so nothing is inspected and nothing is masked.</Text>
        )}
        <ul className="grid gap-2">
          {list.map((p) => (
            <li key={p.id} className="grid gap-4 rounded-lg px-5 py-4 ring ring-kumo-line">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="grid gap-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Text as="span" bold>
                      {p.name}
                    </Text>
                    <Badge>{p.action}</Badge>
                    <Badge>{p.scan}</Badge>
                    {!p.enabled && <Badge>off</Badge>}
                  </div>
                  <Text as="span" variant="secondary">
                    {p.connectorId ? names.get(p.connectorId) ?? p.connectorId : "every connector"} ·{" "}
                    {p.detectors && p.detectors.length > 0 ? p.detectors.join(", ") : "every detector"}
                  </Text>
                </div>
                <div className="flex flex-wrap gap-2">
                  {canManage && editing !== p.id && (
                    <Button variant="secondary" onClick={() => setEditing(p.id)} aria-label={`Change ${p.name}`}>
                      Change
                    </Button>
                  )}
                  <Button
                    variant="secondary"
                    onClick={() => setHistory((current) => (current === p.id ? null : p.id))}
                    aria-expanded={history === p.id}
                    aria-label={`${history === p.id ? "Hide the history of" : "History of"} ${p.name}`}
                  >
                    {history === p.id ? "Hide history" : "History"}
                  </Button>
                  {canManage && (
                    <Button
                      variant="secondary"
                      onClick={() => remove.mutate({ path: { id: p.id } })}
                      disabled={remove.isPending}
                      aria-label={`Delete ${p.name}`}
                    >
                      Delete
                    </Button>
                  )}
                </div>
              </div>
              {canManage && editing === p.id && (
                <RuleEditor
                  policy={p}
                  onDone={async () => {
                    setEditing(null);
                    await refresh();
                    await qc.invalidateQueries({ queryKey: dlpPoliciesRevisionsListQueryKey({ path: { id: p.id } }) });
                  }}
                  onCancel={() => setEditing(null)}
                />
              )}
              {history === p.id && <RuleHistory policy={p} canRestore={canRestore} onRestored={refresh} />}
            </li>
          ))}
        </ul>
      </section>

      {canManage && (
        <section className="grid gap-3">
          <Text as="h2" variant="heading3">
            Add a rule
          </Text>
          <form
            className="grid gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate({
                body: { name, connectorId: connectorId || undefined, scan, action, detectors: chosen, enabled: true },
              });
            }}
          >
            <label className="grid gap-1">
              <Text as="span">What it is for</Text>
              <Input value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={120} />
            </label>
            <label className="grid gap-1">
              <Text as="span">Where it applies</Text>
              <select className={selectClass} value={connectorId} onChange={(e) => setConnectorId(e.currentTarget.value)}>
                <option value="">Every connector</option>
                {(connectors.data ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </label>
            <div className="flex flex-wrap gap-3">
              <label className="grid gap-1">
                <Text as="span">What it reads</Text>
                <select className={selectClass} value={scan} onChange={(e) => setScan(e.currentTarget.value as typeof scan)}>
                  <option value="both">Arguments and result</option>
                  <option value="arguments">Arguments only</option>
                  <option value="result">Result only</option>
                </select>
              </label>
              <label className="grid gap-1">
                <Text as="span">What it does</Text>
                <select className={selectClass} value={action} onChange={(e) => setAction(e.currentTarget.value as typeof action)}>
                  <option value="mask">Mask what it finds</option>
                  <option value="refuse">Refuse the call</option>
                  <option value="allow">Record only</option>
                </select>
              </label>
            </div>
            <fieldset className="grid gap-1">
              <legend>
                <Text as="span">Detectors (none selected means all of them)</Text>
              </legend>
              <div className="grid gap-1">
                {(detectors.data?.detectors ?? []).map((d) => (
                  <label key={d.name} className="flex items-baseline gap-2">
                    <input
                      type="checkbox"
                      checked={chosen.includes(d.name)}
                      onChange={(e) =>
                        setChosen(e.currentTarget.checked ? [...chosen, d.name] : chosen.filter((n) => n !== d.name))
                      }
                    />
                    <span>
                      <Text as="span">{d.summary}</Text>{" "}
                      <Text as="span" variant="secondary">
                        Does not match: {d.excludes}
                      </Text>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="grid gap-2">
              {occupying && (
                <Text variant="secondary">
                  {connectorId ? names.get(connectorId) ?? connectorId : "Every connector"} already has the rule
                  “{occupying.name}”. A scope holds one rule: delete that one, or choose a connector that has none.
                </Text>
              )}
              <div>
                <Button type="submit" disabled={create.isPending || name.trim() === "" || occupying !== undefined}>
                  Add the rule
                </Button>
              </div>
            </div>
          </form>
        </section>
      )}
    </div>
  );
}

/**
 * Changes one rule in place. The scope and the detectors stay as they are;
 * what is offered here is what a rule is most often changed for: its name,
 * what it reads, what it does and whether it is on.
 */
function RuleEditor({ policy, onDone, onCancel }: { policy: ScanPolicy; onDone: () => Promise<void>; onCancel: () => void }) {
  const [name, setName] = useState(policy.name);
  const [scan, setScan] = useState(policy.scan);
  const [action, setAction] = useState(policy.action);
  const [enabled, setEnabled] = useState(policy.enabled);
  const save = useMutation({ ...dlpPolicyUpdateMutation(), onSuccess: onDone });

  return (
    <form
      className="grid gap-3 border-t border-kumo-line pt-4"
      aria-label={`Change ${policy.name}`}
      onSubmit={(e) => {
        e.preventDefault();
        // A PUT replaces the rule, so what this form does not show is sent
        // back as it was read.
        save.mutate({
          path: { id: policy.id },
          body: {
            name,
            connectorId: policy.connectorId || undefined,
            toolId: policy.toolId || undefined,
            scan,
            action,
            detectors: policy.detectors ?? [],
            enabled,
            maxBytes: policy.maxBytes || undefined,
          },
        });
      }}
    >
      {save.error && (
        <div role="alert">
          <Text>{message(save.error)}</Text>
        </div>
      )}
      <label className="grid gap-1">
        <Text as="span">Rule name</Text>
        <Input value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={120} />
      </label>
      <div className="flex flex-wrap gap-3">
        <label className="grid gap-1">
          <Text as="span">What the rule reads</Text>
          <select className={selectClass} value={scan} onChange={(e) => setScan(e.currentTarget.value as typeof scan)}>
            <option value="both">Arguments and result</option>
            <option value="arguments">Arguments only</option>
            <option value="result">Result only</option>
          </select>
        </label>
        <label className="grid gap-1">
          <Text as="span">What the rule does</Text>
          <select className={selectClass} value={action} onChange={(e) => setAction(e.currentTarget.value as typeof action)}>
            <option value="mask">Mask what it finds</option>
            <option value="refuse">Refuse the call</option>
            <option value="allow">Record only</option>
          </select>
        </label>
      </div>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
        <Text as="span">The rule is on</Text>
      </label>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="primary" disabled={save.isPending || name.trim() === ""}>
          Save the rule
        </Button>
        <Button onClick={onCancel}>Cancel</Button>
      </div>
    </form>
  );
}

/**
 * Every change to one rule, and the version it can be put back to. A
 * restore takes effect on the next tool call on every replica, as an edit
 * does.
 */
function RuleHistory({
  policy,
  canRestore,
  onRestored,
}: {
  policy: ScanPolicy;
  canRestore: boolean;
  onRestored: () => Promise<void>;
}) {
  const qc = useQueryClient();
  const key = { path: { id: policy.id } };
  const revisions = useQuery({ ...dlpPoliciesRevisionsListOptions(key), retry: false });
  const restore = useMutation({
    ...dlpPoliciesRevisionsRestoreMutation(),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: dlpPoliciesRevisionsListQueryKey(key) });
      await onRestored();
    },
  });
  return (
    <HistoryPanel
      label={`History of ${policy.name}`}
      intro="Every change to this rule, newest first. Restoring an earlier version is recorded as a further change, and the next tool call is screened by the restored rule."
      loading={revisions.isPending}
      revisions={revisions.data?.revisions ?? []}
      error={restore.error ? message(restore.error) : revisions.error ? message(revisions.error) : null}
      canRestore={canRestore}
      restoring={restore.isPending}
      onRestore={(revision) => restore.mutate({ path: { id: policy.id, revision } })}
      empty="Nothing has changed about this rule since the history began."
    />
  );
}
