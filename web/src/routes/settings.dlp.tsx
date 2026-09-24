import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  connectorsListOptions,
  dlpDetectorsOptions,
  dlpPoliciesListOptions,
  dlpPoliciesListQueryKey,
  dlpPolicyCreateMutation,
  dlpPolicyDeleteMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge, Loading, SignInFirst } from "../lib/ui";
import { message } from "../lib/errors";

export const Route = createFileRoute("/settings/dlp")({
  component: Dlp,
});

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

function Dlp() {
  const { signedIn, can, loading } = useSession();
  const canRead = can("connectors:read");
  const canManage = can("dlp:manage");
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
            <li key={p.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
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
              {canManage && (
                <Button variant="secondary" onClick={() => remove.mutate({ path: { id: p.id } })} disabled={remove.isPending}>
                  Delete
                </Button>
              )}
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
