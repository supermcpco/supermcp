import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
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
import type { CustomDetectorDto, DetectorInfo, ScanPolicy } from "../api";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";
import { message } from "../lib/errors";
import { HistoryPanel } from "../components/revisions";
import { DetectorsPanel } from "../components/dlp-detectors";
import { toast } from "../components/shell/toast";
import { EmptyState, FormDialog, HeaderWithAction } from "../components/form-dialog";
import { ConfirmDialog } from "../components/confirm-dialog";
import { Help, HeadingWithHelp } from "../components/help";
import { RouteTabs, TabPanel } from "../components/route-tabs";
import { LabelledInput } from "../components/labelled-input";

type Tab = "rules" | "detectors";

export const Route = createFileRoute("/_app/settings/dlp")({
  // Which tab is open lives in the URL, so a link or a reload lands on it.
  validateSearch: (search: Record<string, unknown>): { tab?: Tab } =>
    search.tab === "detectors" ? { tab: "detectors" } : {},
  component: Dlp,
});

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

function Dlp() {
  const { can } = useSession();
  const canManage = can("dlp:manage");
  const canRestore = canManage && can("revisions:rollback");
  const tab: Tab = Route.useSearch().tab ?? "rules";

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <HeadingWithHelp
          heading={
            <Text as="h2" variant="heading">
              Data-loss rules
            </Text>
          }
          help={
            <Help about="data-loss rules">
              <Text>
                A rule reads what a tool call carries: the arguments on the way out, the result on the way back, or
                both.
              </Text>
              <Text>
                What it finds it either records, masks, or refuses the whole call for. One rule applies per scope, and
                the most specific wins: a rule on one connector overrides the rule for every connector.
              </Text>
            </Help>
          }
        />
        <Text>What a tool call may carry, checked on every call.</Text>
      </div>

      <RouteTabs
        size="sm"
        value={tab}
        tabs={[
          { value: "rules", label: "Rules", link: <Link to="/settings/dlp" search={{}} /> },
          { value: "detectors", label: "Detectors", link: <Link to="/settings/dlp" search={{ tab: "detectors" }} /> },
        ]}
      />

      <TabPanel label={tab === "detectors" ? "Detectors" : "Rules"}>
        {tab === "detectors" ? (
          <DetectorsPanel canManage={canManage} canRestore={canRestore} />
        ) : (
          <RulesTab />
        )}
      </TabPanel>
    </div>
  );
}

/** The rules, and the form that adds one. */
function RulesTab() {
  const { signedIn, can } = useSession();
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
  // The rule being edited, kept while its dialog closes. Each opening
  // counts, so the dialog starts from the rule as it is now.
  const [edited, setEdited] = useState<ScanPolicy | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [editRound, setEditRound] = useState(0);
  const [history, setHistory] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  // The rule whose deletion is being asked about; kept while the dialog closes.
  const [deleting, setDeleting] = useState<ScanPolicy | null>(null);
  const [asking, setAsking] = useState(false);

  const refresh = () => qc.invalidateQueries({ queryKey: dlpPoliciesListQueryKey() });
  const create = useMutation({
    ...dlpPolicyCreateMutation(),
    onSuccess: async (_, vars) => {
      toast(`Rule ${vars.body.name} added`);
      setName("");
      setChosen([]);
      setError(null);
      setAdding(false);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });
  const remove = useMutation({
    ...dlpPolicyDeleteMutation(),
    onSuccess: async (_, vars) => {
      const gone = policies.data?.policies?.find((p) => p.id === vars.path.id)?.name;
      toast(gone ? `Rule ${gone} deleted` : "Rule deleted");
      setAsking(false);
      await refresh();
    },
  });

  const list = policies.data?.policies ?? [];
  const builtins = detectors.data?.detectors ?? [];
  const custom = detectors.data?.custom ?? [];
  const names = new Map((connectors.data ?? []).map((c) => [c.id, c.name]));
  // A scope holds one rule, so the form can say which rule is in the way
  // before anybody presses the button.
  const occupying = list.find((p) => (p.connectorId ?? "") === connectorId);
  const addRule = canManage ? (
    <Button variant="primary" onClick={() => setAdding(true)}>
      New rule
    </Button>
  ) : null;

  return (
    <>
      <section className="grid gap-2" aria-labelledby="dlp-rules-heading">
        <HeaderWithAction action={addRule}>
          <Text as="h3" variant="heading" id="dlp-rules-heading">
            Rules
          </Text>
        </HeaderWithAction>
        {policies.isPending && <Loading />}
        {!policies.isPending && list.length === 0 && (
          <EmptyState action={addRule}>No rules yet, so nothing is inspected and nothing is masked.</EmptyState>
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
                    {p.detectors && p.detectors.length > 0 ? p.detectors.join(", ") : "every built-in detector"}
                  </Text>
                </div>
                <div className="flex flex-wrap gap-2">
                  {canManage && (
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setEdited(p);
                        setEditRound((n) => n + 1);
                        setEditOpen(true);
                      }}
                      aria-label={`Edit ${p.name}`}
                    >
                      Edit
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
                      variant="secondary-destructive"
                      onClick={() => {
                        remove.reset();
                        setDeleting(p);
                        setAsking(true);
                      }}
                      aria-label={`Delete ${p.name}`}
                    >
                      Delete
                    </Button>
                  )}
                </div>
              </div>
              {history === p.id && <RuleHistory policy={p} canRestore={canRestore} onRestored={refresh} />}
            </li>
          ))}
        </ul>
      </section>

      {canManage && edited && (
        <RuleEditor
          key={editRound}
          open={editOpen}
          onOpenChange={setEditOpen}
          policy={edited}
          builtins={builtins}
          custom={custom}
          onSaved={async () => {
            setEditOpen(false);
            await refresh();
            await qc.invalidateQueries({ queryKey: dlpPoliciesRevisionsListQueryKey({ path: { id: edited.id } }) });
          }}
        />
      )}

      {canManage && (
        <ConfirmDialog
          open={asking}
          onOpenChange={setAsking}
          resourceType="Rule"
          resourceName={deleting?.name ?? ""}
          confirmLabel="Delete rule"
          pending={remove.isPending}
          error={remove.error ? message(remove.error) : null}
          onConfirm={() => deleting && remove.mutate({ path: { id: deleting.id } })}
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
          submitLabel="Add the rule"
          pending={create.isPending}
          canSubmit={name.trim() !== "" && occupying === undefined}
          error={error}
          size="xl"
          onSubmit={() =>
            create.mutate({
              body: { name, connectorId: connectorId || undefined, scan, action, detectors: chosen, enabled: true },
            })
          }
        >
          <LabelledInput labelClassName="grid gap-1" label="What it is for" value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={120} />
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
          <DetectorChoices builtins={builtins} custom={custom} chosen={chosen} onChange={setChosen} />
          {occupying && (
            <Text variant="secondary">
              {connectorId ? names.get(connectorId) ?? connectorId : "Every connector"} already has the rule
              “{occupying.name}”. A scope holds one rule: delete that one, or choose a connector that has none.
            </Text>
          )}
        </FormDialog>
      )}
    </>
  );
}

/**
 * Which detectors a rule runs: the built-ins, and the workspace's own
 * beside them. None chosen means every built-in; a workspace detector
 * runs only where a rule names it. A detector that is switched off is
 * still offered, and says so, because a rule may name it ahead of time.
 */
function DetectorChoices({
  builtins,
  custom,
  chosen,
  onChange,
}: {
  builtins: DetectorInfo[];
  custom: CustomDetectorDto[];
  chosen: string[];
  onChange: (next: string[]) => void;
}) {
  const toggle = (name: string, on: boolean) => onChange(on ? [...chosen, name] : chosen.filter((n) => n !== name));
  return (
    <fieldset className="grid gap-1">
      <legend>
        <Text as="span">Detectors (none selected means every built-in one)</Text>
      </legend>
      <div className="grid gap-1">
        {builtins.map((d) => (
          <label key={d.name} className="flex items-baseline gap-2">
            <input type="checkbox" checked={chosen.includes(d.name)} onChange={(e) => toggle(d.name, e.currentTarget.checked)} />
            <span>
              <Text as="span">{d.summary}</Text>{" "}
              <Text as="span" variant="secondary">
                Does not match: {d.excludes}
              </Text>
            </span>
          </label>
        ))}
        {custom.map((d) => (
          <label key={d.id} className="flex items-baseline gap-2">
            <input
              type="checkbox"
              checked={chosen.includes(d.detector)}
              onChange={(e) => toggle(d.detector, e.currentTarget.checked)}
            />
            <span>
              <Text as="span">
                {d.detector}
                {d.description ? `: ${d.description}` : ""}
              </Text>{" "}
              <Text as="span" variant="secondary">
                This workspace's own{d.enabled ? "" : ", switched off"}.
              </Text>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/**
 * Changes one rule, in a dialog opened from its row. The scope stays as
 * it is; what is offered here is what a rule is most often changed for:
 * its name, what it reads, what it does, which detectors it runs and
 * whether it is on.
 */
function RuleEditor({
  open,
  onOpenChange,
  policy,
  builtins,
  custom,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policy: ScanPolicy;
  builtins: DetectorInfo[];
  custom: CustomDetectorDto[];
  onSaved: () => Promise<void>;
}) {
  const [name, setName] = useState(policy.name);
  const [chosen, setChosen] = useState<string[]>(policy.detectors ?? []);
  const [scan, setScan] = useState(policy.scan);
  const [action, setAction] = useState(policy.action);
  const [enabled, setEnabled] = useState(policy.enabled);
  const save = useMutation({
    ...dlpPolicyUpdateMutation(),
    onSuccess: async (_, vars) => {
      toast(`Rule ${vars.body.name} saved`);
      await onSaved();
    },
  });

  return (
    <FormDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Edit ${policy.name}`}
      submitLabel="Save the rule"
      pending={save.isPending}
      canSubmit={name.trim() !== ""}
      error={save.error ? message(save.error) : null}
      size="xl"
      onSubmit={() =>
        // A PUT replaces the rule, so what this form does not show (the
        // scope and the scan limit) is sent back as it was read.
        save.mutate({
          path: { id: policy.id },
          body: {
            name,
            connectorId: policy.connectorId || undefined,
            toolId: policy.toolId || undefined,
            scan,
            action,
            detectors: chosen,
            enabled,
            maxBytes: policy.maxBytes || undefined,
          },
        })
      }
    >
      <LabelledInput labelClassName="grid gap-1" label="Rule name" value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={120} />
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
      <DetectorChoices builtins={builtins} custom={custom} chosen={chosen} onChange={setChosen} />
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
        <Text as="span">The rule is on</Text>
      </label>
    </FormDialog>
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
    onSuccess: async (_, vars) => {
      toast(`Rule ${policy.name} restored to version ${vars.path.revision}`);
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
