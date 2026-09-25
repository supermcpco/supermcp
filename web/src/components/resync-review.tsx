import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import type { ResyncApplyOutputBody, ResyncToolDto } from "../api";
import {
  connectorsResyncMutation,
  connectorsResyncPreviewOptions,
  connectorsResyncPreviewQueryKey,
} from "../api/@tanstack/react-query.gen";
import { SideBySideDiff } from "./diff";
import { Loading } from "../lib/ui";
import { message, status } from "../lib/errors";
import { fieldLabel, resyncSummary, skipReason } from "../lib/resync";
import { invalidateTool } from "../lib/tool-api";

/**
 * What re-syncing a connector with the adapter this server carries would
 * change, and the button that does it. The server decides every part of
 * the plan, including which tools a person owns and so are left alone;
 * this only shows it.
 */
export function ResyncReview({
  connectorId,
  onApplied,
  onClose,
}: {
  connectorId: string;
  onApplied: (applied: ResyncApplyOutputBody) => void;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const preview = useQuery({ ...connectorsResyncPreviewOptions({ path: { id: connectorId } }), retry: false });
  const [error, setError] = useState<string | null>(null);

  const apply = useMutation({
    ...connectorsResyncMutation(),
    onSuccess: async (data) => {
      setError(null);
      const touched = [...data.applied.update, ...data.applied.remove].flatMap((t) => (t.toolId ? [t.toolId] : []));
      await Promise.all([
        invalidateTool(qc, connectorId),
        ...touched.map((toolId) => invalidateTool(qc, connectorId, toolId)),
        qc.invalidateQueries({ queryKey: connectorsResyncPreviewQueryKey({ path: { id: connectorId } }) }),
      ]);
      onApplied(data);
    },
    onError: async (e) => {
      setError(message(e));
      // The connector changed since the plan below was read: read it again
      // so the next press applies what is shown.
      if (status(e) === 409) await preview.refetch();
    },
  });

  const plan = preview.data;
  return (
    <section aria-labelledby="resync-heading" className="grid gap-4 rounded-lg px-5 py-4 ring ring-kumo-line">
      <Text as="h2" variant="heading3" id="resync-heading">
        Re-sync with the catalog
      </Text>
      <Text>
        Re-syncing brings this connector&rsquo;s settings and its catalog tools up to the adapter this server carries.
        Tools someone edited by hand and tools made here are left as they are. Credentials are not touched.
      </Text>
      {preview.isPending && <Loading />}
      {preview.error && (
        <div role="alert">
          <Text>{message(preview.error)}</Text>
        </div>
      )}
      {plan && (
        <>
          <Text bold>This re-sync: {resyncSummary(plan)}.</Text>
          <ToolGroup title="Tools to add" tools={plan.add} />
          <ToolGroup title="Tools to update" tools={plan.update} />
          <ToolGroup title="Tools to remove" tools={plan.remove} />
          {plan.skipped.length > 0 && (
            <div className="grid gap-1">
              <Text as="h3" bold>
                Left alone ({plan.skipped.length})
              </Text>
              <ul className="grid list-disc gap-1 pl-5">
                {plan.skipped.map((s) => (
                  <li key={s.name}>
                    <Text as="span">
                      <span className="font-mono">{s.name}</span>: {skipReason(s)}
                    </Text>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {plan.fields.map((f) => (
            <div key={f.field} className="grid gap-1">
              <Text as="h3" bold>
                {fieldLabel[f.field]}
              </Text>
              <SideBySideDiff label={fieldLabel[f.field]} before={f.before} after={f.after} />
            </div>
          ))}
          {plan.missingCredentials.length > 0 && (
            <Text>
              The adapter now needs {plan.missingCredentials.length === 1 ? "a credential" : "credentials"} this
              connector does not have: {plan.missingCredentials.join(", ")}. Set{" "}
              {plan.missingCredentials.length === 1 ? "it" : "them"} after re-syncing, or its tools will fail.
            </Text>
          )}
        </>
      )}
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
      <div className="flex flex-wrap gap-3">
        <Button
          variant="primary"
          disabled={!plan || apply.isPending}
          onClick={() =>
            plan &&
            apply.mutate({
              path: { id: connectorId },
              body: { catalogHash: plan.bundledHash, expectedVersion: plan.version },
            })
          }
        >
          Apply re-sync
        </Button>
        <Button onClick={onClose}>Not now</Button>
      </div>
    </section>
  );
}

function ToolGroup({ title, tools }: { title: string; tools: ResyncToolDto[] }) {
  if (tools.length === 0) return null;
  return (
    <div className="grid gap-1">
      <Text as="h3" bold>
        {title} ({tools.length})
      </Text>
      <ul className="grid list-disc gap-1 pl-5">
        {tools.map((t) => (
          <li key={t.name}>
            <Text as="span">
              <span className="font-mono">{t.name}</span>
              {t.changed && t.changed.length > 0 ? `: changes ${t.changed.join(", ")}` : ""}
            </Text>
          </li>
        ))}
      </ul>
    </div>
  );
}
