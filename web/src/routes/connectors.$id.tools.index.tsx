import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import type { ToolDto, ToolReferencesDto } from "../api";
import {
  connectorsGetOptions,
  connectorsToolsOptions,
  toolsDeleteMutation,
  toolsEnableMutation,
  toolsReferencesOptions,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge, Loading, SignInFirst } from "../lib/ui";
import { message } from "../lib/errors";
import { invalidateTool, isReferencesConflict } from "../lib/tool-api";

export const Route = createFileRoute("/connectors/$id/tools/")({
  component: Tools,
});

/** How each origin is named on the screen. */
const sourceLabel: Record<ToolDto["source"], string> = {
  catalog: "from the catalog",
  import: "imported",
  custom: "custom",
};

function Tools() {
  const { id } = Route.useParams();
  const { signedIn, can, loading } = useSession();
  const qc = useQueryClient();
  const connector = useQuery({ ...connectorsGetOptions({ path: { id } }), enabled: signedIn, retry: false });
  const tools = useQuery({ ...connectorsToolsOptions({ path: { id } }), enabled: signedIn, retry: false });
  const canEdit = can("tools:update");

  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const enable = useMutation({
    ...toolsEnableMutation(),
    onSuccess: async (_data, vars) => {
      setError(null);
      await invalidateTool(qc, id, vars.path.id);
    },
    onError: (e) => setError(message(e)),
  });

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;

  const list = tools.data ?? [];

  return (
    <div className="grid gap-6">
      <Link to="/connectors" className="flex items-center gap-1 text-kumo-subtle">
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">Connectors</Text>
      </Link>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="grid gap-1.5">
          <Text as="h1" variant="heading2">
            Tools{connector.data ? ` of ${connector.data.name}` : ""}
          </Text>
          <Text>
            What a model can call through this connector. A tool that is switched off stays here but is not offered to
            clients. Only tools made here can be deleted; one from the catalog or an import can be switched off instead.
          </Text>
        </div>
        {canEdit && (
          <Link to="/connectors/$id/tools/new" params={{ id }}>
            <Button variant="primary">New tool</Button>
          </Link>
        )}
      </div>

      {error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
        </div>
      )}
      {tools.error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{message(tools.error)}</Text>
        </div>
      )}

      {tools.isPending ? (
        <Loading />
      ) : list.length === 0 ? (
        <Text variant="secondary">This connector has no tools yet.</Text>
      ) : (
        <ul className="grid gap-3">
          {list.map((t) => (
            <li key={t.id} className="grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="grid min-w-0 gap-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[0.95em] break-all">{t.name}</span>
                    <Badge>{sourceLabel[t.source]}</Badge>
                    {t.edited && <Badge>edited</Badge>}
                    {t.annotations.destructiveHint && <Badge>destructive</Badge>}
                    {t.annotations.readOnlyHint && <Badge>reads only</Badge>}
                    {!t.enabled && <Badge>off</Badge>}
                  </div>
                  {t.description && (
                    <Text as="span" variant="secondary">
                      {t.description}
                    </Text>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={t.enabled}
                      disabled={!canEdit || enable.isPending}
                      onChange={(e) => enable.mutate({ path: { id: t.id }, body: { enabled: e.target.checked } })}
                    />
                    <Text as="span">
                      Offered<span className="sr-only"> {t.name}</span>
                    </Text>
                  </label>
                  <Link
                    to="/connectors/$id/tools/$toolId"
                    params={{ id, toolId: t.id }}
                    className="rounded-md px-3 py-1.5 ring ring-kumo-line hover:bg-kumo-tint"
                  >
                    <Text as="span">
                      {canEdit ? "Edit" : "View"}
                      <span className="sr-only"> {t.name}</span>
                    </Text>
                  </Link>
                  <Link
                    to="/connectors/$id/tools/$toolId/history"
                    params={{ id, toolId: t.id }}
                    className="rounded-md px-3 py-1.5 ring ring-kumo-line hover:bg-kumo-tint"
                  >
                    <Text as="span">
                      History<span className="sr-only"> of {t.name}</span>
                    </Text>
                  </Link>
                  {canEdit && t.source === "custom" && confirming !== t.id && (
                    <Button onClick={() => setConfirming(t.id)}>
                      Delete<span className="sr-only"> {t.name}</span>
                    </Button>
                  )}
                </div>
              </div>
              {canEdit && t.source === "custom" && confirming === t.id && (
                <ConfirmDelete connectorId={id} tool={t} onDone={() => setConfirming(null)} />
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Asks before a tool goes, and says what goes with it. Access rules and
 * data-loss rules scoped to the tool are removed with it; approval policies
 * that match it by name are left alone and simply stop matching, which is
 * the part somebody would not expect.
 */
function ConfirmDelete({ connectorId, tool, onDone }: { connectorId: string; tool: ToolDto; onDone: () => void }) {
  const qc = useQueryClient();
  const refs = useQuery({ ...toolsReferencesOptions({ path: { id: tool.id } }), retry: false });
  const [error, setError] = useState<string | null>(null);
  // Every approval policy that names or is scoped to the tool has to be
  // acknowledged; having read the list below is that acknowledgement.
  const mustAcknowledge = (refs.data?.approvalPolicies.length ?? 0) > 0;

  const remove = useMutation({
    ...toolsDeleteMutation(),
    onSuccess: async () => {
      await invalidateTool(qc, connectorId);
      onDone();
    },
    onError: async (e) => {
      setError(message(e));
      // Somebody added a policy since the list below was read. Read it
      // again so the next press acknowledges what is actually there.
      if (isReferencesConflict(e)) await refs.refetch();
    },
  });

  return (
    <section
      aria-labelledby={`delete-${tool.id}`}
      className="grid gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line"
    >
      <Text as="h2" bold id={`delete-${tool.id}`}>
        Delete {tool.name}?
      </Text>
      {refs.isPending ? <Loading /> : refs.data ? <References refs={refs.data} /> : null}
      {refs.error && (
        <div role="alert">
          <Text>{message(refs.error)}</Text>
        </div>
      )}
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
      <div className="flex flex-wrap gap-3">
        <Button
          variant="primary"
          disabled={remove.isPending || refs.isPending}
          onClick={() =>
            remove.mutate({
              path: { id: tool.id },
              query: mustAcknowledge ? { acknowledgeReferences: true } : undefined,
            })
          }
        >
          Delete {tool.name} for good
        </Button>
        <Button onClick={onDone}>Keep it</Button>
      </div>
    </section>
  );
}

function References({ refs }: { refs: ToolReferencesDto }) {
  const byName = refs.approvalPolicies.filter((p) => p.match === "name");
  const scoped = refs.approvalPolicies.filter((p) => p.match === "scope");
  const nothing = refs.approvalPolicies.length === 0 && refs.dlpPolicies === 0 && refs.accessRules === 0;
  if (nothing) return <Text>Nothing else refers to this tool.</Text>;
  return (
    <div className="grid gap-2">
      {byName.length > 0 && (
        <div className="grid gap-1">
          <Text>These approval policies match it by name and will stop matching once it is gone:</Text>
          <ul className="grid list-disc gap-1 pl-5">
            {byName.map((p) => (
              <li key={p.id}>
                <Text as="span">
                  {p.name}
                  {!p.enabled && " (off)"}
                </Text>
              </li>
            ))}
          </ul>
        </div>
      )}
      {scoped.length > 0 && (
        <Text>
          {scoped.length === 1 ? "One approval policy is" : `${scoped.length} approval policies are`} scoped to it:{" "}
          {scoped.map((p) => p.name).join(", ")}.
        </Text>
      )}
      {refs.dlpPolicies > 0 && (
        <Text>
          {refs.dlpPolicies === 1 ? "One data-loss rule" : `${refs.dlpPolicies} data-loss rules`} scoped to it will be
          removed with it.
        </Text>
      )}
      {refs.accessRules > 0 && (
        <Text>
          {refs.accessRules === 1 ? "One role rule" : `${refs.accessRules} role rules`} naming it will be removed with
          it.
        </Text>
      )}
    </div>
  );
}
