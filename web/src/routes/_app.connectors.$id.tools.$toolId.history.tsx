import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import {
  toolsGetOptions,
  toolsRevisionsListOptions,
  toolsRevisionsRestoreMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Loading, NotFound } from "../lib/ui";
import { message, status } from "../lib/errors";
import { RevisionList } from "../components/revisions";
import { blockingPolicies, invalidateTool, isReferencesConflict, type BlockingPolicy } from "../lib/tool-api";

export const Route = createFileRoute("/_app/connectors/$id/tools/$toolId/history")({
  component: ToolHistory,
});

function ToolHistory() {
  const { id, toolId } = Route.useParams();
  const { signedIn, can } = useSession();
  const qc = useQueryClient();
  const tool = useQuery({ ...toolsGetOptions({ path: { id: toolId } }), enabled: signedIn, retry: false });
  const revisions = useQuery({
    ...toolsRevisionsListOptions({ path: { id: toolId } }),
    enabled: signedIn,
    retry: false,
  });

  // A restore that renames the tool back asks first when approval
  // policies match it by name, the same as an edit does.
  const [ack, setAck] = useState<{ revision: number; policies: BlockingPolicy[] } | null>(null);
  const restore = useMutation({
    ...toolsRevisionsRestoreMutation(),
    onSuccess: async () => {
      setAck(null);
      await invalidateTool(qc, id, toolId);
    },
    onError: (e, vars) => {
      if (isReferencesConflict(e)) setAck({ revision: vars.path.revision, policies: blockingPolicies(e) });
    },
  });

  if (status(tool.error) === 404 || status(revisions.error) === 404) {
    return (
      <NotFound
        heading="Tool not found"
        back={{ to: "/connectors/$id/tools", params: { id } }}
        backLabel="Back to the connector's tools"
      >
        This connector has no tool at this address; it may have been deleted.
      </NotFound>
    );
  }

  return (
    <div className="grid gap-6">
      <Link
        to="/connectors/$id/tools/$toolId"
        params={{ id, toolId }}
        className="flex items-center gap-1 text-kumo-subtle"
      >
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">{tool.data ? tool.data.name : "Tool"}</Text>
      </Link>

      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          History
        </Text>
        <Text>
          Every change to this tool, newest first: its name, its definition and whether it is offered. Restoring an
          older version records the restore as a further change, and is checked the same way an edit is.
        </Text>
      </div>

      {restore.error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{message(restore.error)}</Text>
        </div>
      )}
      {ack && (
        <section
          aria-labelledby="restore-ack-heading"
          className="grid gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line"
        >
          <Text as="h2" bold id="restore-ack-heading">
            Restoring version {ack.revision} changes which approval policies apply
          </Text>
          {ack.policies.length > 0 && (
            <ul className="grid list-disc gap-1 pl-5">
              {ack.policies.map((p) => (
                <li key={p.id}>
                  <Text as="span">{p.name}</Text>
                </li>
              ))}
            </ul>
          )}
          <Text>They match the tool by its current name and are not changed automatically.</Text>
          <div className="flex flex-wrap gap-3">
            <Button
              variant="primary"
              disabled={restore.isPending}
              onClick={() =>
                restore.mutate({ path: { id: toolId, revision: ack.revision }, query: { acknowledgeReferences: true } })
              }
            >
              Restore anyway
            </Button>
            <Button onClick={() => setAck(null)}>Keep the current version</Button>
          </div>
        </section>
      )}
      {revisions.error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{message(revisions.error)}</Text>
        </div>
      )}

      {revisions.isPending ? (
        <Loading />
      ) : (
        <RevisionList
          revisions={revisions.data?.revisions ?? []}
          canRestore={can("revisions:rollback")}
          restoring={restore.isPending}
          onRestore={(revision) => restore.mutate({ path: { id: toolId, revision } })}
          empty="No changes recorded yet."
        />
      )}
    </div>
  );
}
