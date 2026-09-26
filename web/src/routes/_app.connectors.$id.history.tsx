import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import { connectorsGet, connectorsRevisionsList } from "../api";
import {
  connectorsListQueryKey,
  connectorsRevisionsListQueryKey,
  connectorsRevisionsRestoreMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Loading } from "../lib/ui";
import { message } from "../lib/errors";
import { isVersionConflict } from "../lib/tool-api";
import { RevisionList } from "../components/revisions";

export const Route = createFileRoute("/_app/connectors/$id/history")({
  component: History,
});

function History() {
  const { id } = Route.useParams();
  const { signedIn, can } = useSession();
  const qc = useQueryClient();
  // The history and the connector's version are one read, the version
  // first: a restore says which version it was looking at, and one read
  // after the list could name a change the list does not show yet.
  const history = useQuery({
    queryKey: ["connector-history", id],
    enabled: signedIn,
    retry: false,
    queryFn: async ({ signal }) => {
      const { data: connector } = await connectorsGet({ path: { id }, signal, throwOnError: true });
      const { data: list } = await connectorsRevisionsList({ path: { id }, signal, throwOnError: true });
      return { version: connector.version, revisions: list.revisions };
    },
  });

  const restore = useMutation({
    ...connectorsRevisionsRestoreMutation(),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["connector-history", id] });
      await qc.invalidateQueries({ queryKey: connectorsRevisionsListQueryKey({ path: { id } }) });
      await qc.invalidateQueries({ queryKey: connectorsListQueryKey() });
    },
  });
  const conflict = restore.error ? isVersionConflict(restore.error) : false;
  const reload = async () => {
    await history.refetch();
    restore.reset();
  };

  return (
    <div className="grid gap-6">
      <Link to="/connectors" className="flex items-center gap-1 text-kumo-subtle">
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">Connectors</Text>
      </Link>

      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          History
        </Text>
        <Text>
          Every change to this connector, newest first. Long values — the instructions, the schema a tool expects, how
          the connector is reached — are shown with the two versions side by side, so the line that moved is the one you
          see. Restoring an older version records the restore as a further change, so the history of a mistake survives
          being corrected.
        </Text>
      </div>

      {restore.error && (
        <div role="alert" className="grid gap-2 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{message(restore.error)}</Text>
          {conflict && (
            <div>
              <Button type="button" onClick={reload}>
                Reload the connector
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Until the history has arrived there is nothing to say about it,
          and "no changes recorded yet" would be saying something. */}
      {history.isPending ? (
        <Loading />
      ) : (
        <RevisionList
          revisions={history.data?.revisions ?? []}
          canRestore={can("revisions:rollback")}
          restoring={restore.isPending || !history.data}
          onRestore={(revision) =>
            restore.mutate({ path: { id, revision }, body: { expectedVersion: history.data?.version } })
          }
          empty="No changes recorded yet."
        />
      )}
    </div>
  );
}
