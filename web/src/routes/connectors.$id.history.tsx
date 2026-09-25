import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import {
  connectorsGetOptions,
  connectorsGetQueryKey,
  connectorsListQueryKey,
  connectorsRevisionsListOptions,
  connectorsRevisionsListQueryKey,
  connectorsRevisionsRestoreMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Loading, SignInFirst } from "../lib/ui";
import { message } from "../lib/errors";
import { isVersionConflict } from "../lib/tool-api";
import { RevisionList } from "../components/revisions";

export const Route = createFileRoute("/connectors/$id/history")({
  component: History,
});

function History() {
  const { id } = Route.useParams();
  const { signedIn, can, loading } = useSession();
  const qc = useQueryClient();
  const revisions = useQuery({ ...connectorsRevisionsListOptions({ path: { id } }), enabled: signedIn, retry: false });
  // The connector itself is read for its version: a restore says which
  // one it was looking at, and is refused if somebody has moved it on.
  const connector = useQuery({ ...connectorsGetOptions({ path: { id } }), enabled: signedIn, retry: false });

  const restore = useMutation({
    ...connectorsRevisionsRestoreMutation(),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: connectorsRevisionsListQueryKey({ path: { id } }) });
      await qc.invalidateQueries({ queryKey: connectorsGetQueryKey({ path: { id } }) });
      await qc.invalidateQueries({ queryKey: connectorsListQueryKey() });
    },
  });
  const conflict = restore.error ? isVersionConflict(restore.error) : false;
  const reload = async () => {
    await Promise.all([connector.refetch(), revisions.refetch()]);
    restore.reset();
  };

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;

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
      {revisions.isPending ? (
        <Loading />
      ) : (
        <RevisionList
          revisions={revisions.data?.revisions ?? []}
          canRestore={can("revisions:rollback")}
          restoring={restore.isPending || !connector.data}
          onRestore={(revision) =>
            restore.mutate({ path: { id, revision }, body: { expectedVersion: connector.data?.version } })
          }
          empty="No changes recorded yet."
        />
      )}
    </div>
  );
}
