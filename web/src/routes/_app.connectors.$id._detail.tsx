import { useState } from "react";
import { createFileRoute, Link, Outlet, useMatchRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Switch, Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import {
  connectorsGetOptions,
  connectorsGetQueryKey,
  connectorsListQueryKey,
  connectorsUpdateMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge, Loading, NotFound } from "../lib/ui";
import { message, status } from "../lib/errors";
import { toast } from "../components/shell/toast";

/**
 * One connector: its name and state above, and three tabs below it. The
 * overview, the tools and the history each keep the address they had, so
 * a link to any of them still lands there; the pages a tab leads to (one
 * tool's editor, a new tool) are not tabs and sit outside this layout.
 */
export const Route = createFileRoute("/_app/connectors/$id/_detail")({
  component: ConnectorLayout,
});

const tabClass = "rounded-md px-3 py-1.5 aria-selected:bg-kumo-tint aria-selected:font-semibold";

type Tab = "overview" | "tools" | "history";

function ConnectorLayout() {
  const { id } = Route.useParams();
  const { signedIn } = useSession();
  const connector = useQuery({ ...connectorsGetOptions({ path: { id } }), enabled: signedIn, retry: false });
  const matchRoute = useMatchRoute();
  const tab: Tab = matchRoute({ to: "/connectors/$id/tools", params: { id } })
    ? "tools"
    : matchRoute({ to: "/connectors/$id/history", params: { id } })
      ? "history"
      : "overview";

  if (status(connector.error) === 404) {
    return (
      <NotFound heading="Connector not found" back={{ to: "/connectors" }} backLabel="Back to connectors">
        This workspace has no connector at this address; it may have been deleted.
      </NotFound>
    );
  }

  return (
    <div className="grid gap-6">
      <Link to="/connectors" className="flex items-center gap-1 text-kumo-subtle">
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">Connectors</Text>
      </Link>

      {connector.isPending ? (
        <Loading />
      ) : connector.error ? (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{message(connector.error)}</Text>
        </div>
      ) : (
        <Header id={id} />
      )}

      <div role="tablist" aria-label="Connector" className="flex gap-2 border-b border-kumo-line pb-2">
        <Link
          to="/connectors/$id"
          params={{ id }}
          role="tab"
          id="connector-tab-overview"
          aria-selected={tab === "overview"}
          aria-controls="connector-panel"
          className={tabClass}
          activeOptions={{ exact: true }}
        >
          Overview
        </Link>
        <Link
          to="/connectors/$id/tools"
          params={{ id }}
          role="tab"
          id="connector-tab-tools"
          aria-selected={tab === "tools"}
          aria-controls="connector-panel"
          className={tabClass}
        >
          Tools
        </Link>
        <Link
          to="/connectors/$id/history"
          params={{ id }}
          role="tab"
          id="connector-tab-history"
          aria-selected={tab === "history"}
          aria-controls="connector-panel"
          className={tabClass}
        >
          History
        </Link>
      </div>

      <div role="tabpanel" id="connector-panel" aria-labelledby={`connector-tab-${tab}`} className="grid gap-6">
        <Outlet />
      </div>
    </div>
  );
}

/**
 * The connector's name, where it came from, its state, and the switch
 * that takes it out of service without removing it.
 */
function Header({ id }: { id: string }) {
  const qc = useQueryClient();
  const { can } = useSession();
  const connector = useQuery({ ...connectorsGetOptions({ path: { id } }), retry: false });
  const [error, setError] = useState<string | null>(null);

  const update = useMutation({
    ...connectorsUpdateMutation(),
    onSuccess: async (updated) => {
      setError(null);
      qc.setQueryData(connectorsGetQueryKey({ path: { id } }), updated);
      await qc.invalidateQueries({ queryKey: connectorsListQueryKey() });
      toast(`${updated.name} ${updated.enabled ? "enabled" : "disabled"}`);
    },
    onError: async (e) => {
      setError(message(e));
      // Somebody changed the connector since it was read: read it again,
      // so the switch shows what is stored and the next press is based on it.
      if (status(e) === 409) await connector.refetch();
    },
  });

  const c = connector.data;
  if (!c) return null;
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="grid gap-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <Text as="h1" variant="heading2">
              {c.name}
            </Text>
            {c.readOnly && <Badge>read-only</Badge>}
            {!c.enabled && <Badge>disabled</Badge>}
            {c.catalogOutdated && <Badge>catalog update available</Badge>}
          </div>
          <Text variant="secondary">
            {c.catalogSlug ? (
              <>
                From the catalog:{" "}
                <Link to="/catalog/$slug" params={{ slug: c.catalogSlug }} className="underline">
                  {c.catalogSlug}
                </Link>
              </>
            ) : (
              "Imported"
            )}
          </Text>
        </div>
        <Switch
          label="Enabled"
          checked={c.enabled}
          disabled={!can("connectors:update") || update.isPending}
          onCheckedChange={(enabled) =>
            update.mutate({ path: { id }, body: { enabled, expectedVersion: c.version } })
          }
        />
      </div>
      {error && (
        <div role="alert" className="flex flex-wrap items-center gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
          <Button onClick={() => setError(null)}>Dismiss</Button>
        </div>
      )}
    </div>
  );
}
