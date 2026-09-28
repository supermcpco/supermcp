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
import { RouteTabs, TabPanel } from "../components/route-tabs";

/**
 * One connector: its name and state above, and three tabs below it. The
 * overview, the tools and the history each keep the address they had, so
 * a link to any of them still lands there; the pages a tab leads to (one
 * tool's editor, a new tool) are not tabs and sit outside this layout.
 */
export const Route = createFileRoute("/_app/connectors/$id/_detail")({
  component: ConnectorLayout,
});

type Tab = "overview" | "tools" | "history";

const tabLabels: Record<Tab, string> = { overview: "Overview", tools: "Tools", history: "History" };

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

      <RouteTabs
        label="Connector"
        value={tab}
        tabs={[
          { value: "overview", label: "Overview", link: <Link to="/connectors/$id" params={{ id }} /> },
          { value: "tools", label: "Tools", link: <Link to="/connectors/$id/tools" params={{ id }} /> },
          { value: "history", label: "History", link: <Link to="/connectors/$id/history" params={{ id }} /> },
        ]}
      />

      <TabPanel label={tabLabels[tab]}>
        <Outlet />
      </TabPanel>
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
            <Text as="h1" variant="heading" size="lg">
              {c.name}
            </Text>
            {c.readOnly && <Badge>read-only</Badge>}
            {!c.enabled && <Badge>disabled</Badge>}
            {/* The notice below says what this means; the badge needs no sentence of its own here. */}
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
