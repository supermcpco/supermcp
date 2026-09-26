import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import {
  catalogListOptions,
  connectorsListOptions,
  serversListOptions,
} from "../api/@tanstack/react-query.gen";

export const Route = createFileRoute("/_app/")({
  component: Overview,
});

function Overview() {
  const catalog = useQuery(catalogListOptions({}));
  const connectors = useQuery({ ...connectorsListOptions(), retry: false });
  const servers = useQuery({ ...serversListOptions(), retry: false });
  const hasConnectors = (connectors.data?.length ?? 0) > 0;

  const total = catalog.data?.count ?? 0;
  const keyless = catalog.data?.adapters.filter((a) => a.keyless).length ?? 0;

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Overview
        </Text>
        <Text>Turn the systems you already run into tools for Claude, ChatGPT and Copilot.</Text>
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Adapters in catalog" value={catalog.isPending ? "…" : String(total)} />
        <Stat label="Need no credentials" value={catalog.isPending ? "…" : String(keyless)} />
        <Stat
          label="Connectors installed"
          value={connectors.isPending ? "…" : String(connectors.data?.length ?? 0)}
        />
        <Stat label="MCP servers" value={servers.isPending ? "…" : String(servers.data?.length ?? 0)} />
      </div>
      <div className="grid gap-1.5">
        <Text as="h2" variant="heading3">
          {hasConnectors ? "What to do next" : "Get started"}
        </Text>
        <Text>
          {hasConnectors ? (
            <>
              Put your connectors on an{" "}
              <Link to="/servers" className="underline">
                MCP server
              </Link>
              , then give an AI client{" "}
              <Link to="/api-keys" className="underline">
                a key
              </Link>{" "}
              to reach it.
            </>
          ) : (
            <>
              Browse the{" "}
              <Link to="/catalog" className="underline">
                catalog
              </Link>{" "}
              and install an adapter, or{" "}
              <Link to="/connectors/import" className="underline">
                import an OpenAPI document
              </Link>{" "}
              to create a connector from your own API.
            </>
          )}
        </Text>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg px-5 py-4 ring ring-kumo-line">
      <div className="grid gap-1">
        <Text as="span" variant="secondary">
          {label}
        </Text>
        <Text as="span" variant="heading2">
          {value}
        </Text>
      </div>
    </div>
  );
}
