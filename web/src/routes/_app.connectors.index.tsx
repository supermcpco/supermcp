import { createFileRoute, Link, redirect } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { LinkButton, Text } from "@cloudflare/kumo";
import { connectorsListOptions } from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { consentOutcome, stillNeeded, connectorCredentialFields } from "../lib/connector";

/**
 * The server sends a browser back here from a vendor's consent screen,
 * naming the connector and how it went. The connector's own page is where
 * that is said, so a return that names one goes straight on to it.
 */
interface ConsentReturn {
  connector?: string;
  connected?: string;
  connect_error?: string;
}

export const Route = createFileRoute("/_app/connectors/")({
  validateSearch: (search: Record<string, unknown>): ConsentReturn => ({
    ...(typeof search.connector === "string" ? { connector: search.connector } : {}),
    ...(search.connected !== undefined ? { connected: String(search.connected) } : {}),
    ...(typeof search.connect_error === "string" ? { connect_error: search.connect_error } : {}),
  }),
  beforeLoad: ({ search }) => {
    if (!search.connector) return;
    throw redirect({
      to: "/connectors/$id",
      params: { id: search.connector },
      search: search.connect_error
        ? { connectError: search.connect_error }
        : search.connected
          ? { connected: true }
          : {},
      replace: true,
    });
  },
  component: Connectors,
});

function Connectors() {
  const { signedIn, can } = useSession();
  const search = Route.useSearch();
  const q = useQuery({ ...connectorsListOptions(), enabled: signedIn, retry: false });

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="grid gap-1.5">
          <Text as="h1" variant="heading2">
            Connectors
          </Text>
          <Text>The systems this workspace can reach. Install one from the catalog to get started.</Text>
        </div>
        <div className="flex flex-wrap gap-2">
          {can("connectors:create") && (
            <LinkButton href="/connectors/import" variant="primary">
              Import an API
            </LinkButton>
          )}
          <LinkButton href="/catalog" variant="primary">
            Browse catalog
          </LinkButton>
        </div>
      </div>

      {/* A consent that failed for a connector that no longer exists comes
          back without one to go on to. */}
      {search.connect_error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{consentOutcome(search.connect_error)}</Text>
        </div>
      )}

      {q.isPending && <Text>Loading…</Text>}
      {q.data?.length === 0 && (
        <div className="rounded-lg px-5 py-8 text-center ring ring-kumo-line">
          <div className="grid gap-1.5">
            <Text as="h2" variant="heading3">
              No connectors yet
            </Text>
            <Text variant="secondary">Install an adapter from the catalog, or point one at your own API.</Text>
          </div>
        </div>
      )}

      <ul className="grid gap-3">
        {q.data?.map((c) => (
          // The whole card opens the connector: its name is the link, and
          // the link's area is stretched over the card. The badges and the
          // summary are read after the name, not as part of it.
          <li key={c.id} className="relative rounded-lg px-5 py-4 ring ring-kumo-line hover:bg-kumo-tint">
            <div className="grid gap-1">
              <div className="flex flex-wrap items-center gap-2">
                <Link
                  to="/connectors/$id"
                  params={{ id: c.id }}
                  className="font-semibold after:absolute after:inset-0 after:rounded-lg"
                >
                  {c.name}
                </Link>
                {!c.enabled && <Badge>disabled</Badge>}
                {c.readOnly && <Badge>read-only</Badge>}
                {c.catalogOutdated && <Badge>catalog update available</Badge>}
                {stillNeeded(connectorCredentialFields(c), {}).length > 0 && <Badge>credentials missing</Badge>}
              </div>
              <Text as="span" variant="secondary">
                {String(c.transport?.type ?? "")} · {String(c.auth?.type ?? "none")} · {c.toolCount} tools
              </Text>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
