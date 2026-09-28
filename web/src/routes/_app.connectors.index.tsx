import { useCallback } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { LinkButton, Text } from "@cloudflare/kumo";
import { connectorsListOptions } from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";
import { message } from "../lib/errors";
import { EmptyState, HeaderWithAction } from "../components/form-dialog";
import {
  consentResult,
  consentSearch,
  stillNeeded,
  connectorCredentialFields,
  type ConsentSearch,
} from "../lib/connector";
import { ConsentReturn } from "../components/consent-return";

/**
 * The server sends a browser back to the connector's own page from a
 * vendor's consent screen, and here when the return names no connector
 * it could go on to (`oauth=expired`).
 */
export const Route = createFileRoute("/_app/connectors/")({
  validateSearch: (search: Record<string, unknown>): ConsentSearch => consentSearch(search),
  component: Connectors,
});

function Connectors() {
  const { signedIn, can } = useSession();
  const search = Route.useSearch();
  const navigate = useNavigate();
  const clear = useCallback(() => void navigate({ to: "/connectors", search: {}, replace: true }), [navigate]);
  const q = useQuery({ ...connectorsListOptions(), enabled: signedIn, retry: false });
  const list = q.data ?? [];

  const browse = (
    <LinkButton href="/catalog" variant="primary">
      Browse catalog
    </LinkButton>
  );

  return (
    <div className="grid gap-6">
      <HeaderWithAction
        action={
          <div className="flex flex-wrap gap-2">
            {can("connectors:create") && <LinkButton href="/connectors/import">Import an API</LinkButton>}
            {browse}
          </div>
        }
      >
        <Text as="h1" variant="heading" size="lg">
          Connectors
        </Text>
        <Text>The systems this workspace can reach.</Text>
      </HeaderWithAction>

      {/* A consent whose return names no connector ends here. */}
      <ConsentReturn result={consentResult(search)} onRead={clear} />

      {q.isPending && <Loading />}
      {q.isError && (
        <div role="alert">
          <Text>{message(q.error)}</Text>
        </div>
      )}
      {q.isSuccess && list.length === 0 && (
        <EmptyState title="No connectors yet" action={browse}>
          Install an adapter from the catalog, or import your own API.
        </EmptyState>
      )}

      <ul className="grid gap-3">
        {list.map((c) => (
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
