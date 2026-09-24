import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import { connectorsListOptions } from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge, Loading, SignInFirst } from "../lib/ui";

export const Route = createFileRoute("/connectors/")({
  component: Connectors,
});

function Connectors() {
  const { signedIn, loading } = useSession();
  const q = useQuery({ ...connectorsListOptions(), enabled: signedIn, retry: false });

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="grid gap-1.5">
          <Text as="h1" variant="heading2">
            Connectors
          </Text>
          <Text>The systems this workspace can reach. Install one from the catalog to get started.</Text>
        </div>
        <Link to="/catalog">
          <Button variant="primary">Browse catalog</Button>
        </Link>
      </div>

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
          <li key={c.id} className="rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="grid gap-1">
                <div className="flex items-center gap-2">
                  <Text as="span" bold>
                    {c.name}
                  </Text>
                  {!c.enabled && <Badge>disabled</Badge>}
                  {c.readOnly && <Badge>read-only</Badge>}
                </div>
                <Text as="span" variant="secondary">
                  {String(c.transport?.type ?? "")} · {String(c.auth?.type ?? "none")} · {c.toolCount} tools
                </Text>
              </div>
              <div className="flex items-center gap-2">
                {c.credentials?.some((cr) => !cr.set) && <Badge>credentials missing</Badge>}
                <Link
                  to="/connectors/$id/tools"
                  params={{ id: c.id }}
                  className="rounded-md px-3 py-1.5 ring ring-kumo-line hover:bg-kumo-tint"
                >
                  <Text as="span">Tools</Text>
                </Link>
                <Link
                  to="/connectors/$id/history"
                  params={{ id: c.id }}
                  className="rounded-md px-3 py-1.5 ring ring-kumo-line hover:bg-kumo-tint"
                >
                  <Text as="span">History</Text>
                </Link>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}


