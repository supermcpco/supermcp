import { useMemo, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import {
  catalogGetOptions,
  connectorsInstallMutation,
  connectorsListQueryKey,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { message, status } from "../lib/errors";
import { Loading, NotFound } from "../lib/ui";
import { toast } from "../components/shell/toast";
import { CredentialFields } from "../components/credential-fields";
import { parseAdapter, stillNeeded, type CredentialField } from "../lib/connector";
import { About } from "../components/about";

export const Route = createFileRoute("/_app/catalog/$slug")({
  component: AdapterPage,
});

function AdapterPage() {
  const { slug } = Route.useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { can, loading } = useSession();
  // An unknown slug is an answer, not a hiccup: asking again would only
  // keep the page saying "Loading" while the same 404 comes back.
  const q = useQuery({ ...catalogGetOptions({ path: { slug } }), retry: (n, e) => n < 1 && status(e) !== 404 });
  // Served as raw JSON described by the published adapter schema, not the
  // API's, so it is checked before anything reads it.
  const a = useMemo(() => (q.data === undefined ? undefined : parseAdapter(q.data)), [q.data]);
  // One value per declared credential, filled in before the adapter is
  // installed. They are sealed on the way into the database and never come
  // back out, so this form is the only place they are seen.
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const install = useMutation({
    ...connectorsInstallMutation(),
    onSuccess: async (connector) => {
      await qc.invalidateQueries({ queryKey: connectorsListQueryKey() });
      toast(`${a?.metadata.name ?? connector.name} installed`);
      // The connector's own page is where its credentials, status and
      // tools are, so that is where someone who just installed it goes.
      await navigate({ to: "/connectors/$id", params: { id: connector.id } });
    },
    onError: (e) => setError(message(e)),
  });

  if (q.isPending) return <Loading />;
  if (status(q.error) === 404) {
    return (
      <NotFound heading="Adapter not found" back={{ to: "/catalog" }} backLabel="Back to the catalog">
        This server's catalog has no adapter called {slug}.
      </NotFound>
    );
  }
  if (q.error) {
    return (
      <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
        <Text>{message(q.error)}</Text>
      </div>
    );
  }
  if (!a) {
    return (
      <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
        <Text>This server's description of the {slug} adapter is not in a form this page can read.</Text>
      </div>
    );
  }

  const creds: CredentialField[] = Object.entries(a.credentials ?? {}).map(([name, c]) => ({
    name,
    required: c.required ?? false,
    secret: c.secret !== false,
    description: c.description,
  }));
  const missing = stillNeeded(creds, values);
  // While the session is still arriving nobody has any permission yet, and
  // a button that is dead for that first moment swallows the click of
  // anyone who arrives ready to act. The server is the authority here, so
  // the request is allowed to be made and refused.
  const allowed = loading || can("connectors:create");
  return (
    <div className="grid gap-6">
      <Link to="/catalog" className="flex items-center gap-1 text-kumo-subtle">
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">Catalog</Text>
      </Link>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="grid gap-1.5">
          <Text as="h1" variant="heading" size="lg">
            {a.metadata.name}
          </Text>
          <Text>{a.metadata.description}</Text>
          <Text as="span" variant="secondary">
            {a.transport.type} · {a.auth.type}
            {a.auth.optional ? " (optional)" : ""} · {a.tools.length} tools
            {a.metadata.docsUrl && (
              <>
                {" · "}
                <a href={a.metadata.docsUrl} className="underline" target="_blank" rel="noreferrer">
                  docs
                </a>
              </>
            )}
          </Text>
        </div>
        <div className="flex items-center gap-1">
          <About label="About adding this adapter">
            <p>Installing creates a connector in this workspace with the tools listed below.</p>
            {creds.length > 0 && <p>The credentials you enter are stored encrypted and never shown again.</p>}
            <p>Then attach the connector to an MCP server, so an AI client can call its tools.</p>
          </About>
          <Button
            variant="primary"
            disabled={!allowed || install.isPending || missing.length > 0}
            onClick={() => {
              setError(null);
              install.mutate({ body: { slug, credentials: values } });
            }}
          >
            {install.isPending ? "Installing…" : "Install"}
          </Button>
        </div>
      </div>

      {error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
        </div>
      )}

      {creds.length > 0 && (
        <section className="grid gap-3">
          <div className="grid gap-1">
            <Text as="h2" variant="heading">
              Credentials
            </Text>
            <Text variant="secondary">Each value is stored encrypted and never shown again.</Text>
          </div>
          <CredentialFields fields={creds} values={values} onChange={setValues} disabled={!allowed} />
        </section>
      )}

      <section className="grid gap-1.5">
        <Text as="h2" variant="heading">
          Tools
        </Text>
        <ul className="grid gap-2">
          {a.tools.map((t) => (
            <li key={t.name} className="rounded-lg px-5 py-4 ring ring-kumo-line">
              <div className="grid gap-1">
                <span className="font-mono text-[0.9em]">{t.name}</span>
                <Text as="span" variant="secondary">
                  {t.description}
                </Text>
              </div>
            </li>
          ))}
        </ul>
      </section>

      {a.instructions && (
        <section className="grid gap-1.5">
          <Text as="h2" variant="heading">
            Instructions for the model
          </Text>
          <pre className="whitespace-pre-wrap rounded-lg bg-kumo-tint px-5 py-4 font-mono text-[12px]">{a.instructions}</pre>
        </section>
      )}
    </div>
  );
}
