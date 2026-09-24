import { useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import {
  catalogGetOptions,
  connectorsInstallMutation,
  connectorsListQueryKey,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { message } from "../lib/errors";

export const Route = createFileRoute("/catalog/$slug")({
  component: AdapterPage,
});

// The adapter document is served as raw JSON described by the published
// JSON Schema; only the parts this page needs are typed here.
interface AdapterDoc {
  metadata: { slug: string; name: string; description: string; docsUrl: string; category: string; region: string };
  credentials?: Record<string, { required: boolean; secret?: boolean; description?: string }>;
  transport: { type: string; baseUrl?: string; dsn?: string };
  auth: { type: string; optional?: boolean };
  instructions?: string;
  tools: { name: string; description: string; annotations?: { readOnlyHint?: boolean } }[];
}

function AdapterPage() {
  const { slug } = Route.useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { can, loading } = useSession();
  const q = useQuery(catalogGetOptions({ path: { slug } }));
  const a = q.data as unknown as AdapterDoc | undefined;
  // One value per declared credential, filled in before the adapter is
  // installed. They are sealed on the way into the database and never come
  // back out, so this form is the only place they are seen.
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const install = useMutation({
    ...connectorsInstallMutation(),
    onSuccess: async (connector) => {
      await qc.invalidateQueries({ queryKey: connectorsListQueryKey() });
      await navigate({ to: "/connectors", hash: connector.id });
    },
    onError: (e) => setError(message(e)),
  });

  if (q.isPending) return <Text>Loading…</Text>;
  if (!a) return <Text>Adapter not found.</Text>;

  const creds = Object.entries(a.credentials ?? {});
  const missing = creds.filter(([name, c]) => c.required && !values[name]?.trim()).map(([name]) => name);
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
          <Text as="h1" variant="heading2">
            {a.metadata.name}
          </Text>
          <Text>{a.metadata.description}</Text>
          <Text as="span" variant="secondary">
            {a.transport.type} · {a.auth.type}
            {a.auth.optional ? " (optional)" : ""} · {a.tools.length} tools ·{" "}
            <a href={a.metadata.docsUrl} className="underline" target="_blank" rel="noreferrer">
              docs
            </a>
          </Text>
        </div>
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

      {error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
        </div>
      )}

      {creds.length > 0 && (
        <section className="grid gap-3">
          <div className="grid gap-1">
            <Text as="h2" variant="heading3">
              Credentials
            </Text>
            <Text variant="secondary">
              Each value is encrypted with this workspace's own key before it is stored, and is never shown again.
            </Text>
          </div>
          <div className="grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
            {creds.map(([name, c]) => (
              <label key={name} className="grid gap-1.5">
                <span className="font-mono text-[0.9em]">
                  {name}
                  {!c.required && <span className="font-sans"> (optional)</span>}
                </span>
                {c.description && <Text variant="secondary">{c.description}</Text>}
                <Input
                  type={c.secret === false ? "text" : "password"}
                  autoComplete="off"
                  disabled={!allowed}
                  value={values[name] ?? ""}
                  onChange={(e) => setValues({ ...values, [name]: e.target.value })}
                />
              </label>
            ))}
            {missing.length > 0 && (
              <Text variant="secondary">
                Still needed: {missing.join(", ")}.
              </Text>
            )}
          </div>
        </section>
      )}

      <section className="grid gap-1.5">
        <Text as="h2" variant="heading3">
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
          <Text as="h2" variant="heading3">
            Instructions for the model
          </Text>
          <pre className="whitespace-pre-wrap rounded-lg bg-kumo-tint px-5 py-4 font-mono text-[12px]">{a.instructions}</pre>
        </section>
      )}
    </div>
  );
}
