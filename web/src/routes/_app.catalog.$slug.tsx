import { useId, useMemo, useRef, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, SkeletonLine, Text } from "@cloudflare/kumo";
import { ArrowDown, ArrowLeft, ArrowSquareOut, CaretRight, CheckCircle } from "@phosphor-icons/react";
import type { ConnectorDto } from "../api";
import {
  catalogGetOptions,
  catalogListOptions,
  connectorsInstallMutation,
  connectorsListOptions,
  connectorsListQueryKey,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { message, status } from "../lib/errors";
import { plural } from "../lib/analytics";
import { Badge, NotFound } from "../lib/ui";
import { toast } from "../components/shell/toast";
import { initials } from "../components/shell/initials";
import { CredentialFields } from "../components/credential-fields";
import {
  authBadge,
  authLabel,
  parseAdapter,
  regionLabel,
  stillNeeded,
  targetHost,
  toolEffect,
  toolMatches,
  toolParameters,
  transportLabel,
  type AdapterDocument,
  type AdapterTool,
  type CredentialField,
} from "../lib/connector";
import { About } from "../components/about";

export const Route = createFileRoute("/_app/catalog/$slug")({
  component: AdapterPage,
});

/**
 * One column on a phone: the header, then what it takes to set it up,
 * then its tools. From 1024px the set-up and the details stand in a
 * column of their own on the right, and stay in view while the tools
 * scroll past. The details card closes the page on a phone; the docs
 * link it carries is in the header too.
 */
const layout = "flex min-w-0 flex-col gap-6 *:min-w-0 lg:grid lg:grid-cols-[minmax(0,1fr)_20rem] lg:items-start lg:gap-x-8";
const asideClass = "contents lg:sticky lg:top-0 lg:col-start-2 lg:row-span-2 lg:row-start-1 lg:grid lg:gap-4";
const card = "grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-line";

function AdapterPage() {
  const { slug } = Route.useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { can, loading, signedIn } = useSession();
  // An unknown slug is an answer, not a hiccup: asking again would only
  // keep the page loading while the same 404 comes back.
  const q = useQuery({ ...catalogGetOptions({ path: { slug } }), retry: (n, e) => n < 1 && status(e) !== 404 });
  // Served as raw JSON described by the published adapter schema, not the
  // API's, so it is checked before anything reads it.
  const a = useMemo(() => (q.data === undefined ? undefined : parseAdapter(q.data)), [q.data]);
  // Connectors already made from this adapter. Someone who cannot list
  // connectors simply sees no "Installed"; the install itself is the
  // server's to allow or refuse.
  const connectors = useQuery({ ...connectorsListOptions(), enabled: signedIn, retry: false });
  const installed = (connectors.data ?? []).filter((c) => c.catalogSlug === slug);
  // The index entry carries the adapter's content hash, which the
  // document itself does not.
  const entry = useQuery({ ...catalogListOptions({ query: { q: slug } }), retry: false });
  const hash = entry.data?.adapters.find((e) => e.slug === slug)?.contentHash;

  // One value per declared credential, filled in before the adapter is
  // installed. They are sealed on the way into the database and never come
  // back out, so this form is the only place they are seen.
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const setUp = useRef<HTMLElement>(null);

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

  if (q.isPending) return <PageSkeleton />;
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
  const required = creds.filter((c) => c.required).length;
  const missing = stillNeeded(creds, values);
  // While the session is still arriving nobody has any permission yet, and
  // a button that is dead for that first moment swallows the click of
  // anyone who arrives ready to act. The server is the authority here, so
  // the request is allowed to be made and refused.
  const allowed = loading || can("connectors:create");
  const effects = a.tools.map((t) => toolEffect(t, a.transport.type, a.metadata.slug));
  const readOnly = effects.length > 0 && effects.every((e) => e === "reads only");

  return (
    <div className="grid max-w-6xl min-w-0 gap-5">
      <Link to="/catalog" className="flex w-fit items-center gap-1 text-kumo-subtle">
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">Catalog</Text>
      </Link>

      <div className={layout}>
        <header className="grid gap-3 [overflow-wrap:anywhere] lg:col-start-1">
          <div className="flex items-start gap-4">
            <span
              aria-hidden
              className="grid size-12 shrink-0 place-items-center rounded-lg bg-kumo-tint text-base font-semibold text-kumo-default ring ring-kumo-line"
            >
              {initials(a.metadata.name, a.metadata.slug)}
            </span>
            <div className="grid min-w-0 gap-1">
              <Text as="h1" variant="heading" size="lg">
                {a.metadata.name}
              </Text>
              {a.metadata.description && <Text variant="secondary">{a.metadata.description}</Text>}
            </div>
          </div>
          <ul aria-label="About this adapter" className="flex flex-wrap gap-2">
            {a.metadata.category && (
              <li>
                <Badge>{a.metadata.category}</Badge>
              </li>
            )}
            {a.metadata.region && (
              <li>
                <Badge>{regionLabel(a.metadata.region)}</Badge>
              </li>
            )}
            <li>
              <Badge>{authBadge(a.auth, required)}</Badge>
            </li>
            <li>
              <Badge>{transportLabel(a.transport.type)}</Badge>
            </li>
            {readOnly && (
              <li>
                <Badge>read-only</Badge>
              </li>
            )}
            <li>
              <Badge>{plural(a.tools.length, "tool")}</Badge>
            </li>
          </ul>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            {a.metadata.docsUrl && <ExternalLink href={a.metadata.docsUrl}>Docs</ExternalLink>}
            {/* On a phone the set-up card is further down the page; this
                takes a person there, and its fields take the focus. On a
                wide screen the card is already beside the header, and its
                button is the only Install. */}
            <a
              href="#set-up"
              className="flex items-center gap-1 rounded-md bg-kumo-tint px-3 py-1.5 ring ring-kumo-line lg:hidden"
              onClick={(e) => {
                e.preventDefault();
                setUp.current?.scrollIntoView({ behavior: "smooth", block: "start" });
                setUp.current?.focus({ preventScroll: true });
              }}
            >
              <Text as="span">{installed.length > 0 ? "Installed" : "Install"}</Text>
              <ArrowDown size={14} aria-hidden />
            </a>
          </div>
        </header>

        <div className={asideClass}>
          <section ref={setUp} id="set-up" tabIndex={-1} aria-labelledby="set-up-heading" className={`${card} outline-none focus-visible:ring-2 focus-visible:ring-kumo-brand`}>
            <div className="flex items-center justify-between gap-2">
              <Text as="h2" variant="heading" id="set-up-heading">
                Set up
              </Text>
              <About label="About adding this adapter">
                <p>Installing creates a connector in this workspace with the tools listed on this page.</p>
                {creds.length > 0 && <p>The credentials you enter are stored encrypted and never shown again.</p>}
                <p>Then attach the connector to an MCP server, so an AI client can call its tools.</p>
              </About>
            </div>
            {installed.length > 0 && <Installed connectors={installed} />}
            {creds.length > 0 ? (
              <div className="grid gap-2">
                <Text as="h3" bold>
                  Credentials
                </Text>
                <Text variant="secondary">Each value is stored encrypted and never shown again.</Text>
                <CredentialFields bare fields={creds} values={values} onChange={setValues} disabled={!allowed} />
              </div>
            ) : (
              <Text variant="secondary">No credentials needed: its tools can be called as soon as it is installed.</Text>
            )}
            {error && (
              <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
                <Text>{error}</Text>
              </div>
            )}
            <Button
              variant={installed.length > 0 ? "secondary" : "primary"}
              className="w-full justify-center"
              disabled={!allowed || install.isPending || missing.length > 0}
              onClick={() => {
                setError(null);
                install.mutate({ body: { slug, credentials: values } });
              }}
            >
              {install.isPending ? "Installing…" : installed.length > 0 ? "Install another" : "Install"}
            </Button>
          </section>

          <Details adapter={a} hash={hash} />
        </div>

        <div className="grid min-w-0 gap-6 lg:col-start-1">
          <Tools adapter={a} />
          {a.instructions && (
            <section aria-labelledby="instructions-heading" className="grid gap-1.5">
              <Text as="h2" variant="heading" id="instructions-heading">
                Instructions for the model
              </Text>
              <pre className="whitespace-pre-wrap [overflow-wrap:anywhere] rounded-lg bg-kumo-tint px-5 py-4 font-mono text-[12px]">{a.instructions}</pre>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

/** A link that leaves the console, said so in words and with the usual mark. */
function ExternalLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="flex w-fit items-center gap-1 underline">
      <Text as="span">{children}</Text>
      <ArrowSquareOut size={14} aria-hidden />
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}

/** The connectors this workspace already made from the adapter. */
function Installed({ connectors }: { connectors: ConnectorDto[] }) {
  return (
    <div className="grid gap-1.5 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
      <span className="flex items-center gap-1.5">
        <CheckCircle size={16} weight="fill" aria-hidden className="text-kumo-success" />
        <Text as="span" bold>
          {connectors.length === 1 ? "Installed" : `Installed ${connectors.length} times`}
        </Text>
      </span>
      <ul className="grid gap-1">
        {connectors.map((c) => (
          <li key={c.id}>
            <Link to="/connectors/$id" params={{ id: c.id }} className="underline">
              <Text as="span">{c.name}</Text>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The facts someone checks before installing: how it signs in, where it reaches, which version. */
function Details({ adapter: a, hash }: { adapter: AdapterDocument; hash?: string }) {
  const host = targetHost(a.transport);
  const docsHost = a.metadata.docsUrl ? hostOf(a.metadata.docsUrl) : null;
  return (
    <section aria-labelledby="details-heading" className={`${card} order-last`}>
      <Text as="h2" variant="heading" id="details-heading">
        Details
      </Text>
      <dl className="grid gap-2">
        <Fact term="Sign-in">{authLabel(a.auth)}</Fact>
        <Fact term="Transport">{transportLabel(a.transport.type)}</Fact>
        {host && (
          <Fact term="Reaches">
            <span className="font-mono text-[0.9em] break-all">{host}</span>
          </Fact>
        )}
        {a.metadata.region && <Fact term="Region">{regionLabel(a.metadata.region)}</Fact>}
        {hash && (
          <Fact term="Catalog version">
            <span className="font-mono text-[0.9em]">{hash.slice(0, 12)}</span>
          </Fact>
        )}
        {a.metadata.docsUrl && docsHost && (
          <Fact term="Documentation">
            <ExternalLink href={a.metadata.docsUrl}>{docsHost}</ExternalLink>
          </Fact>
        )}
      </dl>
    </section>
  );
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

function Fact({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-0.5">
      <dt>
        <Text as="span" variant="secondary">
          {term}
        </Text>
      </dt>
      <dd className="min-w-0">
        <Text as="span">{children}</Text>
      </dd>
    </div>
  );
}

/** The adapter's tools, narrowed by what is typed into the filter. */
function Tools({ adapter: a }: { adapter: AdapterDocument }) {
  const [filter, setFilter] = useState("");
  const shown = a.tools.filter((t) => toolMatches(t, filter));
  const total = a.tools.length;
  return (
    <section aria-labelledby="tools-heading" className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <Text as="h2" variant="heading" id="tools-heading">
          Tools
        </Text>
        <Text as="span" variant="secondary" aria-live="polite">
          {shown.length === total ? plural(total, "tool") : `${shown.length} of ${plural(total, "tool")}`}
        </Text>
      </div>
      {total > 1 && (
        <div className="w-full sm:max-w-sm">
          <Input
            type="search"
            className="w-full"
            aria-label="Filter tools"
            placeholder="Filter tools"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      )}
      {shown.length === 0 ? (
        <div className="grid justify-items-start gap-2 rounded-lg px-5 py-4 ring ring-kumo-line">
          <Text>No tool matches “{filter.trim()}”.</Text>
          <Button onClick={() => setFilter("")}>Clear the filter</Button>
        </div>
      ) : (
        <ul className="grid gap-2">
          {shown.map((t) => (
            <ToolRow key={t.name} tool={t} transport={a.transport.type} slug={a.metadata.slug} />
          ))}
        </ul>
      )}
    </section>
  );
}

/** One tool: its name, what calling it does, and the parameters it takes behind a disclosure. */
function ToolRow({ tool: t, transport, slug }: { tool: AdapterTool; transport: string; slug: string }) {
  const [open, setOpen] = useState(false);
  const panel = useId();
  const params = toolParameters(t);
  const effect = toolEffect(t, transport, slug);
  return (
    <li className="grid min-w-0 gap-2 rounded-lg px-5 py-4 [overflow-wrap:anywhere] ring ring-kumo-line">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[0.9em] break-all">{t.name}</span>
        {effect && <Badge>{effect}</Badge>}
      </div>
      {t.description && (
        <Text as="span" variant="secondary">
          {t.description}
        </Text>
      )}
      {params.length === 0 ? (
        <Text as="span" variant="secondary" size="sm">
          No parameters.
        </Text>
      ) : (
        <div className="grid gap-2">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={panel}
            onClick={() => setOpen(!open)}
            className="flex w-fit cursor-pointer items-center gap-1 rounded-md py-0.5 text-kumo-default outline-none hover:underline focus-visible:ring-2 focus-visible:ring-kumo-brand"
          >
            <CaretRight size={12} aria-hidden className={open ? "rotate-90 transition-transform" : "transition-transform"} />
            <Text as="span" size="sm">
              {plural(params.length, "parameter")}
              <span className="sr-only"> of {t.name}</span>
            </Text>
          </button>
          {open && (
            <ul id={panel} aria-label={`Parameters of ${t.name}`} className="grid gap-2 border-l border-kumo-line pl-4">
              {params.map((p) => (
                <li key={p.name} className="grid gap-0.5">
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="font-mono text-[0.85em] break-all">{p.name}</span>
                    {p.type && (
                      <Text as="span" variant="secondary" size="sm">
                        {p.type}
                      </Text>
                    )}
                    <Badge>{p.required ? "required" : "optional"}</Badge>
                  </span>
                  {p.description && (
                    <Text as="span" variant="secondary" size="sm">
                      {p.description}
                    </Text>
                  )}
                  {(p.choices || p.fallback !== undefined) && (
                    <Text as="span" variant="secondary" size="sm">
                      {p.choices && `One of ${p.choices.join(", ")}.`}
                      {p.choices && p.fallback !== undefined && " "}
                      {p.fallback !== undefined && `Defaults to ${p.fallback}.`}
                    </Text>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </li>
  );
}

/**
 * The page's shape while the adapter is on its way, so nothing jumps when
 * it arrives: the header, the set-up card beside it, and a few tool rows.
 */
function PageSkeleton() {
  return (
    <div className="grid max-w-6xl gap-5" aria-busy="true">
      <span className="sr-only">Loading…</span>
      <SkeletonLine minWidth={8} maxWidth={8} className="max-w-24" />
      <div className={layout}>
        <div className="grid gap-3 lg:col-start-1">
          <div className="flex items-start gap-4">
            <span aria-hidden className="size-12 shrink-0 rounded-lg bg-kumo-tint ring ring-kumo-line" />
            <div className="grid flex-1 gap-2">
              <SkeletonLine minWidth={40} maxWidth={55} blockHeight={28} />
              <SkeletonLine minWidth={80} maxWidth={100} />
              <SkeletonLine minWidth={50} maxWidth={70} />
            </div>
          </div>
          <SkeletonLine minWidth={45} maxWidth={60} blockHeight={22} />
        </div>
        <div className={asideClass}>
          <div className={card}>
            <SkeletonLine minWidth={30} maxWidth={40} blockHeight={24} />
            <SkeletonLine minWidth={70} maxWidth={90} />
            <SkeletonLine minWidth={100} maxWidth={100} blockHeight={32} />
          </div>
        </div>
        <div className="grid min-w-0 gap-3 lg:col-start-1">
          <SkeletonLine minWidth={15} maxWidth={20} blockHeight={24} />
          {[0, 1, 2].map((i) => (
            <div key={i} className={card}>
              <SkeletonLine minWidth={35} maxWidth={50} />
              <SkeletonLine minWidth={70} maxWidth={95} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
