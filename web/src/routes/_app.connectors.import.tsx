import { useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text, Textarea } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import { connectorsImportMutation, connectorsListQueryKey } from "../api/@tanstack/react-query.gen";
import type { ErrorDetail, ImportFinding, ImportOutputBody } from "../api";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { message } from "../lib/errors";

export const Route = createFileRoute("/_app/connectors/import")({
  component: ImportConnector,
});

function ImportConnector() {
  const { can } = useSession();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [format, setFormat] = useState<Format>("auto");
  const [source, setSource] = useState<"document" | "url">("document");
  const [doc, setDoc] = useState("");
  const [docUrl, setDocUrl] = useState("");
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [serverUrl, setServerUrl] = useState("");
  const [headers, setHeaders] = useState("");
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [result, setResult] = useState<ImportOutputBody | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [details, setDetails] = useState<ErrorDetail[]>([]);

  // A preview describes one exact document. Once any of the fields that
  // produced it changes, leaving it on screen would show what a different
  // import would create, which is the one thing this screen exists to
  // prevent.
  const revise = (apply: () => void) => {
    apply();
    setResult(null);
    setError(null);
    setDetails([]);
  };

  const fail = (e: unknown) => {
    setResult(null);
    setError(message(e));
    setDetails((e as { errors?: ErrorDetail[] | null } | undefined)?.errors ?? []);
  };

  const body = () => ({
    format,
    document: source === "document" ? doc : undefined,
    url: source === "url" ? docUrl.trim() : undefined,
    name: name.trim() || undefined,
    slug: slug.trim() || undefined,
    serverUrl: serverUrl.trim() || undefined,
    headers: format === "graphql" ? parseHeaders(headers) : undefined,
  });

  const dryRun = useMutation({
    ...connectorsImportMutation(),
    onSuccess: (r) => {
      setResult(r);
      setError(null);
      setDetails([]);
    },
    onError: fail,
  });

  const create = useMutation({
    ...connectorsImportMutation(),
    onSuccess: async (r) => {
      if (!r.connector) return;
      await qc.invalidateQueries({ queryKey: connectorsListQueryKey() });
      // The connectors list is where someone looks for what they just
      // made; its history is a record of a thing they have not seen yet.
      await navigate({ to: "/connectors" });
    },
    onError: fail,
  });

  if (!can("connectors:create")) {
    return <Text>You do not have permission to add connectors to this workspace.</Text>;
  }

  const shape = shapes[format];
  // A curl command is a command, not a document, and there is nothing at
  // the end of a URL to fetch one from.
  const canFetch = format !== "curl";
  const ready = source === "document" || !canFetch ? doc.trim() !== "" : docUrl.trim() !== "";
  const using = canFetch ? source : "document";
  const blockers = (result?.findings ?? []).filter((f) => f.level === "blocker");
  const needed = result?.preview?.credentials ?? [];

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
          Import an API description
        </Text>
        <Text>
          An OpenAPI document, a Postman collection, a curl command or a GraphQL endpoint. Each request in it becomes a
          tool a model can call. Nothing is created until you have seen the preview and asked for it.
        </Text>
      </div>

      <form
        className="grid gap-4 rounded-lg px-5 py-4 ring ring-kumo-line"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          setDetails([]);
          dryRun.mutate({ body: { ...body(), dryRun: true } });
        }}
      >
        <fieldset className="grid gap-2">
          <legend className="pb-1">
            <Text as="span" bold>
              What you have
            </Text>
          </legend>
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {formats.map((f) => (
              <label key={f} className="flex items-center gap-2">
                <input
                  type="radio"
                  name="format"
                  checked={format === f}
                  onChange={() =>
                    revise(() => {
                      setFormat(f);
                      // A curl command cannot be fetched from a URL, and a
                      // GraphQL endpoint is a URL rather than a document, so
                      // the format decides where the input comes from.
                      if (f === "curl") setSource("document");
                      if (f === "graphql") setSource("url");
                    })
                  }
                />
                <Text as="span">{shapes[f].label}</Text>
              </label>
            ))}
          </div>
          <Text variant="secondary">{shape.note}</Text>
        </fieldset>

        {canFetch && (
          <fieldset className="grid gap-2">
            <legend className="pb-1">
              <Text as="span" bold>
                Where it is
              </Text>
            </legend>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="source"
                checked={using === "document"}
                onChange={() => revise(() => setSource("document"))}
              />
              <Text as="span">I will paste it</Text>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="radio"
                name="source"
                checked={using === "url"}
                onChange={() => revise(() => setSource("url"))}
              />
              <Text as="span">{shape.fetch}</Text>
            </label>
          </fieldset>
        )}

        {using === "document" ? (
          <label className="grid gap-1.5">
            <Text as="span">{shape.documentLabel}</Text>
            <Textarea
              rows={10}
              className="font-mono text-[0.9em]"
              placeholder={shape.documentPlaceholder}
              value={doc}
              onChange={(e) => revise(() => setDoc(e.target.value))}
            />
          </label>
        ) : (
          <label className="grid gap-1.5">
            <Text as="span">{shape.urlLabel}</Text>
            <Input
              type="url"
              placeholder={shape.urlPlaceholder}
              value={docUrl}
              onChange={(e) => revise(() => setDocUrl(e.target.value))}
            />
          </label>
        )}

        {format === "graphql" && (
          <label className="grid gap-1.5">
            <Text as="span">Headers to introspect with</Text>
            <Textarea
              rows={2}
              className="font-mono text-[0.9em]"
              placeholder={"Authorization: Bearer …\nOne per line, name then colon then value"}
              value={headers}
              onChange={(e) => revise(() => setHeaders(e.target.value))}
            />
            <Text variant="secondary">
              These are used for the one request that asks the endpoint to describe itself. They are not stored: the
              preview will show a credential for whatever sign-in they imply, and you set its value below.
            </Text>
          </label>
        )}

        <div className="grid gap-3 sm:grid-cols-3">
          <label className="grid gap-1.5">
            <Text as="span">Connector name</Text>
            <Input
              placeholder={shape.namePlaceholder}
              value={name}
              onChange={(e) => revise(() => setName(e.target.value))}
            />
          </label>
          <label className="grid gap-1.5">
            <Text as="span">Tool name prefix</Text>
            <Input
              pattern="[a-z0-9]+(-[a-z0-9]+)*"
              placeholder="Lower case, words joined by hyphens"
              value={slug}
              onChange={(e) => revise(() => setSlug(e.target.value))}
            />
          </label>
          <label className="grid gap-1.5">
            <Text as="span">{format === "graphql" ? "Endpoint" : "Base URL"}</Text>
            <Input
              placeholder={shape.serverPlaceholder}
              value={serverUrl}
              onChange={(e) => revise(() => setServerUrl(e.target.value))}
            />
          </label>
        </div>

        <div>
          <Button type="submit" variant="primary" disabled={!ready || dryRun.isPending}>
            {dryRun.isPending ? shape.pending : "Preview import"}
          </Button>
        </div>
      </form>

      {error && (
        <div role="alert" className="grid gap-2 rounded-lg px-5 py-4 ring ring-kumo-line">
          <Text>{error}</Text>
          {details.length > 0 && (
            <ul className="grid gap-1">
              {details.map((d, i) => (
                <li key={`${d.location ?? ""}-${i}`}>
                  <Text as="span" variant="secondary">
                    {d.location ? `${d.location}: ` : ""}
                    {d.message}
                  </Text>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {result?.preview && (
        <section className="grid gap-6" aria-labelledby="preview-heading">
          <div className="grid gap-1.5">
            <Text as="h2" variant="heading3" id="preview-heading">
              What this would create
            </Text>
            <Text variant="secondary">Nothing here exists yet. Read it, then import.</Text>
          </div>

          <dl className="grid gap-2 rounded-lg px-5 py-4 ring ring-kumo-line">
            <Fact term="Name">{result.preview.name}</Fact>
            <Fact term="Read as">{shapes[(result.preview.format as Format) ?? "auto"]?.read ?? result.preview.format}</Fact>
            <Fact term={result.preview.transport === "graphql" ? "Posts to" : "Calls"}>{result.preview.baseUrl}</Fact>
            <Fact term="Signs in with">{authWording(result.preview.authType)}</Fact>
            <Fact term="Needs">
              {needed.length === 0 ? "Nothing; this connector is called without credentials." : needed.join(", ")}
            </Fact>
            <Fact term="Tools">{count(result.preview.tools.length, "tool")}</Fact>
          </dl>

          <Findings findings={result.findings} />

          {result.warnings && result.warnings.length > 0 && (
            <section className="grid gap-2">
              <div className="grid gap-0.5">
                <Text as="h3" variant="heading3">
                  Rough edges
                </Text>
                <Text variant="secondary">
                  None of these stop the import. They are things a hand-written connector would have and this one will
                  not, and you can put them right afterwards.
                </Text>
              </div>
              <ul className="grid gap-2">
                {result.warnings.map((w) => (
                  <li key={w} className="rounded-lg px-5 py-3 ring ring-kumo-line">
                    <Text as="span">{w}</Text>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="grid gap-2">
            <Text as="h3" variant="heading3">
              Tools
            </Text>
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-kumo-line">
                  <th className="py-2 pr-4">
                    <Text as="span" variant="secondary">
                      Tool
                    </Text>
                  </th>
                  <th className="py-2 pr-4">
                    <Text as="span" variant="secondary">
                      Request
                    </Text>
                  </th>
                  <th className="py-2">
                    <Text as="span" variant="secondary">
                      What it does
                    </Text>
                  </th>
                </tr>
              </thead>
              <tbody>
                {result.preview.tools.map((t) => (
                  <tr key={t.name} className="border-b border-kumo-line align-top">
                    <td className="py-2 pr-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[0.9em]">{t.name}</span>
                        {t.readOnly && <Badge>reads only</Badge>}
                        {t.destructive && <Badge>changes data</Badge>}
                      </div>
                    </td>
                    <td className="py-2 pr-4 whitespace-nowrap">
                      <span className="font-mono text-[0.9em]">{`${t.method} ${readablePath(t.path)}`.trim()}</span>
                    </td>
                    <td className="py-2">
                      <Text as="span" variant="secondary">
                        {t.description}
                      </Text>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          {needed.length > 0 && (
            <section className="grid gap-3">
              <div className="grid gap-1">
                <Text as="h3" variant="heading3">
                  Credentials
                </Text>
                <Text variant="secondary">
                  Each value is encrypted with this workspace's own key before it is stored, and is never shown again.
                  You can leave them empty and fill them in later, but no tool will work until they are set.
                </Text>
              </div>
              <div className="grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
                {needed.map((key) => (
                  <label key={key} className="grid gap-1.5">
                    <span className="font-mono text-[0.9em]">{key}</span>
                    <Input
                      type="password"
                      autoComplete="off"
                      value={credentials[key] ?? ""}
                      onChange={(e) => setCredentials({ ...credentials, [key]: e.target.value })}
                    />
                  </label>
                ))}
              </div>
            </section>
          )}

          <div className="flex flex-wrap items-center gap-3">
            <Button
              variant="primary"
              disabled={blockers.length > 0 || create.isPending}
              onClick={() => {
                setError(null);
                setDetails([]);
                create.mutate({ body: { ...body(), credentials: filled(credentials), dryRun: false } });
              }}
            >
              {create.isPending ? "Importing…" : "Import connector"}
            </Button>
            {blockers.length > 0 && (
              <Text variant="secondary">
                Settle the {count(blockers.length, "question")} above and preview again before importing.
              </Text>
            )}
          </div>
        </section>
      )}
    </div>
  );
}

/**
 * The formats the importer reads. "auto" is first because it is the right
 * answer most of the time; the rest are there for a document that could be
 * read two ways, which the server refuses to guess about.
 */
type Format = "auto" | "openapi" | "postman" | "curl" | "graphql";

const formats: Format[] = ["auto", "openapi", "postman", "curl", "graphql"];

/** What each format changes about this screen. */
const shapes: Record<Format, {
  label: string;
  read: string;
  note: string;
  fetch: string;
  documentLabel: string;
  documentPlaceholder: string;
  urlLabel: string;
  urlPlaceholder: string;
  namePlaceholder: string;
  serverPlaceholder: string;
  pending: string;
}> = {
  auto: {
    label: "Work it out",
    read: "worked out from the document",
    note: "Paste whatever you have. If it could be read two ways, you will be asked which you meant rather than given a connector that calls the wrong thing.",
    fetch: "Fetch it from a URL",
    documentLabel: "Document",
    documentPlaceholder: "Paste an OpenAPI document, a Postman collection, or a curl command",
    urlLabel: "Document URL",
    urlPlaceholder: "https://example.com/openapi.json",
    namePlaceholder: "Taken from the document",
    serverPlaceholder: "Only if the document names several",
    pending: "Reading the document…",
  },
  openapi: {
    label: "OpenAPI",
    read: "an OpenAPI document",
    note: "OpenAPI 3.0 or 3.1, as JSON or YAML. Every operation becomes a tool.",
    fetch: "Fetch it from a URL",
    documentLabel: "OpenAPI document",
    documentPlaceholder: "Paste the JSON or YAML of an OpenAPI 3.0 or 3.1 document",
    urlLabel: "Document URL",
    urlPlaceholder: "https://example.com/openapi.json",
    namePlaceholder: "Taken from the document's title",
    serverPlaceholder: "Only if the document names several",
    pending: "Reading the document…",
  },
  postman: {
    label: "Postman collection",
    read: "a Postman collection",
    note: "A v2.1 collection export. Folders become tool name prefixes, and a variable the collection marks secret becomes a credential rather than a value stored here.",
    fetch: "Fetch it from a URL",
    documentLabel: "Collection JSON",
    documentPlaceholder: "Paste the JSON you exported from Postman",
    urlLabel: "Collection URL",
    urlPlaceholder: "https://example.com/collection.json",
    namePlaceholder: "Taken from the collection's name",
    serverPlaceholder: "Only if the collection calls several hosts",
    pending: "Reading the collection…",
  },
  curl: {
    label: "curl command",
    read: "a curl command",
    note: "One command, however many lines it runs to. Anything that would need a shell to run — $(…), backquotes, reading a file — is refused and says why. A key in the command becomes a credential, never a value stored here.",
    fetch: "Fetch it from a URL",
    documentLabel: "curl command",
    documentPlaceholder: "curl https://api.example.com/v1/things \\\n  -H \"Authorization: Bearer $TOKEN\"",
    urlLabel: "Command URL",
    urlPlaceholder: "",
    namePlaceholder: "Taken from the host it calls",
    serverPlaceholder: "Taken from the command's URL",
    pending: "Reading the command…",
  },
  graphql: {
    label: "GraphQL",
    read: "a GraphQL schema",
    note: "The endpoint itself, which is asked to describe its schema, or an introspection response you already have. Each root field becomes a tool.",
    fetch: "Introspect the endpoint",
    documentLabel: "Introspection response",
    documentPlaceholder: "Paste the JSON an introspection query returned",
    urlLabel: "GraphQL endpoint",
    urlPlaceholder: "https://api.example.com/graphql",
    namePlaceholder: "Taken from the endpoint's host",
    serverPlaceholder: "Needed when you paste a response rather than a URL",
    pending: "Asking the endpoint…",
  },
};

/**
 * Reads the headers someone typed, one per line. An empty result is sent
 * as nothing at all rather than an empty object, so the server sees the
 * same request it would have had before this field existed.
 */
function parseHeaders(text: string): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const at = line.indexOf(":");
    if (at <= 0) continue;
    const name = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    if (name !== "" && value !== "") out[name] = value;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** One line of the preview: a label and the value it would take. */
function Fact({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-2">
      <dt className="w-32 shrink-0">
        <Text as="span" variant="secondary">
          {term}
        </Text>
      </dt>
      <dd className="min-w-0 break-words">
        <Text as="span">{children}</Text>
      </dd>
    </div>
  );
}

/**
 * The findings, split by how much they ask of the reader. A blocker stops
 * the import; the rest are the importer saying what it decided, and
 * burying one in the other is how a decision gets made by nobody.
 */
function Findings({ findings }: { findings: ImportFinding[] }) {
  const groups = [
    {
      level: "blocker",
      heading: "You have to decide these first",
      note: "The import will not run until each of these is answered, usually by filling in a field above.",
      ring: "ring-2 ring-kumo-danger",
    },
    {
      level: "review",
      heading: "Worth reading before you import",
      note: "The importer made a choice here that you may want to make differently.",
      ring: "ring ring-kumo-warning",
    },
    {
      level: "info",
      heading: "What the importer filled in for you",
      note: "Nothing to do; this is only a record of how the document was read.",
      ring: "ring ring-kumo-line",
    },
  ];

  const present = groups.filter((g) => findings.some((f) => f.level === g.level));
  if (present.length === 0) return null;

  return (
    <div className="grid gap-4">
      {present.map((g) => (
        <section key={g.level} className="grid gap-2">
          <div className="grid gap-0.5">
            <Text as="h3" variant="heading3">
              {g.heading}
            </Text>
            <Text variant="secondary">{g.note}</Text>
          </div>
          <ul className="grid gap-2">
            {findings
              .filter((f) => f.level === g.level)
              .map((f, i) => (
                <li key={`${f.path}-${f.operation ?? ""}-${i}`} className={`grid gap-1 rounded-lg px-5 py-3 ${g.ring}`}>
                  <Text as="span">{f.message}</Text>
                  <Text as="span" variant="secondary">
                    <span className="font-mono text-[0.9em]">{f.operation ? `${f.operation} · ${f.path}` : f.path}</span>
                  </Text>
                </li>
              ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

/** Says how a connector proves who it is, without naming the field in the spec. */
function authWording(type: string): string {
  switch (type) {
    case "none":
    case "":
      return "Nothing; the API is called without credentials.";
    case "bearer":
      return "A bearer token, sent with every call.";
    case "basic":
      return "A username and password, sent with every call.";
    case "apiKey":
    case "api_key":
      return "An API key, sent with every call.";
    case "oauth2":
      return "OAuth, which this workspace will hold the tokens for.";
    case "oauth1":
      return "OAuth 1, with a consumer key and secret this workspace holds.";
    default:
      return type;
  }
}

function count(n: number, noun: string): string {
  return n === 1 ? `1 ${noun}` : `${n} ${noun}s`;
}

/** Sends only the credentials someone actually typed into. */
function filled(values: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(values).filter(([, v]) => v.trim() !== ""));
}

/**
 * Paths are stored as templates the engine understands. A person reading
 * the preview wrote `{orderId}` in their document and should see that,
 * not the form it was rewritten into.
 */
function readablePath(path: string): string {
  return path.replace(/\{\{\s*params\.([^}|\s]+)[^}]*\}\}/g, "{$1}");
}
