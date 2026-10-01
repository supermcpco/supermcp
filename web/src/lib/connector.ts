import { z } from "zod";
import type { ConnectorDto } from "../api";

// What the connector screens say about one connector: which credentials it
// still needs, where it reaches, how it signs in and what it last did. The
// server decides every one of these; the functions here only read its
// answer, and never print a value it redacted.

/** One credential a form asks for, from the catalog or from a connector. */
export interface CredentialField {
  name: string;
  required: boolean;
  /** Whether the value is typed into a password field. */
  secret: boolean;
  /** The adapter's own words on where to find the value. */
  description?: string;
  /** Whether the connector already holds a value for it. */
  set?: boolean;
}

/**
 * The credentials that must still be given before the connector can be
 * called: required, not held by the connector, and not typed in yet.
 */
export function stillNeeded(fields: readonly CredentialField[], values: Record<string, string>): string[] {
  return fields.filter((f) => f.required && !f.set && !values[f.name]?.trim()).map((f) => f.name);
}

/**
 * Only the credentials someone actually typed into. An empty value would
 * clear a credential the connector holds, which a blank field never means.
 */
export function filled(values: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(values).filter(([, v]) => v.trim() !== ""));
}

// A catalog adapter document is described by a published JSON Schema
// rather than the API's, so it is checked here instead of trusted. Only
// the parts the screens read are named; the rest is dropped.
const adapterCredential = z.object({
  required: z.boolean().optional(),
  secret: z.boolean().optional(),
  description: z.string().optional(),
});

/** The part of an adapter document the credential form reads. */
const adapterCredentials = z.object({
  credentials: z.record(z.string(), adapterCredential).optional(),
});

/** The part of an adapter document its catalog page shows. */
const adapterDocument = adapterCredentials.extend({
  metadata: z.object({
    slug: z.string(),
    name: z.string(),
    description: z.string().default(""),
    docsUrl: z.string().optional(),
    region: z.string().optional(),
    category: z.string().optional(),
  }),
  transport: z.object({ type: z.string(), baseUrl: z.string().optional(), dsn: z.string().optional() }),
  auth: z.object({ type: z.string(), optional: z.boolean().optional() }),
  instructions: z.string().optional(),
  tools: z
    .array(
      z.object({
        name: z.string(),
        description: z.string().default(""),
        annotations: z
          .object({
            readOnlyHint: z.boolean().optional(),
            destructiveHint: z.boolean().optional(),
            idempotentHint: z.boolean().optional(),
          })
          .optional(),
        // The input schema is read loosely: one odd property must not make
        // the whole page unreadable, so each is checked on its own later.
        input: z
          .object({
            properties: z.record(z.string(), z.unknown()).optional(),
            required: z.array(z.string()).optional(),
          })
          .optional(),
        operation: z
          .object({ method: z.string().optional(), kind: z.string().optional(), statement: z.string().optional() })
          .optional(),
      }),
    )
    .default([]),
});

export type AdapterDocument = z.infer<typeof adapterDocument>;
export type AdapterTool = AdapterDocument["tools"][number];

/** An adapter document as its catalog page reads it, or null when it is not one. */
export function parseAdapter(doc: unknown): AdapterDocument | null {
  const parsed = adapterDocument.safeParse(doc);
  return parsed.success ? parsed.data : null;
}

/** One parameter a tool takes, as its catalog page lists it. */
export interface ToolParameter {
  name: string;
  /** "string", "integer or null", "array of string"; empty when the schema names none. */
  type: string;
  required: boolean;
  description?: string;
  /** The values it is limited to, in the schema's words. */
  choices?: string[];
  /** The value used when it is left out, as text. */
  fallback?: string;
}

const parameterSchema = z.object({
  type: z.union([z.string(), z.array(z.string())]).optional(),
  description: z.string().optional(),
  enum: z.array(z.unknown()).optional(),
  default: z.unknown().optional(),
  items: z.object({ type: z.union([z.string(), z.array(z.string())]).optional() }).optional(),
});

function typeWords(t: string | string[] | undefined): string {
  if (t === undefined) return "";
  return Array.isArray(t) ? t.join(" or ") : t;
}

function asText(v: unknown): string {
  return typeof v === "string" ? v : JSON.stringify(v);
}

/** The parameters a tool's input schema declares, required ones first, each in declared order. */
export function toolParameters(t: Pick<AdapterTool, "input">): ToolParameter[] {
  const required = new Set(t.input?.required ?? []);
  const params = Object.entries(t.input?.properties ?? {}).map(([name, raw]): ToolParameter => {
    const p = parameterSchema.safeParse(raw);
    if (!p.success) return { name, type: "", required: required.has(name) };
    const base = typeWords(p.data.type);
    const item = typeWords(p.data.items?.type);
    return {
      name,
      type: base === "array" && item ? `array of ${item}` : base,
      required: required.has(name),
      description: p.data.description,
      choices: p.data.enum?.map(asText),
      fallback: p.data.default === undefined ? undefined : asText(p.data.default),
    };
  });
  return [...params.filter((p) => p.required), ...params.filter((p) => !p.required)];
}

/** What calling a tool does, as the badges say it. */
export type ToolEffect = "reads only" | "destructive" | "writes";

/** The verbs that make a tool read-shaped when its name starts with one. */
const readVerbs = ["get", "list", "search", "find", "read", "fetch", "describe"];

/**
 * Whether a tool's name says it reads: `bexio_search_contacts`, after the
 * adapter's prefix, or `get_rates` with none. The prefix is the slug when
 * the name carries it, otherwise the name's first word.
 */
function readShaped(name: string, slug: string): boolean {
  const n = name.toLowerCase();
  const prefix = `${slug.toLowerCase().replace(/-/g, "_")}_`;
  const rests = [n, n.startsWith(prefix) ? n.slice(prefix.length) : n.slice(n.indexOf("_") + 1)];
  return rests.some((r) => readVerbs.some((v) => r === v || r.startsWith(`${v}_`)));
}

/**
 * What a catalog tool does when called, for its badge, or null when
 * nothing can be said. The adapter's own hints decide when it declares
 * them. Otherwise GET and HEAD read; a POST, PUT or PATCH reads when its
 * name says so (many APIs search over POST) and writes when not; only a
 * DELETE is destructive. A POST is never called destructive on its own.
 *
 * This is deliberately kinder than the server's derivation for MCP
 * clients (internal/tool/annotations.go), which treats a POST without an
 * additive verb as destructive; a connector's tools screen shows that.
 */
export function toolEffect(
  t: Pick<AdapterTool, "name" | "annotations" | "operation">,
  transport: string,
  slug = "",
): ToolEffect | null {
  const hints = t.annotations;
  if (hints?.readOnlyHint === true) return "reads only";
  if (hints?.destructiveHint === true) return "destructive";
  if (hints?.readOnlyHint === false) return "writes";

  const op = t.operation ?? {};
  const reads = readShaped(t.name, slug);
  let inferred: ToolEffect | null;
  if (op.kind === "static" || op.kind === "schema" || op.kind === "query") {
    inferred = "reads only";
  } else if (op.kind === "mutation") {
    inferred = reads ? "reads only" : "writes";
  } else if (transport === "database" && op.statement) {
    const s = op.statement.trim().toUpperCase();
    if (["SELECT", "WITH", "{"].some((w) => s.startsWith(w))) inferred = "reads only";
    else if (["DELETE", "DROP", "TRUNCATE"].some((w) => s.startsWith(w))) inferred = "destructive";
    else inferred = "writes";
  } else {
    switch ((op.method ?? "").toUpperCase()) {
      case "GET":
      case "HEAD":
        inferred = "reads only";
        break;
      case "POST":
      case "PUT":
      case "PATCH":
        inferred = reads ? "reads only" : "writes";
        break;
      case "DELETE":
        inferred = "destructive";
        break;
      default:
        inferred = reads ? "reads only" : null;
    }
  }
  // An adapter that says a DELETE is not destructive is taken at its word;
  // idempotentHint alone says nothing about reading or writing.
  if (inferred === "destructive" && hints?.destructiveHint === false) return "writes";
  return inferred;
}

/**
 * How an adapter signs in, in a word or two for a badge. "No credentials
 * needed" exactly when the catalog's filter of that name lists it: no
 * credential is required, whatever the auth type says.
 */
export function authBadge(auth: { type: string; optional?: boolean }, requiredCredentials: number): string {
  if (requiredCredentials === 0) return "No credentials needed";
  const optional = auth.optional ? " (optional)" : "";
  switch (auth.type) {
    case "none":
      return "Credentials needed";
    case "apiKey":
      return `API key${optional}`;
    case "oauth2":
      return `OAuth 2.0${optional}`;
    case "oauth1":
      return `OAuth 1.0${optional}`;
    case "basic":
      return `Basic${optional}`;
    case "bearer":
      return `Bearer${optional}`;
    case "query":
      return `Query string${optional}`;
    case "login":
      return `Login${optional}`;
    case "hmac":
      return `Signed requests${optional}`;
    case "database":
      return `Database user${optional}`;
    case "wsSecurity":
      return `WS-Security${optional}`;
    case "mtls":
      return `Client certificate${optional}`;
    default:
      return `${auth.type}${optional}`;
  }
}

/** A transport's name as it is written. */
export function transportLabel(type: string): string {
  const names: Record<string, string> = {
    http: "HTTP",
    graphql: "GraphQL",
    database: "Database",
    soap: "SOAP",
    mcp: "MCP",
  };
  return names[type] ?? type;
}

/** An adapter's region code as a place: "de" is Germany, "intl" is international. */
export function regionLabel(code: string): string {
  if (code === "intl") return "International";
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

/** Whether a tool matches what was typed into the filter: its name, its words or a parameter's name. */
export function toolMatches(t: Pick<AdapterTool, "name" | "description" | "input">, filter: string): boolean {
  const q = filter.trim().toLowerCase();
  if (!q) return true;
  return [t.name, t.description, ...Object.keys(t.input?.properties ?? {})].some((s) => s.toLowerCase().includes(q));
}

/** The adapter's description of each credential, by name. */
export function credentialDescriptions(doc: unknown): Record<string, string> {
  const parsed = adapterCredentials.safeParse(doc);
  if (!parsed.success) return {};
  return Object.fromEntries(
    Object.entries(parsed.data.credentials ?? {}).flatMap(([name, c]) => (c.description ? [[name, c.description]] : [])),
  );
}

/** The fields the credential form shows for an installed connector. */
export function connectorCredentialFields(c: ConnectorDto, descriptions: Record<string, string> = {}): CredentialField[] {
  return (c.credentials ?? []).map((cr) => ({
    name: cr.name,
    required: cr.required,
    secret: cr.secret,
    set: cr.set,
    description: descriptions[cr.name],
  }));
}

/**
 * The host a connector's transport reaches, without the scheme, the path or
 * anything that could carry a secret. A host that is itself a credential
 * placeholder is named as such. Null when the transport names no address.
 */
export function targetHost(transport: Record<string, unknown> | undefined): string | null {
  const raw = [transport?.baseUrl, transport?.dsn].find((v): v is string => typeof v === "string" && v.trim() !== "");
  if (!raw) return null;
  const value = raw.trim();
  // A key=value connection string: host=db.example port=5432 …
  const kv = /(?:^|\s)host=([^\s]+)/i.exec(value);
  if (kv) return kv[1];
  // scheme://[userinfo@]host[:port][/…]; the userinfo is dropped whatever
  // it holds.
  const url = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?([^/?#]+)/i.exec(value);
  if (url) return url[1];
  return null;
}

/** Whether a connector signs in through a consent screen a person approves. */
export function authorizesInBrowser(auth: Record<string, unknown> | undefined): boolean {
  return auth?.type === "oauth2" && auth.grant === "authorization_code";
}

/** How a connector signs in, in words. */
export function authLabel(auth: Record<string, unknown> | undefined): string {
  const type = typeof auth?.type === "string" ? auth.type : "none";
  const optional = auth?.optional === true ? ", optional" : "";
  switch (type) {
    case "none":
      return "No sign-in";
    case "apiKey":
      return `An API key${optional}`;
    case "bearer":
      return `A bearer token${optional}`;
    case "basic":
      return `A username and password${optional}`;
    case "query":
      return `Values in the query string${optional}`;
    case "oauth2":
      return auth?.grant === "authorization_code"
        ? `OAuth, approved by a person on the vendor's consent screen${optional}`
        : `OAuth${optional}`;
    case "oauth1":
      return `OAuth 1${optional}`;
    case "login":
      return `A login call that returns a session${optional}`;
    case "hmac":
      return `A signature on every request${optional}`;
    case "database":
      return `A database user${optional}`;
    case "wsSecurity":
      return `WS-Security${optional}`;
    case "mtls":
      return `A client certificate${optional}`;
    default:
      return `${type}${optional}`;
  }
}

/**
 * Whether an OAuth2 connector holds a token, in words, as the server
 * reports it; undefined for a connector that signs in some other way.
 */
export function authorizationLabel(c: Pick<ConnectorDto, "auth" | "oauthAuthorized">): string | undefined {
  if (c.auth?.type !== "oauth2") return undefined;
  return c.oauthAuthorized ? "Authorized" : "Not authorized yet";
}

/**
 * What the server's return from a vendor's consent screen means, in words.
 * The server sends one of a fixed set of codes, never free text, so an
 * unknown one is said as plainly as possible rather than guessed at.
 */
export function consentOutcome(code: string): string {
  switch (code) {
    case "expired":
      return "The approval took too long or was started elsewhere. Authorize again.";
    case "no_refresh_token":
      return "The vendor approved access but sent no refresh token, so the connection would stop working within the hour. Check that the app registered with the vendor asks for offline access, then authorize again.";
    case "vendor_refused":
      return "The vendor refused the request. Check the client ID and secret, and the redirect address registered with the vendor.";
    case "not_supported":
      return "This connector does not sign in through a consent screen.";
    case "unavailable":
      return "This connector no longer exists.";
    default:
      return "Connecting failed. The workspace's audit log records the request.";
  }
}

/** What is said when the vendor approved access. */
export const consentConnected = "Connected. The vendor approved access, and the workspace now holds the tokens.";

/**
 * The address parameter a return from a vendor's consent screen carries:
 * `oauth`, "ok" or the server's code for why not.
 */
export interface ConsentSearch {
  oauth?: string;
}

/** The consent-return parameter out of an address's search, checked. */
export function consentSearch(search: Record<string, unknown>): ConsentSearch {
  return typeof search.oauth === "string" && search.oauth !== "" ? { oauth: search.oauth } : {};
}

/** How a consent return went: "ok", the server's code for why not, or null when there was none. */
export function consentResult(search: ConsentSearch): string | null {
  return search.oauth ?? null;
}

/**
 * The sentences behind the badges on connectors and their tools, shown
 * in a tooltip where the badge has room for a word or two.
 */
export const badgeWhy = {
  catalogOutdated: "A newer version of the catalog adapter is available; compare the two on the connector's page.",
  credentialsMissing: "Some credentials this connector needs are not stored yet; add them on its page.",
  edited: "Someone changed this tool's definition by hand; a catalog re-sync leaves it alone.",
  off: "Switched off: the tool stays here but is not offered to clients.",
} as const;
