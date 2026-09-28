import { z } from "zod";
import type { ConnectorDto, InvocationDto } from "../api";

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

// The part of a catalog adapter document the credential form reads. The
// document is described by a published JSON Schema rather than the API's,
// so it is checked here instead of trusted.
const adapterCredentials = z.object({
  credentials: z
    .record(
      z.string(),
      z.object({ required: z.boolean().optional(), secret: z.boolean().optional(), description: z.string().optional() }),
    )
    .optional(),
});

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
 * The calls among `recent` that went to one of `toolNames`, newest first.
 * The list of calls names the tool but not its connector, so a tool of the
 * same name on another connector would be counted here too.
 */
export function callsTo(recent: readonly InvocationDto[], toolNames: ReadonlySet<string>, limit = 5): InvocationDto[] {
  return recent.filter((c) => toolNames.has(c.toolName)).slice(0, limit);
}

/** The newest failed call among `recent` that went to one of `toolNames`. */
export function lastFailure(recent: readonly InvocationDto[], toolNames: ReadonlySet<string>): InvocationDto | undefined {
  return recent.find((c) => toolNames.has(c.toolName) && c.status !== "success");
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
