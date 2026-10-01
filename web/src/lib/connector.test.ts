import { describe, expect, it } from "vitest";
import {
  authBadge,
  authorizationLabel,
  authorizesInBrowser,
  consentResult,
  consentSearch,
  credentialDescriptions,
  filled,
  parseAdapter,
  stillNeeded,
  targetHost,
  toolEffect,
  toolMatches,
  toolParameters,
} from "./connector";

describe("stillNeeded", () => {
  const fields = [
    { name: "API_URL", required: true, secret: false },
    { name: "API_KEY", required: true, secret: true, set: true },
    { name: "REGION", required: false, secret: false },
  ];

  it("names required credentials the connector lacks and nobody typed", () => {
    expect(stillNeeded(fields, {})).toEqual(["API_URL"]);
  });

  it("counts a typed value, but not blank space", () => {
    expect(stillNeeded(fields, { API_URL: "https://x.test" })).toEqual([]);
    expect(stillNeeded(fields, { API_URL: "   " })).toEqual(["API_URL"]);
  });
});

describe("filled", () => {
  it("drops the fields nobody typed into, so a held value is not cleared", () => {
    expect(filled({ A: "one", B: "", C: "  " })).toEqual({ A: "one" });
  });
});

describe("credentialDescriptions", () => {
  it("reads the adapter's words for each credential", () => {
    expect(
      credentialDescriptions({ credentials: { A: { required: true, description: "From settings" }, B: { required: false } } }),
    ).toEqual({ A: "From settings" });
  });

  it("gives nothing for a document it does not recognise", () => {
    expect(credentialDescriptions({ credentials: "nope" })).toEqual({});
    expect(credentialDescriptions(null)).toEqual({});
  });
});

describe("targetHost", () => {
  it("keeps only the host of a URL", () => {
    expect(targetHost({ type: "http", baseUrl: "https://api.example.test/v1?key=abc" })).toBe("api.example.test");
  });

  it("never prints the userinfo of a connection string", () => {
    expect(targetHost({ type: "database", dsn: "postgres://app:***@db.internal:5432/sales" })).toBe("db.internal:5432");
    expect(targetHost({ type: "database", dsn: "postgres://app:s3cret@db.internal/sales" })).toBe("db.internal"); // gitleaks:allow
  });

  it("reads a key=value connection string", () => {
    expect(targetHost({ type: "database", dsn: "user=app password=*** host=db.internal port=5432" })).toBe("db.internal");
  });

  it("says nothing when there is no address", () => {
    expect(targetHost({ type: "mcp" })).toBeNull();
    expect(targetHost(undefined)).toBeNull();
  });
});

describe("authorizesInBrowser", () => {
  it("is only the authorization-code grant", () => {
    expect(authorizesInBrowser({ type: "oauth2", grant: "authorization_code" })).toBe(true);
    expect(authorizesInBrowser({ type: "oauth2", grant: "refresh_token" })).toBe(false);
    expect(authorizesInBrowser({ type: "bearer" })).toBe(false);
  });
});

describe("authorizationLabel", () => {
  it("says whether an OAuth2 connector holds a token, and nothing for other sign-ins", () => {
    expect(authorizationLabel({ auth: { type: "oauth2", grant: "authorization_code" }, oauthAuthorized: true })).toBe(
      "Authorized",
    );
    expect(authorizationLabel({ auth: { type: "oauth2", grant: "client_credentials" }, oauthAuthorized: false })).toBe(
      "Not authorized yet",
    );
    expect(authorizationLabel({ auth: { type: "apiKey" }, oauthAuthorized: false })).toBeUndefined();
    expect(authorizationLabel({ auth: undefined, oauthAuthorized: false })).toBeUndefined();
  });
});

describe("consent returns", () => {
  it.each([
    [{ oauth: "ok" }, "ok"],
    [{ oauth: "vendor_refused" }, "vendor_refused"],
    // The older names are no longer read.
    [{ connected: "1" }, null],
    [{ connectError: "expired" }, null],
    [{ connect_error: "unavailable" }, null],
    [{}, null],
    [{ oauth: "" }, null],
    [{ oauth: 7, connected: "no" }, null],
  ])("%j -> %s", (search, want) => {
    expect(consentResult(consentSearch(search))).toBe(want);
  });

  it("keeps nothing but the consent parameters", () => {
    expect(consentSearch({ oauth: "ok", tab: "tools" })).toEqual({ oauth: "ok" });
  });
});

describe("parseAdapter", () => {
  const doc = {
    apiVersion: "supermcp.dev/v2",
    metadata: { slug: "bundesbank", name: "Deutsche Bundesbank", description: "Rates", docsUrl: "https://example.test", icon: "x" },
    credentials: { API_KEY: { required: true, secret: true, description: "From the portal" } },
    transport: { type: "http", baseUrl: "https://api.example.test" },
    auth: { type: "apiKey", in: "header", name: "X-Key", value: "{{API_KEY}}" },
    tools: [{ name: "get_rates", description: "Rates", annotations: { readOnlyHint: true }, request: {} }],
  };

  it("reads the parts the catalog page shows", () => {
    const a = parseAdapter(doc);
    expect(a?.metadata.name).toBe("Deutsche Bundesbank");
    expect(a?.credentials?.API_KEY).toEqual({ required: true, secret: true, description: "From the portal" });
    expect(a?.tools).toEqual([{ name: "get_rates", description: "Rates", annotations: { readOnlyHint: true } }]);
    expect(a?.auth).toEqual({ type: "apiKey" });
  });

  it("fills in what an adapter may leave out", () => {
    const a = parseAdapter({ ...doc, tools: [{ name: "t" }], metadata: { slug: "s", name: "n" } });
    expect(a?.tools).toEqual([{ name: "t", description: "" }]);
    expect(a?.metadata.description).toBe("");
    expect(a?.metadata.docsUrl).toBeUndefined();
  });

  it("refuses something that is not an adapter", () => {
    expect(parseAdapter(undefined)).toBeNull();
    expect(parseAdapter({ metadata: { name: "n" } })).toBeNull();
    expect(parseAdapter({ ...doc, tools: "none" })).toBeNull();
  });
});

describe("toolParameters", () => {
  it("lists required parameters first, with their type, choices and default", () => {
    const params = toolParameters({
      input: {
        properties: {
          startPeriod: { type: "string", description: "First period" },
          maturityYears: { type: "string", enum: ["01", "10"], default: "10" },
          ids: { type: "array", items: { type: "integer" } },
        },
        required: ["maturityYears"],
      },
    });
    expect(params.map((p) => p.name)).toEqual(["maturityYears", "startPeriod", "ids"]);
    expect(params[0]).toEqual({
      name: "maturityYears",
      type: "string",
      required: true,
      description: undefined,
      choices: ["01", "10"],
      fallback: "10",
    });
    expect(params[2].type).toBe("array of integer");
  });

  it("keeps a parameter it cannot read, by name, rather than failing the tool", () => {
    expect(toolParameters({ input: { properties: { odd: true } } })).toEqual([{ name: "odd", type: "", required: false }]);
    expect(toolParameters({})).toEqual([]);
  });
});

describe("toolEffect", () => {
  it("reads GET and HEAD, and a POST whose name says it reads", () => {
    expect(toolEffect({ name: "get_rates", operation: { method: "GET" } }, "http")).toBe("reads only");
    expect(toolEffect({ name: "ping", operation: { method: "HEAD" } }, "http")).toBe("reads only");
    expect(toolEffect({ name: "bexio_search_contacts", operation: { method: "POST" } }, "http", "bexio")).toBe("reads only");
    expect(toolEffect({ name: "teamleader_list_companies", operation: { method: "POST" } }, "http", "teamleader")).toBe("reads only");
    expect(toolEffect({ name: "deutsche_bahn_find_station", operation: { method: "POST" } }, "http", "deutsche-bahn")).toBe("reads only");
    expect(toolEffect({ name: "describe_table", operation: { method: "POST" } }, "http")).toBe("reads only");
  });

  it("calls a POST, PUT or PATCH that is not read-shaped a write, never destructive", () => {
    expect(toolEffect({ name: "bexio_create_contact", operation: { method: "POST" } }, "http", "bexio")).toBe("writes");
    expect(toolEffect({ name: "acme_archive_deal", operation: { method: "POST" } }, "http", "acme")).toBe("writes");
    expect(toolEffect({ name: "acme_update_deal", operation: { method: "PUT" } }, "http", "acme")).toBe("writes");
    expect(toolEffect({ name: "acme_rename", operation: { method: "PATCH" } }, "http", "acme")).toBe("writes");
    // The verb has to start the name after the prefix, not appear anywhere in it.
    expect(toolEffect({ name: "acme_reset_list", operation: { method: "POST" } }, "http", "acme")).toBe("writes");
  });

  it("is destructive only for a DELETE", () => {
    expect(toolEffect({ name: "acme_drop", operation: { method: "DELETE" } }, "http", "acme")).toBe("destructive");
    expect(toolEffect({ name: "purge", operation: { kind: "sql", statement: "DELETE FROM t" } }, "database")).toBe("destructive");
  });

  it("reads other transports by their kind", () => {
    expect(toolEffect({ name: "q", operation: { kind: "query" } }, "graphql")).toBe("reads only");
    expect(toolEffect({ name: "add_item", operation: { kind: "mutation" } }, "graphql")).toBe("writes");
    expect(toolEffect({ name: "rows", operation: { kind: "sql", statement: " select 1" } }, "database")).toBe("reads only");
    expect(toolEffect({ name: "touch", operation: { kind: "sql", statement: "UPDATE t SET a = 1" } }, "database")).toBe("writes");
  });

  it("lets the adapter's own hints decide", () => {
    expect(toolEffect({ name: "x_sync", operation: { method: "POST" }, annotations: { readOnlyHint: true } }, "http")).toBe("reads only");
    expect(toolEffect({ name: "x_get", operation: { method: "GET" }, annotations: { readOnlyHint: false } }, "http")).toBe("writes");
    expect(toolEffect({ name: "x_get", operation: { method: "POST" }, annotations: { destructiveHint: true } }, "http")).toBe("destructive");
    expect(toolEffect({ name: "x_drop", operation: { method: "DELETE" }, annotations: { destructiveHint: false } }, "http")).toBe("writes");
  });

  it("gives no badge when nothing can be inferred", () => {
    expect(toolEffect({ name: "acme_call", operation: {} }, "soap", "acme")).toBeNull();
    expect(toolEffect({ name: "acme_call" }, "mcp", "acme")).toBeNull();
    expect(toolEffect({ name: "acme_call", operation: { method: "OPTIONS" } }, "http", "acme")).toBeNull();
    expect(toolEffect({ name: "acme_call", annotations: { idempotentHint: true } }, "mcp", "acme")).toBeNull();
  });
});

describe("authBadge", () => {
  it("says no credentials are needed exactly when none is required", () => {
    expect(authBadge({ type: "none" }, 0)).toBe("No credentials needed");
    expect(authBadge({ type: "apiKey", optional: true }, 0)).toBe("No credentials needed");
    expect(authBadge({ type: "apiKey" }, 2)).toBe("API key");
    expect(authBadge({ type: "oauth2" }, 3)).toBe("OAuth 2.0");
    expect(authBadge({ type: "bearer", optional: true }, 1)).toBe("Bearer (optional)");
  });
});

describe("toolMatches", () => {
  const t = { name: "bexio_list_contacts", description: "List contacts", input: { properties: { order_by: {} } } };
  it("matches the name, the description or a parameter, whatever the case", () => {
    expect(toolMatches(t, "")).toBe(true);
    expect(toolMatches(t, "LIST_CON")).toBe(true);
    expect(toolMatches(t, "order_by")).toBe(true);
    expect(toolMatches(t, "invoice")).toBe(false);
  });
});
