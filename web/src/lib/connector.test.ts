import { describe, expect, it } from "vitest";
import type { InvocationDto } from "../api";
import {
  authorizesInBrowser,
  callsTo,
  consentResult,
  consentSearch,
  credentialDescriptions,
  filled,
  lastFailure,
  parseAdapter,
  stillNeeded,
  targetHost,
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

describe("calls of one connector", () => {
  const call = (id: string, toolName: string, status = "success"): InvocationDto => ({
    id,
    toolName,
    status,
    durationMs: 10,
    createdAt: "2026-09-28T10:00:00Z",
  });
  const recent = [call("1", "a"), call("2", "other"), call("3", "b", "error"), call("4", "a"), call("5", "b", "timeout")];
  const mine = new Set(["a", "b"]);

  it("keeps only calls to its tools, newest first, up to the limit", () => {
    expect(callsTo(recent, mine, 3).map((c) => c.id)).toEqual(["1", "3", "4"]);
  });

  it("finds the newest failure", () => {
    expect(lastFailure(recent, mine)?.id).toBe("3");
    expect(lastFailure([call("1", "a")], mine)).toBeUndefined();
  });
});

describe("consent returns", () => {
  it.each([
    [{ oauth: "ok" }, "ok"],
    [{ oauth: "vendor_refused" }, "vendor_refused"],
    // The older names, read for one more release.
    [{ connected: "1" }, "ok"],
    [{ connected: true }, "ok"],
    [{ connectError: "expired" }, "expired"],
    [{ connect_error: "unavailable" }, "unavailable"],
    [{ connected: "1", connect_error: "vendor_refused" }, "vendor_refused"],
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
