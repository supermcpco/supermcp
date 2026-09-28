// What a person pastes into an AI client to reach one MCP server. Kept
// apart from the component so the exact text can be tested: a snippet
// that is wrong by one character fails in someone else's program, where
// nobody sees why.

/** Stands in for the secret everywhere it is not in hand. */
export const keyPlaceholder = "<your API key>";

/** The protocol version the curl example opens a session with. */
export const protocolVersion = "2025-06-18";

export interface SnippetTarget {
  /** The streamable HTTP endpoint: origin + /mcp/{server id}. */
  url: string;
  /** What the client calls the server in its config; the server's slug. */
  name: string;
  /** The API key secret, when one was just issued; the placeholder otherwise. */
  secret?: string;
}

export type ClientId = "claude-desktop" | "cursor" | "curl";

export interface ClientSnippet {
  id: ClientId;
  /** The client, as its maker writes it. */
  label: string;
  /** Where the text goes. */
  where: string;
  /** One line a person needs before pasting, if any. */
  note?: string;
  text: string;
}

/** The endpoint a server answers on. */
export function endpointURL(origin: string, serverId: string): string {
  return `${origin.replace(/\/+$/, "")}/mcp/${serverId}`;
}

function bearer(t: SnippetTarget): string {
  return `Bearer ${t.secret || keyPlaceholder}`;
}

// The key a server goes under in a client's mcpServers map. The slug is
// already lower-case and dashed; anything else is made so, and an empty
// result falls back to a name that still works.
function configName(name: string): string {
  const n = name
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return n || "supermcp";
}

// mcp-remote refuses plain http except to the machine it runs on; a
// deployment reached over http elsewhere needs it said out loud.
function needsAllowHTTP(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  } catch {
    return false;
  }
}

/**
 * Claude Desktop's config only starts local programs, so the entry runs
 * mcp-remote, which speaks streamable HTTP to the server. The header is
 * passed through an environment variable, as mcp-remote documents, so
 * the space in "Bearer …" survives being an argument on every platform.
 */
export function claudeDesktopSnippet(t: SnippetTarget): string {
  const args = ["-y", "mcp-remote", t.url, "--header", "Authorization:${SUPERMCP_AUTH}"];
  if (needsAllowHTTP(t.url)) args.push("--allow-http");
  return JSON.stringify(
    {
      mcpServers: {
        [configName(t.name)]: {
          command: "npx",
          args,
          env: { SUPERMCP_AUTH: bearer(t) },
        },
      },
    },
    null,
    2,
  );
}

/** Cursor reaches a streamable HTTP server directly, headers and all. */
export function cursorSnippet(t: SnippetTarget): string {
  return JSON.stringify(
    {
      mcpServers: {
        [configName(t.name)]: {
          url: t.url,
          headers: { Authorization: bearer(t) },
        },
      },
    },
    null,
    2,
  );
}

/** The first request any client sends, to check the endpoint and key by hand. */
export function curlSnippet(t: SnippetTarget): string {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion, capabilities: {}, clientInfo: { name: "curl", version: "1.0" } },
  });
  return [
    `curl -X POST '${t.url}' \\`,
    `  -H 'Authorization: ${bearer(t)}' \\`,
    `  -H 'Content-Type: application/json' \\`,
    `  -H 'Accept: application/json, text/event-stream' \\`,
    `  -d '${body}'`,
  ].join("\n");
}

/** Every client the panel offers, in the order it shows them. */
export function clientSnippets(t: SnippetTarget): ClientSnippet[] {
  return [
    {
      id: "claude-desktop",
      label: "Claude Desktop",
      where: "claude_desktop_config.json",
      note: "Claude Desktop's config file only starts local programs, so it reaches this server through mcp-remote, which needs Node.js.",
      text: claudeDesktopSnippet(t),
    },
    { id: "cursor", label: "Cursor", where: ".cursor/mcp.json", text: cursorSnippet(t) },
    { id: "curl", label: "curl", where: "A terminal", text: curlSnippet(t) },
  ];
}
