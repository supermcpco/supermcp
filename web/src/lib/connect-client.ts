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

export type ClientId =
  | "claude-code"
  | "cursor"
  | "vscode"
  | "windsurf"
  | "zed"
  | "jetbrains"
  | "codex"
  | "gemini"
  | "claude-desktop"
  | "chatgpt"
  | "curl"
  | "generic";

/** The headings the picker sorts clients under, in the order it shows them. */
export const clientGroups = ["Coding assistants", "Desktop apps", "Other"] as const;
export type ClientGroup = (typeof clientGroups)[number];

export interface ClientSnippet {
  id: ClientId;
  /** The client, as its maker writes it. */
  label: string;
  group: ClientGroup;
  /**
   * One line on where the text goes. Paths and commands are in
   * backticks, so the panel can set them in code type.
   */
  where: string;
  /** One line a person needs before pasting, if any. */
  note?: string;
  /** The maker's page on the format. */
  docs?: string;
  /**
   * How the client gets the key when the text does not carry it: VS Code
   * prompts for it, Codex reads it from the environment. Unset when the
   * text carries the key (or its placeholder) itself.
   */
  keyFrom?: "prompt" | "env";
  /**
   * Set when the format was written from memory of the maker's docs and
   * not checked against their current version: the panel says so.
   */
  unchecked?: boolean;
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

/**
 * Claude Code adds the server itself: one command, the transport, the
 * name, the URL and the header, in the order its docs give them.
 */
export function claudeCodeSnippet(t: SnippetTarget): string {
  return `claude mcp add --transport http ${configName(t.name)} ${t.url} --header "Authorization: ${bearer(t)}"`;
}

/** The id of the input VS Code prompts for the key with. */
export const vscodeInputId = "api-token";

/**
 * VS Code (Copilot's agent mode) keeps servers under `servers`, each with
 * its transport named. The key is not written into the file: VS Code's
 * docs recommend an input, which it prompts for once and keeps in its
 * secret storage. So even a key just issued stays out of the text.
 */
export function vscodeSnippet(t: SnippetTarget): string {
  return JSON.stringify(
    {
      inputs: [{ type: "promptString", id: vscodeInputId, description: keyPlaceholder, password: true }],
      servers: {
        [configName(t.name)]: {
          type: "http",
          url: t.url,
          headers: { Authorization: `Bearer \${input:${vscodeInputId}}` },
        },
      },
    },
    null,
    2,
  );
}

/** Windsurf calls the address of a remote server `serverUrl`. */
export function windsurfSnippet(t: SnippetTarget): string {
  return JSON.stringify(
    {
      mcpServers: {
        [configName(t.name)]: {
          serverUrl: t.url,
          headers: { Authorization: bearer(t) },
        },
      },
    },
    null,
    2,
  );
}

/** Zed lists servers under `context_servers` in its settings; a remote one by URL. */
export function zedSnippet(t: SnippetTarget): string {
  return JSON.stringify(
    {
      context_servers: {
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

/**
 * JetBrains AI Assistant: VS Code's `servers` shape, with the key written
 * in, since the dialog has no inputs to prompt with. Its docs could not be
 * checked, so the panel says so.
 */
export function jetbrainsSnippet(t: SnippetTarget): string {
  return JSON.stringify(
    {
      servers: {
        [configName(t.name)]: {
          type: "http",
          url: t.url,
          headers: { Authorization: bearer(t) },
        },
      },
    },
    null,
    2,
  );
}

/** A TOML string: the JSON escapes of a basic string are TOML's too. */
function tomlString(s: string): string {
  return JSON.stringify(s);
}

/** The environment variable Codex reads the key from. */
export const codexKeyEnv = "SUPERMCP_KEY";

/**
 * Codex keeps servers in TOML, one table each; a remote one by URL. The
 * key comes from an environment variable, which Codex sends as the
 * bearer token, so it is not written into the file.
 */
export function codexSnippet(t: SnippetTarget): string {
  return [
    `[mcp_servers.${configName(t.name)}]`,
    `url = ${tomlString(t.url)}`,
    `bearer_token_env_var = ${tomlString(codexKeyEnv)}`,
  ].join("\n");
}

/**
 * Gemini CLI tells streamable HTTP (`httpUrl`) from SSE (`url`) by the
 * key's name. It does not take underscores in a server's name.
 */
export function geminiSnippet(t: SnippetTarget): string {
  return JSON.stringify(
    {
      mcpServers: {
        [configName(t.name).replace(/_/g, "-")]: {
          httpUrl: t.url,
          headers: { Authorization: bearer(t) },
        },
      },
    },
    null,
    2,
  );
}

/**
 * The OpenAI Responses API calls a remote MCP server as a tool of the
 * request; `authorization` is its documented field for a bearer token,
 * and takes the key alone. ChatGPT's own connectors do not take a key;
 * the panel says what to do there instead.
 */
export function openaiSnippet(t: SnippetTarget): string {
  return JSON.stringify(
    {
      tools: [
        {
          type: "mcp",
          server_label: configName(t.name),
          server_url: t.url,
          authorization: t.secret || keyPlaceholder,
          require_approval: "never",
        },
      ],
    },
    null,
    2,
  );
}

/** The shape most clients that speak streamable HTTP read, for one this panel does not name. */
export function genericSnippet(t: SnippetTarget): string {
  return JSON.stringify(
    {
      mcpServers: {
        [configName(t.name)]: {
          type: "http",
          url: t.url,
          headers: { Authorization: bearer(t) },
        },
      },
    },
    null,
    2,
  );
}

/** Every client the panel offers, grouped, in the order it shows them. */
export function clientSnippets(t: SnippetTarget): ClientSnippet[] {
  return [
    {
      id: "claude-code",
      label: "Claude Code",
      group: "Coding assistants",
      where:
        "Run in a terminal in your project. It adds the server for this project; add `--scope user` for every project, or `--scope project` to share it in `.mcp.json`.",
      docs: "https://code.claude.com/docs/en/mcp",
      text: claudeCodeSnippet(t),
    },
    {
      id: "cursor",
      label: "Cursor",
      group: "Coding assistants",
      where: "Paste into `.cursor/mcp.json` in your project, or `~/.cursor/mcp.json` for every project.",
      docs: "https://cursor.com/docs/context/mcp",
      text: cursorSnippet(t),
    },
    {
      id: "vscode",
      label: "VS Code (GitHub Copilot)",
      group: "Coding assistants",
      where:
        "Paste into `.vscode/mcp.json` in your workspace, or into the file MCP: Open User Configuration opens, for every workspace.",
      note: "VS Code asks for the key the first time it starts the server and keeps it in its secret storage; Copilot Chat uses the server in agent mode.",
      keyFrom: "prompt",
      docs: "https://code.visualstudio.com/docs/copilot/customization/mcp-servers",
      text: vscodeSnippet(t),
    },
    {
      id: "windsurf",
      label: "Windsurf",
      group: "Coding assistants",
      where:
        "Paste into `~/.config/devin/mcp_config.json`, where current Windsurf keeps it, or `~/.codeium/windsurf/mcp_config.json`, the classic path; then refresh the MCP servers in Cascade.",
      docs: "https://docs.windsurf.com/windsurf/cascade/mcp",
      text: windsurfSnippet(t),
    },
    {
      id: "zed",
      label: "Zed",
      group: "Coding assistants",
      where: "Add to `context_servers` in Zed's `settings.json`: `~/.config/zed/settings.json` on macOS and Linux.",
      docs: "https://zed.dev/docs/ai/mcp",
      text: zedSnippet(t),
    },
    {
      id: "jetbrains",
      label: "JetBrains AI Assistant",
      group: "Coding assistants",
      where: "In Settings, Tools, AI Assistant, MCP, add a server and paste this in as JSON.",
      unchecked: true,
      text: jetbrainsSnippet(t),
    },
    {
      id: "codex",
      label: "OpenAI Codex CLI",
      group: "Coding assistants",
      where:
        "Add to `~/.codex/config.toml`, or `.codex/config.toml` in a project; the Codex IDE extension reads the same file.",
      note: "Codex reads the key from SUPERMCP_KEY: export it in the shell that starts Codex. To write the key into the file instead, replace the last line with http_headers = { \"Authorization\" = \"Bearer <key>\" }.",
      docs: "https://developers.openai.com/codex/mcp",
      keyFrom: "env",
      text: codexSnippet(t),
    },
    {
      id: "gemini",
      label: "Gemini CLI",
      group: "Coding assistants",
      where: "Add to `~/.gemini/settings.json`, or `.gemini/settings.json` in a project. No underscores in the server's name.",
      docs: "https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md",
      text: geminiSnippet(t),
    },
    {
      id: "claude-desktop",
      label: "Claude Desktop",
      group: "Desktop apps",
      where: "Paste into `claude_desktop_config.json`: Settings, Developer, Edit Config.",
      note: "Claude Desktop's config file only starts local programs, so it reaches this server through mcp-remote, which needs Node.js.",
      docs: "https://modelcontextprotocol.io/docs/develop/connect-local-servers",
      text: claudeDesktopSnippet(t),
    },
    {
      id: "chatgpt",
      label: "ChatGPT and the OpenAI API",
      group: "Desktop apps",
      where: "Send as the `tools` of an OpenAI Responses API request.",
      note: "In the ChatGPT app the key is not used: its connectors sign in with OAuth 2.1 only, and this server is an OAuth provider. Turn on Developer mode and add the endpoint as a connector by its URL; ChatGPT then signs in to this workspace.",
      docs: "https://platform.openai.com/docs/guides/tools-connectors-mcp",
      text: openaiSnippet(t),
    },
    {
      id: "curl",
      label: "curl",
      group: "Other",
      where: "Run in a terminal; the answer names the server and its capabilities.",
      text: curlSnippet(t),
    },
    {
      id: "generic",
      label: "Other client (JSON)",
      group: "Other",
      where:
        "For a client this list does not name: most that speak streamable HTTP read this shape, some under another key or with `url` named differently.",
      text: genericSnippet(t),
    },
  ];
}

/** The client picked when nothing was remembered. */
export const defaultClient: ClientId = "claude-code";

/** Where the last client picked is kept between visits. Not a secret: only which client. */
export const clientStorageKey = "supermcp.connect-client";

const clientIds: readonly string[] = [
  "claude-code",
  "cursor",
  "vscode",
  "windsurf",
  "zed",
  "jetbrains",
  "codex",
  "gemini",
  "claude-desktop",
  "chatgpt",
  "curl",
  "generic",
] satisfies ClientId[];

export function isClientId(v: unknown): v is ClientId {
  return typeof v === "string" && clientIds.includes(v);
}

type ClientStorage = Pick<Storage, "getItem" | "setItem">;

function browserStorage(): ClientStorage | undefined {
  return typeof window === "undefined" ? undefined : window.localStorage;
}

/**
 * The client picked last, or the default when there is none, it is one
 * this version no longer offers, or storage cannot be read.
 */
export function readClient(storage: () => ClientStorage | undefined = browserStorage): ClientId {
  try {
    const v = storage()?.getItem(clientStorageKey);
    return isClientId(v) ? v : defaultClient;
  } catch {
    return defaultClient;
  }
}

/** Remembers the pick; a refusal to store it only costs the memory. */
export function storeClient(id: ClientId, storage: () => ClientStorage | undefined = browserStorage): void {
  try {
    storage()?.setItem(clientStorageKey, id);
  } catch {
    // Nothing to do: the picker still works, it just forgets.
  }
}
