import { describe, expect, it } from "vitest";
import {
  claudeCodeSnippet,
  claudeDesktopSnippet,
  clientGroups,
  clientSnippets,
  clientStorageKey,
  codexSnippet,
  curlSnippet,
  cursorSnippet,
  defaultClient,
  endpointURL,
  geminiSnippet,
  genericSnippet,
  jetbrainsSnippet,
  keyPlaceholder,
  openaiSnippet,
  protocolVersion,
  readClient,
  storeClient,
  vscodeSnippet,
  windsurfSnippet,
  zedSnippet,
} from "./connect-client";

const secret = "smk_0123456789ab_notarealsecretatall"; // gitleaks:allow
const url = "https://mcp.example.com/mcp/9d1f3c1e-8a0b-4a57-9d1b-2b1f0c7f7e11";

describe("endpointURL", () => {
  it("puts the server id under /mcp on the origin", () => {
    expect(endpointURL("https://mcp.example.com", "abc")).toBe("https://mcp.example.com/mcp/abc");
    expect(endpointURL("https://mcp.example.com/", "abc")).toBe("https://mcp.example.com/mcp/abc");
  });
});

describe("claudeDesktopSnippet", () => {
  it("runs mcp-remote against the endpoint with the key as a bearer header", () => {
    const cfg = JSON.parse(claudeDesktopSnippet({ url, name: "support-desk", secret }));
    const entry = cfg.mcpServers["support-desk"];
    expect(entry.command).toBe("npx");
    expect(entry.args).toEqual(["-y", "mcp-remote", url, "--header", "Authorization:${SUPERMCP_AUTH}"]);
    expect(entry.env.SUPERMCP_AUTH).toBe(`Bearer ${secret}`);
  });

  it("uses the placeholder when no secret is in hand", () => {
    const cfg = JSON.parse(claudeDesktopSnippet({ url, name: "support-desk" }));
    expect(cfg.mcpServers["support-desk"].env.SUPERMCP_AUTH).toBe(`Bearer ${keyPlaceholder}`);
  });

  it("allows plain http only when the endpoint is not on this machine", () => {
    const remote = JSON.parse(claudeDesktopSnippet({ url: "http://mcp.internal:8080/mcp/x", name: "a" }));
    expect(remote.mcpServers.a.args).toContain("--allow-http");
    const local = JSON.parse(claudeDesktopSnippet({ url: "http://localhost:8080/mcp/x", name: "a" }));
    expect(local.mcpServers.a.args).not.toContain("--allow-http");
  });

  it("names the entry something a config key can be", () => {
    const cfg = JSON.parse(claudeDesktopSnippet({ url, name: "Support Desk!" }));
    expect(Object.keys(cfg.mcpServers)).toEqual(["support-desk"]);
    const empty = JSON.parse(claudeDesktopSnippet({ url, name: "!!" }));
    expect(Object.keys(empty.mcpServers)).toEqual(["supermcp"]);
  });
});

describe("cursorSnippet", () => {
  it("points Cursor at the URL with an Authorization header", () => {
    const cfg = JSON.parse(cursorSnippet({ url, name: "support-desk", secret }));
    expect(cfg).toEqual({
      mcpServers: { "support-desk": { url, headers: { Authorization: `Bearer ${secret}` } } },
    });
  });
});

describe("curlSnippet", () => {
  it("posts an initialize request to the endpoint with the key", () => {
    const text = curlSnippet({ url, name: "support-desk", secret });
    expect(text).toContain(`curl -X POST '${url}'`);
    expect(text).toContain(`-H 'Authorization: Bearer ${secret}'`);
    expect(text).toContain("-H 'Accept: application/json, text/event-stream'");
    const body = /-d '(.*)'$/m.exec(text)?.[1] ?? "";
    const parsed = JSON.parse(body);
    expect(parsed.method).toBe("initialize");
    expect(parsed.params.protocolVersion).toBe(protocolVersion);
  });
});

describe("claudeCodeSnippet", () => {
  it("adds the server over http with the key as a header", () => {
    expect(claudeCodeSnippet({ url, name: "support-desk", secret })).toBe(
      `claude mcp add --transport http support-desk ${url} --header "Authorization: Bearer ${secret}"`,
    );
  });
});

describe("vscodeSnippet", () => {
  it("puts an http server under servers with the header", () => {
    expect(JSON.parse(vscodeSnippet({ url, name: "support-desk", secret }))).toEqual({
      servers: { "support-desk": { type: "http", url, headers: { Authorization: `Bearer ${secret}` } } },
    });
  });
});

describe("windsurfSnippet", () => {
  it("names the endpoint serverUrl", () => {
    expect(JSON.parse(windsurfSnippet({ url, name: "support-desk", secret }))).toEqual({
      mcpServers: { "support-desk": { serverUrl: url, headers: { Authorization: `Bearer ${secret}` } } },
    });
  });
});

describe("zedSnippet", () => {
  it("puts a remote server under context_servers", () => {
    expect(JSON.parse(zedSnippet({ url, name: "support-desk", secret }))).toEqual({
      context_servers: { "support-desk": { url, headers: { Authorization: `Bearer ${secret}` } } },
    });
  });
});

describe("jetbrainsSnippet", () => {
  it("runs mcp-remote as Claude Desktop does", () => {
    const t = { url, name: "support-desk", secret };
    expect(jetbrainsSnippet(t)).toBe(claudeDesktopSnippet(t));
  });
});

describe("codexSnippet", () => {
  it("writes a TOML table with the url and the header", () => {
    const lines = codexSnippet({ url, name: "support-desk", secret }).split("\n");
    expect(lines).toContain("[mcp_servers.support-desk]");
    expect(lines).toContain(`url = "${url}"`);
    expect(lines).toContain(`http_headers = { "Authorization" = "Bearer ${secret}" }`);
    expect(lines[0]).toMatch(/^# Check against the vendor's docs/);
  });
});

describe("geminiSnippet", () => {
  it("names a streamable HTTP endpoint httpUrl", () => {
    expect(JSON.parse(geminiSnippet({ url, name: "support-desk", secret }))).toEqual({
      mcpServers: { "support-desk": { httpUrl: url, headers: { Authorization: `Bearer ${secret}` } } },
    });
  });
});

describe("openaiSnippet", () => {
  it("passes the endpoint and the header as a Responses API mcp tool", () => {
    const cfg = JSON.parse(openaiSnippet({ url, name: "support-desk", secret }));
    expect(cfg.tools).toEqual([
      {
        type: "mcp",
        server_label: "support-desk",
        server_url: url,
        headers: { Authorization: `Bearer ${secret}` },
        require_approval: "never",
      },
    ]);
  });
});

describe("genericSnippet", () => {
  it("gives the common mcpServers shape", () => {
    expect(JSON.parse(genericSnippet({ url, name: "support-desk", secret }))).toEqual({
      mcpServers: { "support-desk": { type: "http", url, headers: { Authorization: `Bearer ${secret}` } } },
    });
  });
});

describe("clientSnippets", () => {
  const labels = [
    "Claude Code",
    "Cursor",
    "VS Code (GitHub Copilot)",
    "Windsurf",
    "Zed",
    "JetBrains AI Assistant",
    "OpenAI Codex CLI",
    "Gemini CLI",
    "Claude Desktop",
    "ChatGPT and the OpenAI API",
    "curl",
    "Other client (JSON)",
  ];

  it("offers every client, grouped in the order the picker shows them", () => {
    const all = clientSnippets({ url, name: "support-desk" });
    expect(all.map((s) => s.label)).toEqual(labels);
    const grouped = clientGroups.flatMap((g) => all.filter((s) => s.group === g).map((s) => s.label));
    expect(grouped).toEqual(labels);
    expect(all.filter((s) => s.group === "Desktop apps").map((s) => s.id)).toEqual(["claude-desktop", "chatgpt"]);
    expect(all.filter((s) => s.group === "Other").map((s) => s.id)).toEqual(["curl", "generic"]);
    expect(new Set(all.map((s) => s.id)).size).toBe(all.length);
  });

  for (const [i, label] of labels.entries()) {
    describe(label, () => {
      it("carries the endpoint and the placeholder when no secret is in hand", () => {
        const s = clientSnippets({ url, name: "support-desk" })[i];
        expect(s.text).toContain(url);
        expect(s.text).toContain(keyPlaceholder);
        expect(s.text).not.toContain("smk_");
        expect(s.where.length).toBeGreaterThan(0);
        expect(s.where).not.toContain("\n");
      });

      it("carries the secret, and not the placeholder, when one was just issued", () => {
        const s = clientSnippets({ url, name: "support-desk", secret })[i];
        expect(s.text).toContain(url);
        expect(s.text).toContain(`Bearer ${secret}`);
        expect(s.text).not.toContain(keyPlaceholder);
      });
    });
  }

  it("says which clients reach the server through mcp-remote, and that ChatGPT's connectors need OAuth", () => {
    const all = clientSnippets({ url, name: "support-desk" });
    const by = (id: string) => all.find((s) => s.id === id);
    expect(by("claude-desktop")?.note).toMatch(/mcp-remote/);
    expect(by("jetbrains")?.note).toMatch(/mcp-remote/);
    expect(by("chatgpt")?.note).toMatch(/OAuth/);
  });
});

describe("remembered client", () => {
  function memory(initial: Record<string, string> = {}) {
    const m = new Map(Object.entries(initial));
    return {
      getItem: (k: string) => m.get(k) ?? null,
      setItem: (k: string, v: string) => void m.set(k, v),
    };
  }

  it("starts at Claude Code", () => {
    expect(defaultClient).toBe("claude-code");
    expect(readClient(() => memory())).toBe("claude-code");
    expect(readClient(() => undefined)).toBe("claude-code");
  });

  it("reads back what was stored", () => {
    const s = memory();
    storeClient("vscode", () => s);
    expect(s.getItem(clientStorageKey)).toBe("vscode");
    expect(readClient(() => s)).toBe("vscode");
  });

  it("falls back when the stored value is not a client this version offers", () => {
    expect(readClient(() => memory({ [clientStorageKey]: "netscape" }))).toBe("claude-code");
  });

  it("survives storage that refuses", () => {
    const refusing = {
      getItem: () => {
        throw new Error("denied");
      },
      setItem: () => {
        throw new Error("denied");
      },
    };
    expect(readClient(() => refusing)).toBe("claude-code");
    expect(() => storeClient("zed", () => refusing)).not.toThrow();
  });
});
