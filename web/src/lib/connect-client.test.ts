import { describe, expect, it } from "vitest";
import {
  claudeCodeSnippet,
  claudeDesktopSnippet,
  clientGroups,
  clientSnippets,
  clientStorageKey,
  codexKeyEnv,
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
  vscodeInputId,
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
  it("puts an http server under servers, its key from a password input", () => {
    expect(JSON.parse(vscodeSnippet({ url, name: "support-desk", secret }))).toEqual({
      inputs: [{ type: "promptString", id: vscodeInputId, description: keyPlaceholder, password: true }],
      servers: {
        "support-desk": { type: "http", url, headers: { Authorization: `Bearer \${input:${vscodeInputId}}` } },
      },
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
  it("uses VS Code's servers shape with the key written in", () => {
    expect(JSON.parse(jetbrainsSnippet({ url, name: "support-desk", secret }))).toEqual({
      servers: { "support-desk": { type: "http", url, headers: { Authorization: `Bearer ${secret}` } } },
    });
  });
});

describe("codexSnippet", () => {
  it("writes a TOML table with the url and the key's environment variable", () => {
    expect(codexSnippet({ url, name: "support-desk", secret }).split("\n")).toEqual([
      "[mcp_servers.support-desk]",
      `url = "${url}"`,
      `bearer_token_env_var = "${codexKeyEnv}"`,
    ]);
    expect(codexKeyEnv).toBe("SUPERMCP_KEY");
  });
});

describe("geminiSnippet", () => {
  it("names a streamable HTTP endpoint httpUrl", () => {
    expect(JSON.parse(geminiSnippet({ url, name: "support-desk", secret }))).toEqual({
      mcpServers: { "support-desk": { httpUrl: url, headers: { Authorization: `Bearer ${secret}` } } },
    });
  });

  it("keeps underscores out of the server's name", () => {
    const cfg = JSON.parse(geminiSnippet({ url, name: "support_desk" }));
    expect(Object.keys(cfg.mcpServers)).toEqual(["support-desk"]);
  });
});

describe("openaiSnippet", () => {
  it("passes the endpoint and the key as a Responses API mcp tool's authorization", () => {
    const cfg = JSON.parse(openaiSnippet({ url, name: "support-desk", secret }));
    expect(cfg.tools).toEqual([
      {
        type: "mcp",
        server_label: "support-desk",
        server_url: url,
        authorization: secret,
        require_approval: "never",
      },
    ]);
    const bare = JSON.parse(openaiSnippet({ url, name: "support-desk" }));
    expect(bare.tools[0].authorization).toBe(keyPlaceholder);
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
      const bare = clientSnippets({ url, name: "support-desk" })[i];
      const issued = clientSnippets({ url, name: "support-desk", secret })[i];

      it("carries the endpoint and no secret when none is in hand", () => {
        expect(bare.text).toContain(url);
        expect(bare.text).not.toContain("smk_");
        expect(bare.where.length).toBeGreaterThan(0);
        expect(bare.where).not.toContain("\n");
      });

      if (bare.keyFrom === "env") {
        it("keeps the key out of the text, and says where it comes from", () => {
          expect(bare.text).not.toContain(keyPlaceholder);
          expect(issued.text).toBe(bare.text);
          expect(issued.note).toContain(codexKeyEnv);
        });
      } else if (bare.keyFrom === "prompt") {
        it("prompts for the key, naming it with the placeholder, and never writes the secret", () => {
          expect(bare.text).toContain(keyPlaceholder);
          expect(issued.text).toBe(bare.text);
          expect(issued.note).toMatch(/asks for the key/);
        });
      } else {
        it("carries the placeholder when no secret is in hand", () => {
          expect(bare.text).toContain(keyPlaceholder);
        });

        it("carries the secret, and not the placeholder, when one was just issued", () => {
          expect(issued.text).toContain(url);
          expect(issued.text).toContain(secret);
          expect(issued.text).not.toContain(keyPlaceholder);
        });
      }
    });
  }

  it("takes the key from somewhere else only for VS Code and Codex", () => {
    const all = clientSnippets({ url, name: "support-desk" });
    expect(all.filter((s) => s.keyFrom).map((s) => [s.id, s.keyFrom])).toEqual([
      ["vscode", "prompt"],
      ["codex", "env"],
    ]);
  });

  it("flags only JetBrains as not checked against its vendor's docs", () => {
    const all = clientSnippets({ url, name: "support-desk" });
    expect(all.filter((s) => s.unchecked).map((s) => s.id)).toEqual(["jetbrains"]);
  });

  it("says which notes a person needs before pasting", () => {
    const all = clientSnippets({ url, name: "support-desk" });
    const by = (id: string) => all.find((s) => s.id === id);
    expect(by("claude-desktop")?.note).toMatch(/mcp-remote/);
    expect(by("chatgpt")?.note).toMatch(/OAuth 2\.1/);
    expect(by("chatgpt")?.note).toMatch(/key is not used/);
    expect(by("windsurf")?.where).toContain("~/.config/devin/mcp_config.json");
    expect(by("windsurf")?.where).toContain("~/.codeium/windsurf/mcp_config.json");
    expect(by("gemini")?.where).toMatch(/No underscores/);
    expect(by("codex")?.where).toContain(".codex/config.toml");
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
