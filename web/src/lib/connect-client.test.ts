import { describe, expect, it } from "vitest";
import {
  claudeDesktopSnippet,
  clientSnippets,
  curlSnippet,
  cursorSnippet,
  endpointURL,
  keyPlaceholder,
  protocolVersion,
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

describe("clientSnippets", () => {
  it("offers Claude Desktop, Cursor and curl, each carrying the endpoint", () => {
    const all = clientSnippets({ url, name: "support-desk" });
    expect(all.map((s) => s.label)).toEqual(["Claude Desktop", "Cursor", "curl"]);
    for (const s of all) {
      expect(s.text).toContain(url);
      expect(s.text).toContain(keyPlaceholder);
    }
    expect(all[0].note).toMatch(/mcp-remote/);
  });
});
