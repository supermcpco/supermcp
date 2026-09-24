/**
 * Drives the legacy v1 REST engine with a stubbed transport and records
 * the request it would have sent. The Go parity test replays the same
 * inputs and compares, which is how we know the rewrite speaks the same
 * wire protocol as the system it replaces.
 */
import axios from 'axios';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { RestEngine } from '../connectors/engines/rest.engine';

type Case = {
  adapter: string;
  tool: string;
  params: Record<string, unknown>;
  env: Record<string, string>;
};

const captured: any[] = [];
// Replace the transport, not the module: axios calls its adapter last,
// after the config is fully built, which is exactly what we want to see.
(axios as any).defaults.adapter = (config: any) => {
  captured.push(config);
  return Promise.resolve({ status: 200, statusText: 'OK', data: {}, headers: {}, config });
};

const CORPUS = process.argv[2];
const OUT = process.argv[3];
const engine = new RestEngine({} as any, {} as any);

// Values substituted for any env var an adapter references, so the
// rendered request is deterministic on both sides.
const envValue = (name: string) => `env-${name}`;

function sampleFor(schema: any, name: string): unknown {
  const type = schema?.type;
  if (schema?.default !== undefined) return schema.default;
  if (Array.isArray(schema?.enum) && schema.enum.length) return schema.enum[0];
  switch (type) {
    case 'integer': return 7;
    case 'number': return 2.5;
    case 'boolean': return true;
    case 'array': return ['a', 'b'];
    case 'object': return { k: 'v' };
    default: return `val-${name}`;
  }
}

const out: any[] = [];
async function main() {
for (const region of readdirSync(CORPUS, { withFileTypes: true }).filter((d) => d.isDirectory())) {
  for (const file of readdirSync(join(CORPUS, region.name)).filter((f) => f.endsWith('.json'))) {
    const adapter = JSON.parse(readFileSync(join(CORPUS, region.name, file), 'utf8'));
    if (adapter.connector?.type !== 'REST') continue;
    const env: Record<string, string> = {};
    for (const name of [...(adapter.requiredEnvVars ?? []), ...(adapter.optionalEnvVars ?? [])]) env[name] = envValue(name);
    for (const tool of adapter.tools) {
      const m = tool.endpointMapping;
      if (!m || m.method === 'static') continue;
      const params: Record<string, unknown> = {};
      for (const [name, schema] of Object.entries<any>(tool.parameters?.properties ?? {})) {
        params[name] = sampleFor(schema, name);
      }
      // Env vars are merged into params by the caller in production.
      Object.assign(params, env);
      captured.length = 0;
      try {
        await engine.execute(
          { baseUrl: interpolate(adapter.connector.baseUrl, env), authType: 'NONE', headers: interpolateAll(adapter.connector.headers, env) },
          interpolateMapping(m, env),
          params,
        );
      } catch (e: any) {
        out.push({ adapter: adapter.slug, tool: tool.name, error: String(e?.message ?? e) });
        continue;
      }
      const c = captured[0];
      if (!c) continue;
      out.push({
        adapter: adapter.slug,
        tool: tool.name,
        method: String(c.method ?? 'GET').toUpperCase(),
        url: c.url,
        query: serializeParams(c),
        headers: lower(c.headers ?? {}),
        body: renderBody(c.data),
        params,
        env,
      });
    }
  }
}
}
main().then(() => {
  writeFileSync(OUT, JSON.stringify(out, null, 1));
  console.log(`wrote ${out.length} cases`);
}).catch((e) => { console.error(e); process.exit(1); });

function serializeParams(c: any): string {
  const params = c.params ?? {};
  const ser = c.paramsSerializer;
  if (typeof ser === 'function') return ser(params);
  if (ser && typeof ser.serialize === 'function') return ser.serialize(params);
  return new URLSearchParams(params).toString();
}

function interpolate(s: string, env: Record<string, string>): string {
  return String(s ?? '').replace(/\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g, (m, n) => (n in env ? env[n] : m));
}
function interpolateAll(o: any, env: Record<string, string>): any {
  if (!o) return o;
  const out: any = {};
  for (const [k, v] of Object.entries(o)) out[k] = typeof v === 'string' ? interpolate(v, env) : v;
  return out;
}
function interpolateMapping(m: any, env: Record<string, string>): any {
  return JSON.parse(interpolate(JSON.stringify(m), env));
}
function lower(h: any): Record<string, string> {
  const out: Record<string, string> = {};
  const plain = h && typeof h.toJSON === 'function' ? h.toJSON() : h;
  for (const [k, v] of Object.entries(plain ?? {})) {
    if (v === undefined || v === null || typeof v === 'object') continue;
    out[k.toLowerCase()] = String(v);
  }
  return out;
}
function renderBody(d: any): string {
  if (d === undefined || d === null) return '';
  if (typeof d === 'string') return d;
  return JSON.stringify(d);
}
