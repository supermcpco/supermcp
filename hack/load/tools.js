// k6 load test for the MCP endpoint.
//
// What it measures is the overhead this gateway adds to a tool call, not
// how fast someone else's API is. Every iteration calls the stub directly
// and then calls the same stub through the gateway, and records the
// difference. A number taken from the gateway alone would move whenever
// the upstream moved, and would tell an operator nothing about us.
//
// See README.md in this directory for how to run it and how to read it.
import http from 'k6/http';
import { check, fail } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const BASE_URL = (__ENV.BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
const STUB_URL = (__ENV.STUB_URL || 'http://127.0.0.1:8099').replace(/\/$/, '');
const TOOLS = Number(__ENV.TOOLS || 500);
const RATE = Number(__ENV.RATE || 500);
const LIST_RATE = Number(__ENV.LIST_RATE || 10);
const DURATION = __ENV.DURATION || '1m';
const PASSWORD = __ENV.PASSWORD || 'correct horse battery 9';
// The importer refuses a document with more than 200 operations, so a
// catalogue larger than that arrives as several connectors on one server,
// which is how a large one is assembled in practice anyway.
const MAX_OPS_PER_IMPORT = 200;

// The gateway's own share of a tool call. This is the number the plan puts
// a gate on, and the only one in this file that is about us.
const overhead = new Trend('gateway_overhead_ms', true);
// Kept beside it so a failed run can be read: if both rose together the
// stub is what got slower, and the overhead is innocent.
const toolCall = new Trend('tool_call_total_ms', true);
const upstream = new Trend('upstream_direct_ms', true);
// tools/list is measured on its own because its cost is the size of the
// catalogue, not the size of the call: the surface is rebuilt per request.
const toolsList = new Trend('tools_list_ms', true);
const rpcErrors = new Counter('rpc_errors');
const rpcErrorRate = new Rate('rpc_error_rate');

export const options = {
  scenarios: {
    tool_calls: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      // Enough VUs that the arrival rate is the thing under test rather
      // than the pool size. k6 warns loudly if it still cannot keep up,
      // and that warning means the load generator gave up, not the server.
      preAllocatedVUs: Math.max(50, Math.ceil(RATE / 4)),
      maxVUs: Math.max(200, RATE * 2),
      exec: 'toolCallScenario',
    },
    tools_list: {
      executor: 'constant-arrival-rate',
      rate: LIST_RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 10,
      maxVUs: 50,
      exec: 'toolsListScenario',
    },
  },
  thresholds: {
    // The gate from the plan.
    gateway_overhead_ms: ['p(99)<300'],
    // A gateway that is fast because it is refusing calls has not passed.
    rpc_error_rate: ['rate<0.01'],
    checks: ['rate>0.99'],
    // Not a gate, a tripwire: tools/list rebuilds the surface on every
    // request, so this is where a large catalogue shows up first.
    tools_list_ms: ['p(99)<1000'],
  },
  // The defaults would bury a p99 under an averaged summary.
  summaryTrendStats: ['min', 'med', 'p(95)', 'p(99)', 'max', 'count'],
};

// --- bootstrap ---------------------------------------------------------------

export function setup() {
  stubIsUp();
  if (__ENV.API_KEY && __ENV.SERVER_ID) {
    const endpoint = `${BASE_URL}/mcp/${__ENV.SERVER_ID}`;
    return { endpoint, key: __ENV.API_KEY, tool: discoverTool(endpoint, __ENV.API_KEY), owned: false };
  }

  const cookie = signIn();
  const connectorIDs = importStub(cookie);
  const server = createServer(cookie, connectorIDs);
  const key = createKey(cookie, server.id);
  const endpoint = `${BASE_URL}/mcp/${server.id}`;
  const tool = discoverTool(endpoint, key.secret);
  console.log(`${connectorIDs.length} connector(s), ${TOOLS} tools, server ${server.id}, calling ${tool}`);
  return { endpoint, key: key.secret, tool, cookie, connectorIDs, serverID: server.id, keyID: key.id, owned: true };
}

// teardown removes what setup made, so running this twice against one
// instance does not leave a trail of connectors behind. An account is left
// in place on purpose: registration is rate limited, and reusing one is
// what EMAIL and PASSWORD are for.
export function teardown(data) {
  if (!data || !data.owned) {
    return;
  }
  const headers = { Cookie: data.cookie };
  http.del(`${BASE_URL}/api/v1/api-keys/${data.keyID}`, null, { headers });
  http.del(`${BASE_URL}/api/v1/servers/${data.serverID}`, null, { headers });
  for (const id of data.connectorIDs) {
    http.del(`${BASE_URL}/api/v1/connectors/${id}`, null, { headers });
  }
}

function stubIsUp() {
  const res = http.get(`${STUB_URL}/items/0`, { tags: { name: 'stub-probe' } });
  if (res.status !== 200) {
    fail(`the stub at ${STUB_URL} answered ${res.status}; start it first (see README.md)`);
  }
}

function signIn() {
  const email = __ENV.EMAIL || `load-${Date.now()}@example.test`;
  const body = JSON.stringify({ email, password: PASSWORD, orgName: 'Load test' });
  const opts = { headers: { 'Content-Type': 'application/json' } };
  let res = http.post(`${BASE_URL}/api/v1/auth/login`, JSON.stringify({ email, password: PASSWORD }), opts);
  if (res.status !== 200) {
    res = http.post(`${BASE_URL}/api/v1/auth/register`, body, opts);
  }
  if (res.status !== 200) {
    fail(`sign in as ${email}: ${res.status} ${res.body}`);
  }
  const cookie = (res.headers['Set-Cookie'] || '').split(';')[0];
  if (!cookie) {
    fail('sign in returned no session cookie');
  }
  return cookie;
}

// importStub creates the connector under test by importing a generated
// OpenAPI document that points at the local stub. It goes through the
// public import API rather than seeding the database, so the connector is
// exactly the kind an operator would have.
function importStub(cookie) {
  const ids = [];
  let imported = 0;
  for (let first = 0; first < TOOLS; first += MAX_OPS_PER_IMPORT) {
    const count = Math.min(MAX_OPS_PER_IMPORT, TOOLS - first);
    const part = ids.length + 1;
    const res = http.post(`${BASE_URL}/api/v1/connectors/import`,
      JSON.stringify({
        document: JSON.stringify(openapiDoc(first, count)),
        serverUrl: STUB_URL,
        slug: `loadstub-${part}`,
        name: `Load stub ${part}`,
      }),
      { headers: { 'Content-Type': 'application/json', Cookie: cookie }, timeout: '120s' });
    if (res.status !== 200) {
      fail(`import part ${part} of the stub document: ${res.status} ${res.body}`);
    }
    const c = res.json('connector');
    ids.push(c.id);
    imported += c.toolCount;
  }
  if (imported !== TOOLS) {
    fail(`imported ${imported} tools, expected ${TOOLS}`);
  }
  return ids;
}

function createServer(cookie, connectorIDs) {
  const res = http.post(`${BASE_URL}/api/v1/servers`,
    JSON.stringify({ name: `Load test ${Date.now()}`, connectorIds: connectorIDs }),
    { headers: { 'Content-Type': 'application/json', Cookie: cookie } });
  if (res.status !== 200) {
    fail(`create the MCP server: ${res.status} ${res.body}`);
  }
  return res.json();
}

function createKey(cookie, serverID) {
  const res = http.post(`${BASE_URL}/api/v1/api-keys`,
    JSON.stringify({ name: `load-${Date.now()}`, serverId: serverID }),
    { headers: { 'Content-Type': 'application/json', Cookie: cookie } });
  if (res.status !== 200) {
    fail(`mint an API key: ${res.status} ${res.body}`);
  }
  return { id: res.json('key.id'), secret: res.json('secret') };
}

// discoverTool asks the endpoint what it serves rather than guessing the
// name the importer chose, so a change in the naming rules does not turn
// into a load test that measures error responses.
function discoverTool(endpoint, key) {
  const res = rpc(endpoint, key, 'tools/list', {});
  const body = parseRPC(res);
  if (!body || !body.result || !body.result.tools || body.result.tools.length === 0) {
    fail(`tools/list returned nothing usable: ${res.status} ${res.body}`);
  }
  return body.result.tools[0].name;
}

// --- scenarios ---------------------------------------------------------------

export function toolCallScenario(data) {
  // The upstream is called first and on its own, so the pair is the same
  // work done twice: once directly, once through the gateway.
  const direct = http.get(`${STUB_URL}/items/0`, { tags: { name: 'upstream-direct' } });
  const call = rpc(data.endpoint, data.key, 'tools/call', { name: data.tool, arguments: {} });

  const ok = check(call, {
    'tool call answered 200': (r) => r.status === 200,
    'tool call returned content': (r) => {
      const body = parseRPC(r);
      return !!body && !!body.result && !body.result.isError;
    },
  }) && direct.status === 200;

  rpcErrorRate.add(!ok);
  if (!ok) {
    rpcErrors.add(1);
    return;
  }
  toolCall.add(call.timings.duration);
  upstream.add(direct.timings.duration);
  // Negative values are possible and are left in: pretending a fast sample
  // was zero would flatter the tail this test exists to measure.
  overhead.add(call.timings.duration - direct.timings.duration);
}

export function toolsListScenario(data) {
  const res = rpc(data.endpoint, data.key, 'tools/list', {});
  const ok = check(res, {
    'tools/list answered 200': (r) => r.status === 200,
    'tools/list returned the catalogue': (r) => {
      const body = parseRPC(r);
      return !!body && !!body.result && body.result.tools.length === TOOLS;
    },
  });
  rpcErrorRate.add(!ok);
  if (ok) {
    toolsList.add(res.timings.duration);
  } else {
    rpcErrors.add(1);
  }
}

// --- wire --------------------------------------------------------------------

function rpc(endpoint, key, method, params) {
  return http.post(endpoint, JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), {
    headers: {
      'Content-Type': 'application/json',
      // Both types: the endpoint answers SSE by default and JSON when the
      // instance is configured for it.
      Accept: 'application/json, text/event-stream',
      'X-API-Key': key,
    },
    tags: { name: method },
  });
}

// parseRPC reads the JSON-RPC body out of either response shape. A
// Streamable HTTP response is server-sent events by default, and the
// result is the payload of the first data: line.
function parseRPC(res) {
  if (!res.body) {
    return null;
  }
  const body = String(res.body);
  if (body.charAt(0) === '{') {
    return safeJSON(body);
  }
  for (const line of body.split('\n')) {
    if (line.startsWith('data:')) {
      return safeJSON(line.slice(5).trim());
    }
  }
  return null;
}

function safeJSON(s) {
  try {
    return JSON.parse(s);
  } catch (e) {
    return null;
  }
}

// --- the document under import -----------------------------------------------

// openapiDoc generates count read-only operations against the stub,
// numbered from first. They are deliberately parameterless: a tool call
// that needs arguments would measure argument templating as well, and the
// point here is the fixed cost the gateway adds to any call at all.
function openapiDoc(first, count) {
  const paths = {};
  for (let i = first; i < first + count; i++) {
    paths[`/items/${i}`] = {
      get: {
        operationId: `get_item_${String(i).padStart(4, '0')}`,
        summary: `Fetch item ${i}`,
        description: `Fetch record ${i} from the load stub. This description is long enough to satisfy the adapter validator, and about as long as one a real catalogue entry carries.`,
        responses: {
          200: {
            description: 'The record.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    id: { type: 'string', description: 'Identifier of the record.' },
                    name: { type: 'string', description: 'Display name of the record.' },
                    price: { type: 'number', description: 'Price in minor units.' },
                  },
                },
              },
            },
          },
        },
      },
    };
  }
  return {
    openapi: '3.1.0',
    info: {
      title: 'Load stub',
      version: '1.0.0',
      description: 'A stub API with no authentication, used to measure the overhead the gateway adds to a tool call.',
    },
    servers: [{ url: STUB_URL }],
    paths,
  };
}
