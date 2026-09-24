# Load test

`tools.js` is a [k6](https://k6.io) script that answers one question: **how
much latency does supermcp add to a tool call?**

It is not a benchmark of anybody's API. The script points a connector at a
stub upstream running on the same machine, and on every iteration it calls
that stub twice — once directly, once through the gateway — and records the
difference. That difference, `gateway_overhead_ms`, is the number that
belongs in a capacity plan. A measurement taken from the gateway alone
would move every time the upstream moved and would say nothing about us.

There are two scenarios, running at the same time:

- **`tool_calls`** — `tools/call` at a fixed arrival rate (500 per second by
  default). This is the plan's target: 500 rps, 99th percentile overhead
  under 300 ms.
- **`tools_list`** — `tools/list` at a low rate. It is measured separately
  because its cost is the *size of the catalogue*, not the size of the call:
  the tool surface is rebuilt from the database on every request. On a
  large catalogue this is the expensive one, and on a large catalogue it
  makes `tools/call` expensive too, because `tools/call` rebuilds the same
  surface before it dispatches.

## Running it

You need three things: a stub upstream, an instance configured to allow it,
and k6.

### 1. The stub

Anything that answers `GET /items/<n>` with JSON will do. This is the one
the numbers below were taken with:

```bash
cat > /tmp/stub.py <<'PY'
import http.server, json, socketserver, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = json.dumps({"id": self.path.rsplit("/", 1)[-1], "name": "Widget", "price": 9.5}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 /tmp/stub.py 8099
```

The stub must be *fast and boring*. If it has a slow tail of its own, that
tail lands in the subtraction and the overhead figure gets noisier, not
wrong — but harder to read. Check it first: `curl -s localhost:8099/items/0`.

### 2. The instance

```bash
export DATABASE_URL='postgres://supermcp:supermcp@127.0.0.1:5432/supermcp?sslmode=disable'
export ENCRYPTION_KEK=$(openssl rand -base64 32)
export SUPERMCP_PUBLIC_URL=http://127.0.0.1:8080
export SUPERMCP_OPEN_REGISTRATION=1

# The stub is on loopback, which the SSRF guard refuses by default.
export SUPERMCP_SSRF_ALLOW_LOOPBACK=true

# Without this the limiter, not the gateway, is what you measure: the
# default tool-call budget is 600 a minute, which is 10 a second.
export SUPERMCP_RATELIMIT_TOOL_CALL='2000000/1m'
export SUPERMCP_RATELIMIT_API='2000000/1m'

supermcp migrate && supermcp serve
```

Run it the way you intend to deploy it. A load test against a binary built
with `-race`, or against a database on a laptop's Docker, measures that
choice and not much else.

### 3. The test

```bash
k6 run hack/load/tools.js
```

Knobs, all through `-e NAME=value`:

| Variable | Default | What it does |
| --- | --- | --- |
| `BASE_URL` | `http://127.0.0.1:8080` | the instance under test |
| `STUB_URL` | `http://127.0.0.1:8099` | the stub, as **the gateway** must be able to reach it |
| `TOOLS` | `500` | how many tools the server carries |
| `RATE` | `500` | tool calls per second |
| `LIST_RATE` | `10` | `tools/list` calls per second |
| `DURATION` | `1m` | how long both scenarios run |
| `EMAIL`, `PASSWORD` | a fresh random account | reuse an account; registration is rate limited, so set these for repeat runs |
| `API_KEY`, `SERVER_ID` | — | skip the bootstrap entirely and measure a server you already have |

`setup()` does the whole bootstrap through the public API — register, import
a generated OpenAPI document as a connector (in batches of 200 operations,
because the importer refuses more than that in one document), create an MCP
server, mint an API key — and `teardown()` deletes the connectors, the
server and the key again. Nothing is seeded straight into the database, so
what gets measured is the same kind of connector an operator would have.

## Reading the result

k6 prints the thresholds first. Three of them matter:

```
gateway_overhead_ms ... p(99)<300     the gate
rpc_error_rate      ... rate<0.01     it has to be answering, not refusing
tools_list_ms       ... p(99)<1000    a tripwire, not a gate
```

And then the trends:

```
gateway_overhead_ms: min=1.21ms med=4.15ms p(95)=50.74ms p(99)=221.85ms
tool_call_total_ms:  ...                                  the same call, undifferenced
upstream_direct_ms:  min=51µs   med=110µs  p(95)=418µs    p(99)=1.31ms
tools_list_ms:       ...
```

**Look at `upstream_direct_ms` first.** It is the control. If it has grown
into milliseconds, the stub or the machine is the bottleneck and the
overhead figure is measuring congestion you created. Then look at
`gateway_overhead_ms` p(99).

### What a bad result looks like

- **`dropped_iterations` in the EXECUTION block.** k6 could not start
  iterations fast enough to keep the arrival rate, which means the server
  was not keeping up. Any latency number from a run with dropped iterations
  understates the problem: the requests that would have been slowest were
  never sent. This is the first thing to check and the easiest to miss.
- **`gateway_overhead_ms` p(99) far above p(95)** — a queue. Something is
  serialised: the database pool, the connector's upstream semaphore, or the
  audit writer.
- **`upstream_direct_ms` rising with `gateway_overhead_ms`** — not our
  problem. The box is saturated; give the stub or the generator its own.
- **`rpc_error_rate` above zero with a *good* latency.** The gateway is
  fast because it is refusing. Check for 429s: the rate limit budgets above
  are almost certainly still at their defaults.
- **A p(99) that is fine at 10 tools and terrible at 500.** That is the
  surface rebuild, and it is the finding below.

## What it found

Measured on an Apple M5 laptop with everything co-located — the instance,
Postgres in Docker, the stub and k6 on one machine. Treat the absolute
numbers as a shape, not as a spec sheet; the shape is the point.

| Tools on the server | Arrival rate | p(99) overhead | Sustained |
| --- | --- | --- | --- |
| 10 | 200/s | 11.7 ms | yes |
| 10 | 500/s | **221.9 ms** | yes |
| 100 | 200/s | 453.0 ms | yes |
| 500 | 50/s | 73.9 ms | yes |
| 500 | 100/s | 1.34 s | no |
| 500 | 500/s | 18.05 s | no, 25 264 iterations dropped |

The plan's gate — 500 rps, p(99) overhead under 300 ms — **is met with a
small catalogue and is not met with a large one.** Cost tracks the product
of tools and request rate, because the tool surface is rebuilt on every MCP
request: every connector on the server is loaded, every one of its tools is
read out of Postgres, annotations are derived, and each tool's JSON Schema
is re-parsed when it is registered on the SDK server. `tools/call` pays all
of that before it dispatches a single call, exactly as `tools/list` does.

The Go side of that is measurable without a database:

```
go test -bench 'BenchmarkToolsList|BenchmarkGetServer' ./internal/mcp/
```

which reports roughly 10 ms and 46 MB of allocation per `tools/list` at 500
tools, of which about 95 % is the SDK re-parsing input schemas inside
`AddTool`. The plan's 5 ms surface-build gate is not met at 500 tools today.
The fix is a cache keyed by the connector version that already exists for
this purpose (`tool.Signature`), so that a surface is rebuilt when it
changes rather than when it is asked for.

Until that lands, the honest operating guidance is: a server carrying a few
dozen tools sustains 500 rps comfortably; a server carrying hundreds should
be sized against the table above, or split across several MCP servers so
that each caller's surface is small.
