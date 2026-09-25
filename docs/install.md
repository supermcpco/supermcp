# Installing supermcp

supermcp is one static Go binary and one Postgres database. Everything
else — Redis, a key management service, an identity provider — is
optional and changes behaviour rather than enabling it.

This document covers two deployments. Docker Compose is for a trial on a
single host. Helm is for production. Both end with the same first-run
sequence: apply the schema, create the first workspace, install an
adapter, point a client at it.

`docs/operations.md` covers what happens after that: alerts, key
rotation, audit verification and the failure modes an operator meets in
practice.

## Decide these before the first start

Four settings are difficult to change later. Decide them now.

| Decision | Setting | Why it is hard to change |
|---|---|---|
| The externally visible URL | `SUPERMCP_PUBLIC_URL` | It is the OAuth issuer, the audience of every access token, the single sign-on redirect target and the base of every MCP endpoint address. Changing it invalidates every token that named the old value, and every client configuration that pointed at it. |
| Where the master key lives | `SUPERMCP_KEK_PROVIDER` | Moving between a key in the environment and a key in AWS KMS is a rotation, not an edit. It is supported (see `docs/operations.md`) but it is a planned operation. |
| The master key material itself | `ENCRYPTION_KEK` or the KMS key | Every stored credential is encrypted under a data key that this key wraps. A database backup without this key is unreadable. |
| Whether anyone may create a workspace | `SUPERMCP_OPEN_REGISTRATION` | See the first-run note below: it also controls whether the sign-up form appears at all. |

Two more are worth deciding early because they are per workspace and
affect what the system stores about your data:

- **How much of a tool call is recorded.** `PUT /api/v1/audit/policy`,
  or the audit screen. The default keeps the *shape* of the arguments
  and the result and none of their values. See `docs/compliance/retention.md`.
- **How long the audit trail is kept.** Default 365 days, floor 90 days.

## Docker Compose: a trial on one host

This runs one supermcp container and one Postgres container. Migrations
run at container start, which is safe only because there is exactly one
replica.

```bash
cd deploy/compose
cp .env.example .env
```

Fill in `.env`:

```bash
# 32 random bytes, base64. Store a copy somewhere else before you continue.
openssl rand -base64 32
```

```
ENCRYPTION_KEK=<the value that command printed>
POSTGRES_PASSWORD=<a password for the bundled Postgres>
SUPERMCP_PUBLIC_URL=http://localhost:8080
```

Then start it:

```bash
docker compose up -d
docker compose logs -f supermcp
```

The service listens on `127.0.0.1:8080` by default. `SUPERMCP_BIND` and
`SUPERMCP_PORT` move it. There is a `tls` profile that puts Caddy in
front and obtains a certificate:

```bash
DOMAIN=mcp.example.com docker compose --profile tls up -d
```

If you use the `tls` profile, set `SUPERMCP_PUBLIC_URL` to the same
`https://` address. The binary refuses to start with a plain `http://`
public URL that does not point at loopback.

### What the compose file does and does not do

- `SUPERMCP_MIGRATE_ON_START=true` is set. The binary logs a warning
  about this on every start, because with more than one replica the
  replicas would race. Compose runs one replica, so it is correct here.
- No Redis. Rate-limit budgets and the tool-response cache are therefore
  per process. With one process that is the same thing as shared.
- No metrics listener. `SUPERMCP_ADMIN_LISTEN` is unset, so `/metrics`
  is not served.
- The container runs read-only, with no new privileges and all
  capabilities dropped.

## Helm: production

The chart is at `charts/supermcp`. It requires Kubernetes 1.29 or later.

### 1. Create the secrets

The chart does not create secrets. It reads existing ones by name, so
that key material never passes through `helm --set` and into release
history.

```bash
kubectl create secret generic supermcp-db \
  --from-literal=DATABASE_URL='postgres://supermcp_app:...@db.internal:5432/supermcp?sslmode=require' \
  --from-literal=MAINT_DATABASE_URL='postgres://supermcp_maint:...@db.internal:5432/supermcp?sslmode=require'

kubectl create secret generic supermcp-kek \
  --from-literal=ENCRYPTION_KEK="$(openssl rand -base64 32)"
```

`MAINT_DATABASE_URL` is optional and the chart marks it so. When it is
absent, the maintenance work runs under the same role as the
application. Read "Two database roles" below before deciding to leave it
out.

### 2. Install

```bash
helm install supermcp charts/supermcp \
  --set publicUrl=https://mcp.example.com \
  --set database.existingSecret=supermcp-db \
  --set encryption.local.existingSecret=supermcp-kek \
  --set ingress.enabled=true \
  --set ingress.host=mcp.example.com \
  --set ingress.tls.enabled=true \
  --set replicaCount=2
```

`publicUrl`, `database.existingSecret` and — for the local key provider
— `encryption.local.existingSecret` have no defaults. The chart fails to
render without them rather than installing something that will not
start.

### 3. What the chart renders

| Object | Notes |
|---|---|
| `Deployment` | `serve`, rolling update with `maxUnavailable: 0`. Liveness on `/healthz`, readiness on `/readyz`. Runs as UID 65532, non-root, read-only root filesystem, all capabilities dropped, with an `emptyDir` at `/tmp`. |
| `Job` (migrate) | A `pre-install,pre-upgrade` Helm hook running `supermcp migrate --wait-lock`. Disable with `database.migrate.enabled=false` if you apply migrations yourself. |
| `Service` | Port 80 to the HTTP port, plus the admin port when `metrics.enabled` is true. |
| `Ingress` | Only when `ingress.enabled` is true. Routes `/` to the HTTP port; the admin port is never routed. |
| `ServiceAccount` | Created by default. `serviceAccount.annotations` is where an IRSA, GKE workload identity or Azure workload identity annotation goes. |
| `PodDisruptionBudget` | `minAvailable: 1`. With `replicaCount: 1` this blocks voluntary eviction entirely, which is deliberate. |
| `HorizontalPodAutoscaler` | Only when `autoscaling.enabled` is true. |
| `NetworkPolicy` | Only when `networkPolicy.enabled` is true. The default egress rule is allow-all; see "Egress" below. |
| `ServiceMonitor`, `PrometheusRule` | Only when the matching `metrics.*.enabled` value is true. The six alert rules are explained in `docs/operations.md`. |

`SUPERMCP_EXPECTED_REPLICAS` is set from `replicaCount` automatically.
It matters when there is no Redis: the in-memory rate limiter divides
every budget by that number so that the replicas together stay near the
intended ceiling. If you enable autoscaling, set `replicaCount` to the
number you expect to run at, or the ceiling drifts.

### 4. Redis

Optional. Without it, rate-limit budgets and the tool-response cache are
per replica. Neither fails open: the limiter divides the budget instead
of allowing everything, and the cache resolves every error to a miss.

```bash
kubectl create secret generic supermcp-redis \
  --from-literal=REDIS_URL='rediss://:password@redis.internal:6380/0'
helm upgrade supermcp charts/supermcp --reuse-values \
  --set redis.existingSecret=supermcp-redis
```

### 5. Key management service

The binary understands two key providers: `local` (the key is in the
process environment or a file) and `awskms`.

For AWS KMS the binary reads `SUPERMCP_KMS_KEY_ID` and
`SUPERMCP_KMS_REGION`, with `AWS_REGION` and `AWS_DEFAULT_REGION` as
fallbacks for the region. Credentials come from the default AWS chain,
so a pod can authenticate with a workload identity rather than a static
access key.

The chart renders them from `encryption.awskms`:

```bash
helm upgrade supermcp charts/supermcp --reuse-values \
  --set encryption.provider=awskms \
  --set encryption.awskms.keyId=alias/supermcp \
  --set encryption.awskms.region=eu-north-1
```

`SUPERMCP_KMS_DEPLOYMENT` names this installation and becomes part of
the KMS encryption context. Set it through `extraEnv` when staging and
production share an AWS account or a KMS key: without it, a wrapped key
lifted from one database can be unwrapped against the other.

`local` and `awskms` are the only providers the binary implements, and
they are the only ones the chart accepts: any other value fails the
render with a message naming the setting, rather than producing a pod
that cannot start.

### 6. Egress

By default the chart's network policy, when enabled, allows all egress.
That is the honest default for a system whose job is to call arbitrary
upstream APIs, but it means the only egress control is the SSRF guard
inside the process.

The SSRF guard is on by default and refuses loopback, RFC 1918, CGNAT,
link-local (including the cloud metadata address), unique-local,
multicast and reserved addresses. It classifies after resolving and
connects to the address it checked, so a DNS answer that changes between
check and connect cannot reach a blocked address. Redirects are
re-checked.

To reach an internal system deliberately, name it rather than widening
the class:

```
SUPERMCP_SSRF_ALLOWED_HOSTS=erp.internal,*.corp.example.com
```

`SUPERMCP_SSRF_ALLOW_PRIVATE=true` opens every RFC 1918 address at once,
and `SUPERMCP_SSRF_GUARD=disabled` turns the guard off entirely. Neither
belongs in production.

## Two database roles

Migration `00002` creates a Postgres role `supermcp_app` with
`NOBYPASSRLS`. When the server starts, every connection in the
application pool runs `SET ROLE supermcp_app`, so row-level security
applies even though the login user owns the schema. Every tenant-scoped
query then runs inside a transaction that has set `app.current_org`, and
the policies compare that setting to the row's `organization_id`. A
missing setting matches nothing.

The maintenance pool never switches role. It runs migrations, the audit
writer, the retention sweep and the audit exporter — the work that
spans tenants by definition. Each replica also opens one extra session
on the maintenance URL that `LISTEN`s for cache invalidations, which is
why that URL must reach Postgres directly (see "Cache invalidation" in
the operations guide).

`SUPERMCP_MAINT_DATABASE_URL` lets you give those two pools different
database users. If you leave it unset, both pools use `DATABASE_URL` and
the separation is the `SET ROLE` alone. That is still enforced by
Postgres, but it means anything that can execute SQL as the login user
can reset the role. Giving the maintenance pool its own user, and giving
the application pool a user with no more rights than `supermcp_app`
needs, is the stronger arrangement.

The application role is explicitly denied `INSERT`, `UPDATE` and
`DELETE` on `audit_events`, with one exception: it may set `diff`,
`payload` and `scrubbed_at`, which is what a retention scrub does.
Appending to the audit trail is the maintenance role's job.

## Settings

Every setting is an environment variable. Names are prefixed
`SUPERMCP_` except `DATABASE_URL`, `REDIS_URL` and `ENCRYPTION_KEK`,
which are also accepted under the prefix.

### Required

| Setting | Default | What it decides |
|---|---|---|
| `DATABASE_URL` | none | The Postgres connection for the application pool. Boot fails without it. |
| `SUPERMCP_PUBLIC_URL` | none (`http://localhost:8080` when `SUPERMCP_DEV=1`) | The externally visible base URL. Must be an absolute `http` or `https` URL; `http` is refused unless the host is `localhost`, `127.0.0.1`, `::1` or a `.localhost` name. A trailing slash is trimmed. |
| `ENCRYPTION_KEK` or `ENCRYPTION_KEK_FILE` | none, for the `local` provider | The master key: exactly 32 bytes, base64. Any other length is refused outright rather than padded. A key file must not be group- or world-readable. |

### Process

| Setting | Default | What it decides |
|---|---|---|
| `SUPERMCP_LISTEN` | `:8080` | The public HTTP listener: API, MCP endpoint and the embedded interface. |
| `SUPERMCP_ADMIN_LISTEN` | empty | Where `/metrics` is served. Empty means the exposition is off. It must never share the public listener: the series describe the shape of the estate. |
| `SUPERMCP_MAINT_DATABASE_URL` | `DATABASE_URL` | The Postgres connection for cross-tenant work, and for the one long-lived session per replica that listens for cache invalidations. Point it at Postgres directly, not at a transaction-pooling proxy. |
| `SUPERMCP_REDIS_URL` / `REDIS_URL` | empty | Shared rate-limit budgets and a shared tool-response cache. |
| `SUPERMCP_LOG_LEVEL` | `info` | Log verbosity. |
| `SUPERMCP_LOG_FORMAT` | `json` | `json` or `text`. Anything else fails the boot. |
| `SUPERMCP_SHUTDOWN_TIMEOUT` | `20s` | How long a graceful shutdown waits for in-flight requests. |
| `SUPERMCP_DEV` | off | Relaxes the public-URL check, serves the API documentation page at `/api/docs`, and allows the SSRF guard to reach loopback. Never in production. |
| `SUPERMCP_MIGRATE_ON_START` | off | Runs migrations from `serve`. Single-replica deployments only; the binary logs a warning when it is set. |

### Access

| Setting | Default | What it decides |
|---|---|---|
| `SUPERMCP_OPEN_REGISTRATION` | off | Whether anyone who reaches the sign-in page may create an account and a workspace of their own. See the first-run note below. |
| `SUPERMCP_DCR_MODE` | `approval` | Whether an MCP client may register itself through RFC 7591. `open` accepts any registration, `approval` records it as pending until the operator approves it with `supermcp oauth clients approve`, `closed` refuses. A pending client cannot start an authorisation flow. |
| `SUPERMCP_MCP_RESPONSE_MODE` | `sse` | `json` makes the MCP endpoint answer with `application/json` instead of server-sent events. Some clients require it. |

### Rate limiting

Budgets are written `count/duration`, for example `10/1m`. A malformed
value fails the boot, and every malformed value is reported in the same
message, so an operator who mistyped two finds out about both at once.

| Setting | Default | What it covers |
|---|---|---|
| `SUPERMCP_RATELIMIT_ENABLED` | on | Off only when set to an explicit false value. A value that does not parse leaves the limiter on. |
| `SUPERMCP_RATELIMIT_SIGNIN` | `10/1m` | `POST /api/v1/auth/login` and the password routes. |
| `SUPERMCP_RATELIMIT_REGISTER` | `5/1h` | `POST /api/v1/auth/register`. |
| `SUPERMCP_RATELIMIT_DCR` | `10/1h` | `POST /oauth/register`. |
| `SUPERMCP_RATELIMIT_TOOL_CALL` | `600/1m` | Everything under `/mcp/`. |
| `SUPERMCP_RATELIMIT_API` | `300/1m` | The rest of the surface. |
| `SUPERMCP_RATELIMIT_MAX_KEYS` | `100000` | Bounds the in-memory bucket map, so a distributed flood cannot turn the limiter itself into the outage. |
| `SUPERMCP_EXPECTED_REPLICAS` | `1` | Only used without Redis: the in-memory limiter divides each budget by this number. |

The limiter charges against the authenticated principal where there is
one, so an office behind one address is not a single bucket. Health
probes are never counted or limited.

### Encryption

| Setting | Default | What it decides |
|---|---|---|
| `SUPERMCP_KEK_PROVIDER` | `local` | `local` or `awskms`. Any other value fails the boot. A provider that cannot be built is an error, never a silent downgrade to a weaker one. |
| `ENCRYPTION_KEK_FILE` | empty | Reads the local key from a file instead of the environment. Takes precedence over `ENCRYPTION_KEK`. |
| `SUPERMCP_KEK_PREVIOUS` | empty | Comma-separated master keys that may decrypt and never seal, for a rolling key rotation. An entry is either the base64 material or `<reference>|<base64>`. |
| `SUPERMCP_KMS_KEY_ID` | none, for `awskms` | A key id, key ARN, alias name (`alias/supermcp`) or alias ARN. |
| `SUPERMCP_KMS_REGION` | `AWS_REGION`, then `AWS_DEFAULT_REGION` | The region holding the key. Required even when the key is an ARN. |
| `SUPERMCP_KMS_DEPLOYMENT` | the key reference | Names this installation in the KMS encryption context. |
| `SUPERMCP_KMS_TIMEOUT` | `10s` | Bounds a single KMS round trip. |

### Outbound network

| Setting | Default | What it decides |
|---|---|---|
| `SUPERMCP_SSRF_GUARD` | on | `disabled` turns off address classification entirely. |
| `SUPERMCP_SSRF_ALLOW_LOOPBACK` | off | Permits `127.0.0.0/8` and `::1`. Forced on when `SUPERMCP_DEV` is set. |
| `SUPERMCP_SSRF_ALLOW_PRIVATE` | off | Permits RFC 1918, CGNAT and unique-local addresses. |
| `SUPERMCP_SSRF_ALLOWED_HOSTS` | empty | Comma-separated exact hostnames or `*.suffix` patterns that skip address classification. |

Link-local, multicast and reserved ranges are refused unconditionally;
no setting permits them except `SUPERMCP_SSRF_GUARD=disabled` or an
entry in the allowed-hosts list.

### Audit and metrics

| Setting | Default | What it decides |
|---|---|---|
| `SUPERMCP_AUDIT_ON_UNAVAILABLE` | `degrade` | What happens when the audit queue is full because the database is slow or down. `degrade` drops the event, counts it, and records the gap in the stream on the next successful append. `block` makes the caller wait instead. |
| `SUPERMCP_METRICS_PER_TOOL` | off | Publishes a metric series per tool name. Off by default: tool names are operator data and nothing caps how many an organisation installs. |
| `SUPERMCP_METRICS_PER_TOOL_CAP` | `5000` | How many distinct tool names get their own series before the rest collapse into one. |

### Database connectors

| Setting | Default | What it decides |
|---|---|---|
| `SUPERMCP_SQLITE_ROOT` | empty | The directory under which a SQLite database connector may open a file. Empty means no SQLite connector can open anything. |

## What happens if a setting is wrong

| Mistake | What you see |
|---|---|
| `SUPERMCP_PUBLIC_URL` is `http://` and not loopback | Boot fails, naming the setting and the value. |
| `SUPERMCP_PUBLIC_URL` changes after clients have connected | Existing access tokens name an audience that no longer matches, and are refused at the MCP endpoint. Clients must re-authorise. API keys are unaffected. |
| `ENCRYPTION_KEK` is not 32 bytes | Boot fails with "KEK material must be exactly 32 bytes (base64)". |
| `ENCRYPTION_KEK` is a *different* 32 bytes than before | Boot succeeds. Every data key then fails to unwrap, and every operation touching a stored credential fails. `supermcp keys verify` reports each stranded key and the reference it is wrapped under. |
| The key file is group-readable | Boot fails, naming the file and its mode. |
| `SUPERMCP_KEK_PROVIDER` is `gcpkms`, `azurekv` or `vault` | Boot fails: only `local` and `awskms` exist. The chart refuses these at render time. |
| `SUPERMCP_KEK_PREVIOUS` names the same reference as the active key | Boot fails. Two keys under one reference cannot be told apart by anything reading `data_keys.kek_ref`, so a rotation between them would skip every row as already done. Load the new key from `ENCRYPTION_KEK_FILE` to give it a distinct reference. |
| A rate-limit budget is malformed | Boot fails. A limit nobody notices is off is worse than no limit: the dashboard says the route is protected and it is not. |
| `SUPERMCP_LOG_FORMAT` is neither `json` nor `text` | Boot fails. |
| The schema is older than the binary | `/readyz` returns 503 saying "schema behind: have N, want M", so a rolling upgrade never serves traffic from a pod whose migration hook has not finished. |
| `supermcp migrate` has never run | The server fails to start with "SET ROLE supermcp_app (run `supermcp migrate` first)". |
| Two branches added migrations with the same number | `supermcp migrate` refuses. One of them needs renumbering. |
| Redis is configured but unreachable | The service keeps running. Rate-limit budgets fall back to per-replica, a `system` warning is logged, and the `supermcp_ratelimit_degraded` gauge goes to 1. The response cache falls back the same way and resolves errors to misses. |

## First run

### 1. Apply the schema

Under Helm this is the migrate hook and happens automatically. By hand:

```bash
supermcp migrate            # blocks for the advisory lock
supermcp migrate --status   # prints the applied version and the one the binary expects
```

Migrations take a Postgres advisory lock, so a second process waits
rather than racing. `--wait-lock=false` fails fast instead.

### 2. Create the first workspace

The first account created owns the first workspace. The server permits
registration when no user exists yet, whatever
`SUPERMCP_OPEN_REGISTRATION` says.

The sign-in page offers the sign-up form while the instance has no
users, so the first administrator creates the workspace in the browser
and nothing has to be turned on for it.

The same thing can be done from the command line:

```bash
curl -sS -X POST https://mcp.example.com/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"correct horse battery staple","orgName":"Acme"}'
```

The password must satisfy the policy: at least 12 characters drawing on
at least two of lower case, upper case, digits and symbols. The response
sets the session cookie. The account is bound to the built-in `owner`
role in the new workspace.

After this, add people through single sign-on or SCIM (see
`docs/api.md`) rather than leaving open registration on.

### 3. Install an adapter

255 adapters are compiled into the binary. Browse them at
`GET /api/v1/catalog`, or in the interface under the catalog screen.

```bash
curl -sS https://mcp.example.com/api/v1/catalog?q=nominatim \
  -H "Cookie: __Host-sm_sess=$SESSION"
```

Installing one creates a connector in your workspace, copies the
adapter's tools into it, and seals the credentials you supply:

```bash
curl -sS -X POST https://mcp.example.com/api/v1/connectors/install \
  -H 'Content-Type: application/json' \
  -H "Cookie: __Host-sm_sess=$SESSION" \
  -d '{"slug":"pandadoc","credentials":{"PANDADOC_API_KEY":"..."}}'
```

Every credential the adapter declares as `required: true` must be
supplied, or the install is refused naming the one that is missing.
Credentials can be set or replaced later with
`PUT /api/v1/connectors/{id}/credentials`. They are sealed with the
workspace's data key before they are stored; the API never returns a
value, only the names and whether each is secret.

An adapter that needs no credentials — Nominatim, for example —
installs with an empty body.

### 4. Create an MCP server

A connector is not reachable on its own. An MCP server is the endpoint a
client connects to, and it names the connectors whose tools it exposes.

```bash
curl -sS -X POST https://mcp.example.com/api/v1/servers \
  -H 'Content-Type: application/json' \
  -H "Cookie: __Host-sm_sess=$SESSION" \
  -d '{"name":"Documents","connectorIds":["<connector id>"]}'
```

It is then served at `https://mcp.example.com/mcp/<server id>`. The slug
works in that position too.

### 5. Point a client at it

Two ways, described in full in `docs/api.md`.

**An API key** is the shorter path and is what a client that cannot do
OAuth needs. Create one bound to the server:

```bash
curl -sS -X POST https://mcp.example.com/api/v1/api-keys \
  -H 'Content-Type: application/json' \
  -H "Cookie: __Host-sm_sess=$SESSION" \
  -d '{"name":"Claude Desktop","serverId":"<server id>","ttlDays":90}'
```

The secret is returned once and never again. Only its SHA-256 is
stored. Keys expire after 90 days unless you ask for something else. In
the client, send it as `Authorization: Bearer smk_...`.

**OAuth** is what a client that supports it should use. Point the client
at `https://mcp.example.com/mcp/<server id>` with no credential. The
401 carries a `WWW-Authenticate` header naming the protected-resource
metadata document, the client follows it to the authorisation server
metadata, registers itself if `SUPERMCP_DCR_MODE` permits, and sends the
person to the consent page. With `SUPERMCP_DCR_MODE=approval` — the
default — the registration is recorded as pending and the operator
must approve it before the flow can start:

```bash
supermcp oauth clients list -status pending
supermcp oauth clients approve smc_...
```

Clients belong to the instance, not to a workspace, so this is a
command-line decision rather than a screen. Each approval and rejection
is written to the audit trail.

### 6. Check it

```bash
curl -sS https://mcp.example.com/healthz     # process is up
curl -sS https://mcp.example.com/readyz      # database reachable and schema current
supermcp audit verify                        # the audit chain is intact
supermcp keys verify                         # every data key opens with the keys this process holds
```

## Upgrading

Migrations are applied by the Helm hook before the new pods start, and
pods report ready only once `/readyz` sees the new schema version. Read
`docs/UPGRADING.md` for the releases that need something from you beyond
running the migrations.
