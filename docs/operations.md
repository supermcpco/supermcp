# Running supermcp

What an operator needs to know that the code cannot tell them: which
settings matter, what the failure modes look like, and which commands to
reach for when something is wrong.

## The settings that decide behaviour

| Setting | Default | What it decides |
|---|---|---|
| `DATABASE_URL` | none, required | Where everything lives. The application connects as a role that cannot bypass row-level security. |
| `SUPERMCP_MAINT_DATABASE_URL` | `DATABASE_URL` | Cross-tenant work, and each replica's cache invalidation listener. Must reach Postgres directly or through a session-mode proxy; see "Cache invalidation". |
| `SUPERMCP_PUBLIC_URL` | none, required | The address clients reach. It appears in token audiences, the single sign-on redirect and the MCP endpoints, so changing it invalidates tokens that named the old one. Must be https unless it points at loopback. |
| `SUPERMCP_KEK_PROVIDER` | `local` | `local` reads the master key from the environment; `awskms` leaves it in a key service and never in the pod. |
| `ENCRYPTION_KEK` | none for `local` | 32 bytes, base64. A wrong length fails the boot rather than encrypting with a key nobody meant. |
| `SUPERMCP_REDIS_URL` | empty | Shared rate-limit budgets. Without it each replica keeps its own, divided by `SUPERMCP_EXPECTED_REPLICAS`. |
| `SUPERMCP_EXPECTED_REPLICAS` | 1 | Only used when Redis is absent. Set it to the replica count or the cluster together allows several times the intended ceiling. |
| `SUPERMCP_ADMIN_LISTEN` | empty | Where `/metrics` is served. Empty means the exposition is off; it must never share the public listener. |
| `SUPERMCP_OPEN_REGISTRATION` | off | Whether anyone who reaches the sign-in page can create a workspace. The first registration on an empty instance is always allowed. |
| `SUPERMCP_OTLP_ENDPOINT` | empty | An OTLP/HTTP collector for traces. Empty is off; `OTEL_EXPORTER_OTLP_ENDPOINT` is read too. A collector that cannot be reached is a log line, never a failed boot. |
| `SUPERMCP_TRACE_SAMPLE` | 0.01 | The fraction of traces kept. |
| `SUPERMCP_AUDIT_ON_UNAVAILABLE` | `degrade` | What happens when the database will not take an event. See "When the database refuses audit events" below. |
| `SUPERMCP_AUDIT_SPOOL_DIR` | `/var/lib/supermcp/audit-spool` | Where `spool` writes. It must be a persistent volume: a spool in a pod's ephemeral layer buys nothing over `degrade`. |
| `SUPERMCP_AUDIT_SPOOL_MAX_BYTES` | 256 MiB | Past this, events are dropped and counted as they are without a spool. |
| `SUPERMCP_DCR_MODE` | `approval` | Whether an MCP client can register itself: `open`, `approval` or `closed`. |

Rate-limit budgets are written `count/duration`, for example `10/1m`. A
malformed value fails the boot, because a limit nobody notices is off is
worse than no limit at all.

## The audit trail

Every sign-in, administrative change, secret operation, tool call and
refused request lands in one append-only stream. Each row carries the hash
of the one before it, so removing or editing one breaks the chain at a
point the verifier can name.

```
supermcp audit verify              # exits non-zero when the chain is broken
supermcp audit verify -format json # for a deployment check
```

It needs `DATABASE_URL` and the master key settings, and nothing else:
the commands that do not serve a request do not ask for the address
clients reach. The same is true of `keys verify` and `keys rotate-kek`.

Run it after a restore and on a schedule. A broken chain means either a
bug or someone editing the database directly; both deserve the same
attention.

### When the database refuses audit events

Each replica writes events through one in-memory queue (256 events) and
appends them in batches. When the database refuses a batch (it is down,
failing over, or does not answer within ten seconds), what happens
depends on `SUPERMCP_AUDIT_ON_UNAVAILABLE`:

- **`degrade`** (the default). The batch stays at the head of the queue
  and is retried with back-off, six attempts over about eight seconds.
  Nothing behind it is written first, so the order holds. Requests are
  never slowed: while the batch waits, new events fill the queue, and
  once it is full further events are dropped. If the retries run out, the
  batch is dropped too. Every dropped event is counted in
  `supermcp_audit_events_dropped_total`, and the next append that
  succeeds writes an `audit.events_dropped` event ahead of its own, with
  how many were lost (`meta.events`), the replica's own numbers for them
  (`meta.firstSeq`, `meta.lastSeq`) and when they were accepted
  (`meta.from`, `meta.to`). A database that refuses a few appends and
  then recovers loses nothing.
- **`block`**. The batch stays at the head of the queue and is retried
  with back-off, capped at five seconds, until the database takes it.
  The queue fills behind it, and then every request that emits an event
  waits for room. A request that gives up waiting drops its event, which
  is counted and recorded like any other.
- **`spool`**. The batch is written to disk (see "The audit spool"
  below) and replayed in order when the database takes events again.
  Events that arrive while the queue is full wait in a second in-memory
  buffer of the same size and go to disk behind it; past that buffer they
  are dropped. A batch the spool refuses because it is at its bound
  (`SUPERMCP_AUDIT_SPOOL_MAX_BYTES`) is dropped. Both are counted and
  recorded as a gap. A spool that could not be opened at start is logged,
  and the writer then does what `degrade` does.

In every mode, a replica shutting down gives a refused batch one more
attempt rather than the full back-off. What it cannot write then is
logged (`audit events dropped`, with the count and range) and is lost
with the process, because the record of the gap has nowhere to go.

**What a tool call records** is the workspace's decision, on the audit
screen: nothing, the shape of the arguments, their masked values, or
everything. The default keeps shapes, which is enough to reconstruct who
called what without storing what they typed.

**Where it goes** is the workspace's decision too: a signed webhook, a
syslog collector (RFC 5424, or CEF), Splunk's event collector, or OTLP
logs. Delivery resumes from where it stopped, and a destination that
cannot be reached backs off rather than blocking anything.

**Retention** runs hourly. Each workspace's own window is honoured by
removing the content of its older events while leaving them in the chain;
rows are deleted only by one contiguous cut across the whole instance, at
the longest window any workspace still asks for. A legal hold stops that
cut where it sits. Deleting one tenant's rows out of the middle of a
shared sequence would leave a gap no anchor can bridge, which is why it is
not offered.

A workspace sets its window, 90 to 36 500 days and 365 by default, under
**Settings → Audit trail → How long it is kept**, or with
`PUT /api/v1/audit/retention`. Either needs `audit:policy:manage`. The
screen and `GET /api/v1/audit/retention` also show the instance-wide
cut, which is the longest window any workspace keeps; one workspace
choosing ten years therefore keeps every workspace's scrubbed rows for
ten years.

## Rotating the master key

The data keys are what the master key protects, so a rotation re-wraps
them and touches no ciphertext. It needs no maintenance window if the
steps are taken in this order.

1. `supermcp keys verify` with the current settings. It must exit zero.
   If keys are already stranded, fix that first.
2. Deploy every replica with the new key as the active one and the old key
   named in `SUPERMCP_KEK_PREVIOUS`. Both halves of the roll can read
   everything: old pods hold the old key, new pods hold both.
3. `supermcp keys rotate-kek`. It proves each new wrapping opens before
   overwriting the old one, and skips what it has already moved, so it is
   safe to interrupt and run again.
4. `supermcp keys verify` again.
5. Deploy again without `SUPERMCP_KEK_PREVIOUS` and remove the old key
   material from the secret store.

Keep the old key for as long as you keep backups. A restored dump still
carries keys wrapped by it.

## Rotating a data key

The data keys are what seal the rows, so rotating one rewrites every
sealed value in its scope. Reach for it when the sealed values themselves
are suspect — a data key may have been exposed in a heap dump or a backup
— or when a workspace's contract asks for periodic re-keying. It is not a
substitute for `keys rotate-kek`, which changes the master key and
touches no ciphertext.

1. `supermcp keys rotate-dek -org <id> -dry-run`. It refuses to go on if
   any sealed column in the schema has no rotation target, and otherwise
   says how many rows each table would rewrite.
2. `supermcp keys rotate-dek -org <id>`. Use `-all` for every workspace
   and the instance scope, `-instance` for the signing keys alone, and
   `-batch N` to change the rows per transaction from the default 500.
   Every value is opened again before the row holding it is overwritten,
   and every statement has to match exactly the row it named, so a run
   either moves a row or fails with that row's name.
3. `supermcp keys verify`.

It is safe to interrupt and safe to run twice. The command works out for
itself whether it is starting a rotation or finishing one: a superseded
key that rows still sit on means the last run stopped part way, so it
carries on onto the key that run minted rather than minting another, and
says so. Run it once more afterwards to move the workspace onto a key of
its own. Only one rotation of a scope runs at a time — the others leave
rather than queue — while different workspaces rotate independently.

The lock is held on the connection for the length of the run, so point
`SUPERMCP_MAINT_DATABASE_URL` at Postgres directly rather than through a
transaction-pooling proxy.

The superseded key is left `decrypt_only` and becomes `retired` only once
a count over every sealed column finds nothing referencing it. A key that
stays `decrypt_only` is telling you rows were left behind; the report says
how many and in which table. Nothing is ever deleted: a retired key still
opens a restored backup, and you should keep the master key that wraps it
for as long as you keep the backups.

## Replacing the token signing key

One ES256 key signs the OAuth access tokens and the audit checkpoints,
and `/.well-known/jwks.json` publishes it with the key that will replace
it and the one it replaced. A sweep every six hours rotates it once it is
90 days old: it publishes a next key, promotes it after it has been
published for a day, so a verifier that cached the key set still knows
the new key, and retires the old key 30 days later.

`supermcp keys rotate-signing` starts the same rotation now. It publishes
a next key, and the first sweep after a day promotes it. If a next key is
already published it keeps that one and changes nothing, because it is
the key clients have been fetching.

`supermcp keys rotate-signing -revoke` is for a key that may be known.
In one transaction it retires every key in the key set (the active key,
the one it replaced, and a next key if there is one) and makes a new key
active with no pre-publish. The JWKS then carries only the new key, and
every access token signed before is refused. Each replica reloads its
keys within a minute, and until then it still accepts the old tokens and
may sign a few more with the old key, which are refused after the
reload. A verifier outside the instance follows when its copy of the
JWKS expires, which the endpoint allows for five minutes. Clients get new access tokens with
their refresh tokens, which the signing key does not touch, or sign in
again. Retiring the older keys as well costs nothing more: they vouch
only for tokens signed before the last promotion, which have expired
unless that promotion was within the hour. Checkpoints signed by a
retired key still verify, because `audit verify` checks them against
every key the table has ever held.

Both forms write `signing_key.rotate` to the audit trail, with
`revoked: true` or `false`, the new key id as the target, and the name
given with `-by` (default `$USER`). A run that changed nothing writes
nothing. The new private key is sealed under the instance data key, so
the command needs the same master key settings as the gateway, and it
proves a KMS key round-trips before using it. `-format json` prints the
result for a script.

## Cache invalidation

Each replica caches two things that decide what a caller may do: a
principal's role bindings with the organisation's tool access rules, and
the organisation's data-loss policies. Entries live for up to thirty
seconds. A revoked role or a tightened policy must not keep applying on
the other replicas for those thirty seconds, so the database tells every
replica when either changes.

**How it works.** Triggers on `roles`, `role_bindings`,
`tool_access_rules` and `dlp_policies` (migration 00020) send a Postgres
notification on the `supermcp_cache` channel naming the cache and the
workspace: `authz:<organization id>` or `dlp:<organization id>`, or
`authz:*` for a built-in role, which every workspace shares. Because they
are triggers, they fire for every path that writes those tables: the
API, group-to-role mapping at single sign-on, service account changes,
foreign-key cascades such as deleting a role or a connector, and SQL an
operator runs by hand. A notification is delivered only when the
transaction commits, and once per workspace however many rows it
touched.

Every replica holds one session that `LISTEN`s on that channel and drops
the named workspace's entries when a notification arrives. Delivery is
milliseconds. A payload it cannot read drops everything.

**The thirty seconds are the backstop.** While the listener is not
connected, the caches still expire. When it (re)connects it drops every
entry, because notifications sent while it was away are not replayed.
It reconnects on its own with backoff (half a second, doubling, capped
at thirty seconds).

**It needs a direct connection.** The listening session is opened on
`SUPERMCP_MAINT_DATABASE_URL`, apart from both pools. `LISTEN` does not
work through PgBouncer or any other proxy in transaction pooling mode:
the proxy hands the server connection that ran `LISTEN` to other
clients, and notifications never reach this one. Point the maintenance
URL at Postgres itself, or at a proxy in session mode. The listener
checks: every thirty seconds of silence it sends itself a notification
from the maintenance pool, a separate session, and waits five seconds
for it to arrive. If it does not, it reports itself disconnected and
reconnects. Behind a transaction-pooling proxy it therefore never
reports connected, and changes reach other replicas within the thirty
seconds alone. On such a deployment set
`metrics.prometheusRule.cacheInvalidation.expected=false`, or the
chart's `SupermcpCacheListenerDown` alert fires on every replica and
never clears.

**What to watch.**

- `supermcp_cache_listener_connected` is 1 on a replica whose listener
  is connected and delivering. 0 for more than a minute means that
  replica sees other replicas' changes only when its entries expire; the
  log says why (`cache invalidation listener disconnected`).
- `supermcp_cache_invalidations_total{cache,source}` counts drops by
  cache (`authz`, `dlp`) and cause: `local` for a write on this replica,
  `notify` for a notification, `reconnect` for the flush after a
  (re)connect. `reconnect` climbing steadily means the listener keeps
  losing its connection.
- The chart's `SupermcpCacheListenerDown` alert fires when a replica has
  reported 0 for ten minutes (`metrics.prometheusRule.for.errors`).

## What the alerts mean

The chart ships eleven rules with `metrics.prometheusRule.enabled=true`.
Each is a symptom rather than a cause.

- **Nothing answering.** No replica responded. Clients cannot reach any tool.
- **A quarter of tool calls failing.** Usually the upstreams, not this
  system. Check the connectors' own services before this one.
- **The slowest calls over ten seconds.** Look at
  `supermcp_upstream_duration_seconds` first: if that moved and the tool
  call duration followed, the problem is outside.
- **A connector's breaker open.** Calls are being refused locally because
  the upstream was failing. It closes itself when the upstream recovers.
- **The rate limiter degraded.** Redis is unreachable, so budgets are per
  replica and the effective ceiling is lower and uneven.
- **The audit writer falling behind.** Events queue before they are
  written and a full queue drops them, which is a gap in the record. This
  one is worth waking someone. `supermcp_audit_events_dropped_total`
  going up means the gap has already happened. With `SUPERMCP_AUDIT_ON_UNAVAILABLE=spool`
  they go to disk instead, and `supermcp_audit_spool_depth` above zero
  means part of the record is somewhere a database backup does not reach.
- **KMS unreachable.** More than half of the calls to AWS KMS are failing.
  Replicas that already hold their data keys carry on; one that restarts
  cannot open any stored credential, so do not restart pods to fix it.
  Check the key's policy and state, the pod's AWS identity, and the route
  to KMS. `supermcp_kek_operations_total` counts real KMS requests,
  which happen only when a data key is not already in memory. A request
  that needed KMS and could not reach it (a failed connection, a
  timeout, throttling, a KMS server error) answers 503 and logs `key
  service unavailable` with the request id and the AWS error; a refusal
  (access denied, a disabled key, a rejected ciphertext) stays a 500.
- **Audit export lagging.** A destination has not accepted an event for
  over fifteen minutes. Nothing is lost: delivery resumes from where it
  stopped. The destination's `lastError` in its workspace says why, and
  `SELECT id, organization_id, consecutive_failures, last_error FROM
  audit_exporters WHERE enabled ORDER BY consecutive_failures DESC` finds
  it across all of them.
- **A database pool saturated.** A replica has used more than nine in ten
  of the `app` or `maint` pool's connections for ten minutes and requests
  are queueing for one. Look for slow queries and long transactions
  first. More connections per replica (`pool_max_conns` in the database
  URL) only helps if Postgres has them to give.
- **The migration job failed.** An install or upgrade stopped at the
  schema, and the previous version is still serving. Read
  `kubectl logs job/<release>-migrate` before the job is removed, which
  happens after `database.migrate.ttlSecondsAfterFinished`. This rule
  reads `kube_job_failed` from kube-state-metrics and never fires without
  it.
- **A cache listener down.** A replica has not been hearing cache
  invalidations for ten minutes, so a revoked role or a changed
  data-loss policy made elsewhere takes up to thirty seconds to apply
  there. Nothing is refused and nothing is lost. Check that
  `SUPERMCP_MAINT_DATABASE_URL` reaches Postgres directly (or a proxy in
  session mode), not PgBouncer in transaction mode, then read that
  replica's log for `cache invalidation listener disconnected`. If the
  deployment goes through a transaction-pooling proxy on purpose, set
  `metrics.prometheusRule.cacheInvalidation.expected=false`; the rule is
  then not rendered.

## Traces

A trace answers what a metric cannot: where inside one slow call the time
went. Name a collector and spans appear for the MCP request, the tool
call and the upstream exchange, sampled at one in a hundred by default.

Trace context is deliberately not sent upstream. A connector points at
somebody else's system, and a header invented here would be data leaving
this instance to a vendor who never asked for it.

## The dashboard

`metrics.dashboard.enabled=true` ships a Grafana dashboard as a ConfigMap
carrying the label the Grafana sidecar watches, so it appears without
anybody importing anything. Thirteen panels, in the order an incident is
usually read: what the instance is doing, what is failing and why,
latency end to end beside the time spent waiting on the upstream (when
those two move together the problem is outside this system), the surface
build, MCP methods, refusals, open breakers, the audit queue, whether
the rate limiter is degraded, master key calls, audit export lag and how
full the database pools are.

The JSON is `charts/supermcp/dashboards/supermcp.json` for anyone not
running that sidecar.

## When something is wrong

**A tool call fails but the connector tests fine.** The credential is per
connector and sealed; a test uses the same path as a call, so look at the
tool's own mapping first. The audit trail records the failure with the
error class.

**Single sign-on stops working.** The provider's signing keys rotate, and
they are cached for ten minutes. If a sign-in fails immediately after a
rotation at the provider, the next attempt usually succeeds. If it does
not, check the issuer still publishes the metadata document.

**A client gets 401 from the MCP endpoint.** The response carries the
address of the resource metadata, which is what a compliant client follows
to discover how to authenticate. A client that ignores it is not
configured for this server.

**The database is lost, or must go back to a backup.** Follow
`docs/compliance/dr-runbook.md`. It covers the restore, the master key
the dump needs, the audit spool and what a restore undoes.

**Someone may have misused the instance.** Follow
`docs/compliance/incident-response.md`. It covers cutting off people,
keys and clients, rotating keys, holding and exporting the audit trail,
and scaling to zero.

**Migrations will not apply.** They take an advisory lock, so a second
process waits rather than racing. A migration numbered below the current
version is refused; that means two branches added migrations at once and
one needs renumbering.

**Pods of the previous release fail once the migration Job has run.**
CI refuses a migration that drops, renames, retypes or empties anything
(`scripts/check-migrations.sh`), so during a rolling upgrade old pods keep
working against the new schema. The exceptions carry
`-- supermcp:breaking` and each has a section in `docs/UPGRADING.md` that
names the migration's number: find it and do what it says.
