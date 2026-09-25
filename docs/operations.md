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
| `ENCRYPTION_KEK_FILE` | empty | The local master key read from a file, which wins over `ENCRYPTION_KEK`. The key is recorded under the file's path, so moving the file is a rotation, not a rename. The file may be readable by its owner and group and nobody else. Chart: `encryption.local.file`. |
| `SUPERMCP_KEK_PREVIOUS` | empty | Old master keys that may decrypt and never seal, for the length of a rotation: base64, `<reference>|<base64>` for a key that came from a file, or `awskms:<key>[@<region>][#<deployment>]` for a KMS key. Chart: `encryption.previous`. |
| `SUPERMCP_REDIS_URL` | empty | Shared rate-limit budgets. Without it each replica keeps its own, divided by `SUPERMCP_EXPECTED_REPLICAS`. |
| `SUPERMCP_EXPECTED_REPLICAS` | 1 | Only used when Redis is absent. Set it to the replica count or the cluster together allows several times the intended ceiling. |
| `SUPERMCP_ADMIN_LISTEN` | empty | Where `/metrics` is served. Empty means the exposition is off; it must never share the public listener. |
| `SUPERMCP_OPEN_REGISTRATION` | off | Whether anyone who reaches the sign-in page can create a workspace. The first registration on an empty instance is always allowed. |
| `SUPERMCP_OTLP_ENDPOINT` | empty | An OTLP/HTTP collector for traces. Empty is off; `OTEL_EXPORTER_OTLP_ENDPOINT` is read too. A collector that cannot be reached is a log line, never a failed boot. |
| `SUPERMCP_TRACE_SAMPLE` | 0.01 | The fraction of traces kept. |
| `SUPERMCP_AUDIT_ON_UNAVAILABLE` | `degrade` | What happens when the database will not take an event. See "When the database refuses audit events" below. |
| `SUPERMCP_AUDIT_SPOOL_DIR` | `/var/lib/supermcp/audit-spool` | Where `spool` writes. It must be a persistent volume: a spool in a pod's ephemeral layer buys nothing over `degrade`. Replicas may share it; each keeps to a directory of its own. |
| `SUPERMCP_AUDIT_SPOOL_MAX_BYTES` | 256 MiB | What one replica may hold on disk. Past this, events are dropped, counted and recorded as a gap. |
| `SUPERMCP_AUDIT_SPOOL_ORPHAN_AGE` | `10m` | How long a replica's spool heartbeat may go unrefreshed before a live replica takes over its events. At least `30s`; a shorter value is raised to that. |
| `SUPERMCP_INSTANCE_ID` | the host name | This replica's name: its spool directory, and the `meta.instance` of the gaps it records. Must be unique among running replicas. The chart sets it to the pod name. |
| `SUPERMCP_DCR_MODE` | `approval` | Whether an MCP client can register itself: `open`, `approval` or `closed`. |
| `SUPERMCP_MCP_MAX_SESSIONS` | 5000 | How many MCP sessions one replica holds for servers set to stateful. See "Stateful MCP sessions". |
| `SUPERMCP_MCP_MAX_SESSIONS_PER_CALLER` | 16 | How many of those one credential may hold. |
| `SUPERMCP_MCP_MAX_SESSIONS_PER_ORG` | a tenth of the maximum | How many one workspace may hold. |
| `SUPERMCP_MCP_SESSION_IDLE` | `15m` | How long such a session may go without a request before it is closed. |
| `SUPERMCP_MCP_SESSION_MAX_AGE` | `12h` | How long such a session may last, however busy. |
| `SUPERMCP_MCP_ELICITATION_TIMEOUT` | `45s` | How long a call held for approval waits for the person behind a stateful client to confirm it. |

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

### The audit spool

The spool directory may be one volume shared by every replica (the
chart's claim is `ReadWriteMany`). Each replica writes only under
`<SUPERMCP_AUDIT_SPOOL_DIR>/<SUPERMCP_INSTANCE_ID>/`, in files named
`<order>-<count>-<instance>.ndjson`, and only ever replays files under
that directory, so no two replicas write or replay the same file. It
refreshes a `.heartbeat` file there every quarter of the orphan age, at
most a minute apart, while it runs.

A replica that is gone (scaled down, rescheduled, crashed) leaves its
directory behind. Once that directory's heartbeat is older than
`SUPERMCP_AUDIT_SPOOL_ORPHAN_AGE`, the first live replica to notice
renames it into its own directory as `adopted-<name>-<time>/` and
replays it; the rename is the claim, and only one replica's rename can
succeed. A replica looks at start and then at every heartbeat, and logs
`took over audit events spooled by a replica that is gone`. The adopted
directory is removed once it is empty. So events spooled by a pod that
is replaced reach the trail up to the orphan age plus a minute after it
went, not at once.

Segments written directly into the shared directory by an earlier
release are taken over the same way once the file is as old as the
orphan age.

Two running replicas with the same `SUPERMCP_INSTANCE_ID` would share a
directory and could replay a file twice. The chart sets it from the pod
name, and a host name is unique too; set it by hand only if neither is.

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

### On the Helm chart

The chart reads the active key from `encryption.local.existingSecret` as
`ENCRYPTION_KEK`, or from `encryption.local.file` as a file mounted at
`/etc/supermcp/kek/<key>`, and the previous key from
`encryption.previous`. Every key is recorded under a reference, and the
two keys in a local rotation need different ones: `env:ENCRYPTION_KEK`
for the environment form, `file:/etc/supermcp/kek/<key>` for the file.
So the incoming key always arrives as a file, under a Secret key name
the outgoing key never had. `KEK_<year>_<month>` is a good habit.

The commands assume the release is called `supermcp`; `deploy/supermcp`
is its Deployment.

1. Check nothing is stranded:

   ```bash
   kubectl exec deploy/supermcp -- /supermcp keys verify
   ```

2. Create the new key and, in its own Secret, the old one as
   `SUPERMCP_KEK_PREVIOUS`. If the old key is `ENCRYPTION_KEK` in
   `supermcp-kek`, the value is its base64 on its own:

   ```bash
   kubectl create secret generic supermcp-kek-2026-09 \
     --from-literal=KEK_2026_09="$(openssl rand -base64 32)"
   kubectl create secret generic supermcp-kek-previous \
     --from-literal=SUPERMCP_KEK_PREVIOUS="$(kubectl get secret supermcp-kek \
       -o jsonpath='{.data.ENCRYPTION_KEK}' | base64 -d)"
   ```

   If the old key was itself a file, say `KEK_2026_03` in
   `supermcp-kek-2026-03`, the value carries its reference:
   `file:/etc/supermcp/kek/KEK_2026_03|<base64>`. `SELECT DISTINCT
   kek_ref FROM data_keys` shows the reference to use, with a `local:`
   prefix you may keep or drop.

3. Roll every replica onto the new key with the old one beside it, and
   wait for the roll to finish:

   ```bash
   helm upgrade supermcp charts/supermcp --reuse-values \
     --set encryption.local.file.secretName=supermcp-kek-2026-09 \
     --set encryption.local.file.key=KEK_2026_09 \
     --set encryption.previous.secretName=supermcp-kek-previous
   kubectl rollout status deploy/supermcp
   ```

   A pod that will not start saying the previous key names the active
   key's reference was given the same Secret key name for both; go back
   to step 2 with a new name.

4. Re-wrap and check, from a pod of the new release:

   ```bash
   kubectl exec deploy/supermcp -- /supermcp keys rotate-kek
   kubectl exec deploy/supermcp -- /supermcp keys verify
   ```

5. Drop the previous key and roll again:

   ```bash
   helm upgrade supermcp charts/supermcp --reuse-values \
     --set encryption.previous.secretName=
   kubectl rollout status deploy/supermcp
   kubectl delete secret supermcp-kek-previous
   ```

   Move the old key out of the cluster to wherever the backups' keys
   live before deleting `supermcp-kek` or `supermcp-kek-2026-03`. Do not
   change `encryption.local.file.key` again except as the next rotation:
   the pods would start and then fail to open every stored credential.

Moving from `local` to `awskms` is the same shape: in step 3 set
`encryption.provider=awskms` and the `encryption.awskms` values instead
of the file, keep `encryption.previous` pointing at the local key, and
leave it there until step 4's `keys verify` passes.

### From one KMS key to another

AWS automatic key rotation keeps the key id and needs none of this. This
is for a move to a different key: a new CMK, a key in another account,
or a single-Region key in another region. The entry form is described in
"Moving to another KMS key" in `docs/install.md`.

1. Create the new key and give the pods' role `kms:Encrypt` and
   `kms:Decrypt` on it. Keep `kms:Decrypt` on the old key. Do not point
   the old key's alias at the new key; give the new key its own alias.
2. `supermcp keys verify` with the current settings. It must exit zero.
3. Deploy every replica with the new key in `SUPERMCP_KMS_KEY_ID` and the
   old key in `SUPERMCP_KEK_PREVIOUS`, spelled as `SUPERMCP_KMS_KEY_ID`
   spelled it:

   ```
   SUPERMCP_KMS_KEY_ID=alias/supermcp-2026
   SUPERMCP_KEK_PREVIOUS=awskms:alias/supermcp
   ```

   Add `@<region>` if the old key is in another region than the new one.
   Leave `SUPERMCP_KMS_DEPLOYMENT` as it was. If you change it in the
   same deploy, write the old value after `#` in the entry.
4. `supermcp keys rotate-kek`, then `supermcp keys verify`. verify lists
   each scope's data keys and the reference they are under, and ends with
   `N of N data keys are under the active key` once nothing is left on
   the old key.
5. Deploy again without `SUPERMCP_KEK_PREVIOUS`. Remove the old key's
   grant from the pods' role, but do not schedule the old key for
   deletion while a backup that needs it exists: a dump taken before
   step 4 has data keys wrapped by it.

On the chart, put the entry in the Secret `encryption.previous` names
(`--from-literal=SUPERMCP_KEK_PREVIOUS=awskms:alias/supermcp`) and set
`encryption.awskms.keyId` to the new key in step 3.

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
`tool_access_rules` and `dlp_policies` (migration 00020), and on
`dlp_detectors` (migration 00031), send a Postgres
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

## Stateful MCP sessions

An MCP server is stateless unless someone sets it to stateful (the
server screen, or `sessions` on `PATCH /api/v1/servers/{id}`). A
stateless server answers every request on its own, on any replica, and
this section does not apply to it.

A stateful server keeps a session per client, which is what lets it ask
the client a question in the middle of a call. The session lives in the
memory of the replica that answered the client's `initialize`, and only
there: the MCP library keeps no shared store, and none is added here. So:

- **Route each client to one replica.** With one replica there is
  nothing to do. With more, the load balancer has to send a client's
  requests to the replica it started on. Behind ingress-nginx, cookie
  affinity (`nginx.ingress.kubernetes.io/affinity: cookie`) is the
  steadiest, for clients that keep cookies; hashing the client address
  (`nginx.ingress.kubernetes.io/upstream-hash-by: "$binary_remote_addr"`)
  works for every client whose address stays put. A client reaching the
  Service directly can use `service.sessionAffinity: ClientIP`. The
  chart's values carry all three, commented out. Hashing the
  `Mcp-Session-Id` header does not work: the replica is chosen before the
  id exists.
- **A request that reaches the wrong replica is answered `404`**, with
  the JSON-RPC error `Session not found; initialize a new one`. That is
  the transport's signal to start a new session, and the MCP clients in
  common use do so; what the client loses is the session, not any data.
- **Limits, and who pays for room.** Per replica there are three: the
  table (`SUPERMCP_MCP_MAX_SESSIONS`, 5000), each caller
  (`SUPERMCP_MCP_MAX_SESSIONS_PER_CALLER`, 16) and each workspace
  (`SUPERMCP_MCP_MAX_SESSIONS_PER_ORG`, a tenth of the table). A caller
  is one credential: one API key, one OAuth client, or one browser
  session's method. Busy sessions, ones with a request in flight such as
  a call waiting on a person's answer, count towards every limit and are
  never closed to make room. A caller at its limit makes room by closing
  its own session idle longest and nobody else's; with none of its own
  idle it is refused with `429`. A workspace at its limit is treated the
  same way, within the workspace. When the whole table is full, a
  session is closed only if it is the newcomer's own, or belongs to a
  caller or a workspace holding more than its share (the table divided
  among those holding places in it); with no such idle session the
  newcomer is refused with `503`. So one tenant filling a replica closes
  its own sessions, not anyone else's.
- **Lifetimes.** A session is closed after `SUPERMCP_MCP_SESSION_IDLE`
  (15 minutes) without a request, and after `SUPERMCP_MCP_SESSION_MAX_AGE`
  (12 hours) whatever it is doing; a request on an expired session is
  answered `404`, and one still running finishes first.
- **Ownership.** A session is its caller's and its server's. Presented
  by anyone else, including the same person on another API key or
  another OAuth client, or on another server, it is unknown.
- **What a session does not change.** Each request still authenticates,
  and the tools it may see and call are worked out for that request, so a
  permission taken away or a tool removed applies to a session at once,
  in `tools/list` as well as to calls. A tool added after a session
  opened appears in its `tools/list` only once the client starts a new
  session. Each request's handler is cancelled when the request ends or
  reaches its deadline (the router's 60 seconds), as on a stateless
  server.

`supermcp_mcp_sessions` is the number of sessions a replica holds, one
series per replica. `supermcp_mcp_sessions_closed_total{reason}` counts
why they ended: `idle`, `capacity` (made room for a new one), `client`
(the client ended it), `shutdown` (the replica drained), `expired` (past
the maximum age) and `gone` (the session had already ended, usually an
`initialize` that failed). A
`capacity` rate that keeps climbing means the limit is too low for the
traffic or the affinity is not holding and clients keep starting over.

A stateful session is also what lets a call held for approval ask the
person behind the client to confirm it (docs/api.md, "Calls held for
approval"). That keeps the call open for up to
`SUPERMCP_MCP_ELICITATION_TIMEOUT` (45 seconds; at most 55, and in any
case five seconds short of the request's own deadline, so the held
result is still written before the router's 60 second timeout). Keep the
load balancer's and any proxy's read timeout on `/mcp/` above 60
seconds, or the proxy cuts the call and the client sees an error instead
of the held result.

**On a rollout,** a replica told to stop first stops waiting on any such
question (the call returns held, as it would have without one), takes no
new requests, lets the ones in flight finish within
`SUPERMCP_SHUTDOWN_TIMEOUT`, then closes
every session it holds (`reason="shutdown"`). Each of those clients is
routed to another replica on its next request, is answered `404`, and
initialises again. Scaling down does the same to the sessions on the
replicas removed. Changing a server between stateless and stateful takes
effect for new connections; a client connected across the change has to
reconnect.

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

**A client reports a 500.** The response says only "something went
wrong; the request id is …", with the same id in `X-Request-Id`, and the
audit event (if the request was a change) carries it as `meta.requestId`.
Search the log for that id in `req_id`: the `request failed` line has
the underlying error in `err` (`request panicked`, `scim request failed`,
`mcp request failed` and `oauth request failed` for the other paths).
A `/readyz` that answers 503 logs `not ready: …` with the cause.

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
process waits rather than racing; it logs `another migrator holds the
migration lock; waiting for it to finish` and polls. A `serve` replica
with `SUPERMCP_MIGRATE_ON_START` that waited and still finds migrations
pending exits with an error naming the other migrator: its logs say why
it stopped. A migration numbered below the current
version is refused; that means two branches added migrations at once and
one needs renumbering.

**Pods of the previous release fail once the migration Job has run.**
CI refuses a migration that drops, renames, retypes or empties anything
(`scripts/check-migrations.sh`), so during a rolling upgrade old pods keep
working against the new schema. The exceptions carry
`-- supermcp:breaking` and each has a section in `docs/UPGRADING.md` that
names the migration's number: find it and do what it says.
