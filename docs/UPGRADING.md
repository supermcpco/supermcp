# Upgrading

This file records the changes that need something from you beyond running
`supermcp migrate`. Versions with nothing here upgrade by applying the
migrations, which the Helm chart does in a hook before the new pods start.

## Unreleased

Migration 00018 adds `tool_blobs` and needs nothing from you. Two fixes
change what people see, and two change what is on the audit trail and at
rest. Tools can now be created, edited and deleted, which brings
migration 00019 and a handful of changes to existing behaviour, listed
under "Tools can be edited" below. Two catalogue adapters that could not
authenticate are removed. Migration 00020 adds triggers that make a
revoked role or a changed data-loss policy apply on every replica at
once; see "Access changes reach every replica at once" below.

### Access changes reach every replica at once

A revoked role binding, a narrowed role, a changed tool access rule or a
changed data-loss policy used to keep applying on replicas other than
the one that made the change for up to thirty seconds, until their
caches expired. Migration 00020 adds triggers to `roles`,
`role_bindings`, `tool_access_rules` and `dlp_policies` that send a
Postgres notification on commit, and each replica now holds one extra
database session that listens for it and drops the affected
workspace's entries. The thirty-second expiry stays as the backstop.

What it needs from you:

- **One more connection per replica**, opened on
  `SUPERMCP_MAINT_DATABASE_URL` (or `DATABASE_URL` when that is unset),
  held for the life of the process. Allow for it in `max_connections`.
- **That URL must reach Postgres directly**, or through a proxy in
  session mode. `LISTEN` does not work through PgBouncer in transaction
  mode. The replica still serves; it just falls back to the thirty
  seconds, logs `cache invalidation listener disconnected`, and
  `supermcp_cache_listener_connected` stays 0. The operations guide
  ("Cache invalidation") has the details.
- Nothing for the migration itself. It is additive: an older replica
  still running during the roll ignores the notifications and keeps its
  expiry.

New series: `supermcp_cache_invalidations_total{cache,source}` and
`supermcp_cache_listener_connected`.

Within one replica, the data-loss policy routes now share the tool-call
path's reader, so a policy change there applies to the next tool call
on that replica rather than after the expiry.

### Four more alerts, and the metrics behind them

With `metrics.prometheusRule.enabled=true` the chart now also ships
`SupermcpKMSUnreachable`, `SupermcpAuditExportLag`,
`SupermcpDBConnPoolSaturated` and `SupermcpMigrationJobFailed`; the
operations guide says what to do about each. They read new series:

- `supermcp_kek_operations_total{provider,op,outcome}`: master key wraps
  and unwraps. With AWS KMS each one is a KMS request.
- `supermcp_audit_export_lag_seconds{kind}`: age of the oldest event a
  destination of that kind has not accepted. Every replica runs one query
  a minute to measure it.
- `supermcp_db_pool_*{pool}`: acquired, idle, total and maximum
  connections, acquires, and acquires that had to wait, for the `app` and
  `maint` pools.

`SupermcpMigrationJobFailed` reads `kube_job_failed` from
kube-state-metrics. Without kube-state-metrics it never fires.

### A password maximum age now applies

A workspace could set one and nothing enforced it. It is enforced now,
measured from the last change or, for a password never changed, from
when the account was made. In a workspace that set a maximum age, anyone
whose password is older than it will be asked to change it at their
next request, and can do nothing else until they have. Check
`GET /api/v1/org/password-policy` in each workspace before upgrading if
that would surprise people.

### Pending OAuth clients can be approved

`SUPERMCP_DCR_MODE=approval` is the default, and nothing could approve a
client registered under it. List and approve the ones waiting:

```bash
supermcp oauth clients list -status pending
supermcp oauth clients approve smc_...
```

The token endpoint now also refuses a client that is not approved.
Before, only authorisation did.

### Refused token requests are recorded up to a budget

Every refused token request was an audit event, with nothing but the
optional rate limiter between a client and the trail. Now the first ten
refusals per client and minute are recorded in full, and further ones in
that minute are counted and reported as one `oauth.token` failure event
carrying `meta.suppressed` when the next refusal arrives. A detection
rule that counted refusal events should add `meta.suppressed` to its
count.

### Blob results are sealed

Binary tool results awaiting collection (`/api/v1/blobs/{id}`) are now
encrypted under the workspace's data key, in Redis and in Postgres
alike. A blob stored by the previous version cannot be opened by this
one, so a link handed out in the fifteen minutes before the upgrade
answers 500 after it, once, and the log names the blob. Nothing to do
beyond knowing that. `keys rotate-dek` does not re-seal blobs, because
they outlive nothing; wait fifteen minutes after a rotation before
retiring the superseded key.

### The password age is checked less often

A password found within its maximum age is trusted for a minute on the
replica that checked it. What that changes: a password crossing its
maximum age, or a policy tightened in another replica, is enforced
within a minute rather than on the next request. An expired password is
still re-read on every request, so a change is seen at once.

### Tools can be edited

A connector's tools can be created, edited and deleted through the API
and the connector screen. The routes and the permissions they need are
in `docs/api.md`. What changes for an existing instance:

**Migration 00019** adds three columns to `tools`: `source`, `edited_at`
and `edited_by`. It only adds, and it backfills `source`: `catalog` for
every tool of a connector installed from the catalogue, `import` for
every other. `source` defaults to `import`, so a replica still on the
previous version, which does not know the column, writes a valid row.
The cost is that a catalogue install made on an old replica during the
roll is labelled `import`. Nothing depends on the difference yet beyond
what the screen shows, but if you want the labels right, run the
backfill again once every replica is on the new version, as the
maintenance role:

```sql
UPDATE tools t SET source = 'catalog'
  FROM connectors c
 WHERE c.id = t.connector_id AND c.catalog_slug IS NOT NULL
   AND t.source = 'import';
```

**Only custom tools can be deleted.** A tool from the catalogue or an
import can be disabled, as before, and not deleted, because a re-sync or
a re-import would bring it back.

**Enabling or disabling a tool now reaches clients at once.** It
records a revision, and it moves the version of every MCP server the
connector is on, which is what a served tool list is cached under.
Before, a change could take up to 30 seconds to show in `tools/list`.
The permission is now checked against the tool and its connector, so a
binding scoped to the connector covers it; before, only a binding on
the tool or the workspace did.

**Approval requests are withdrawn when their tool changes.** A request
that is pending, or approved and not yet run, is cancelled when its tool
is deleted or edited in a way that changes what a call does. An
approval replays by tool, so otherwise a yes given to the old
definition would run the new one. Whoever raised it asks again.

**Dry-run previews redact more.** A preview used to hide only headers
whose names looked like credentials. It now replaces every credential
value and every value upstream authentication prepared, wherever it
appears in the rendered request — the URL, any header, the body, the SQL
and its arguments — with `<redacted:env.NAME>` or
`<redacted:auth.NAME>`. Values shorter than four characters are left
alone. Anything that compared previews byte for byte will see the
difference.

**An absolute operation path must stay on a known host.** A tool that
is created or edited on an HTTP or SOAP connector may not send its request, and
the connector's credential with it, to a host that is not the base
URL's, one the connector's other tools already use, or the one the tool
had before. Existing tools are not checked until someone edits them.

**Unique violations are 409, not 500.** Any write that collided with a
record already held unique used to fail as an internal error. It is now
a `409`, whose message does not name the constraint or the value.

**Definitions keep the order they were always stored in.** A saved
definition goes into the same `jsonb` column a catalogue install always
used, so the free-form parts — the input and output schemas, the query,
the body, the variables — come back with their keys in `jsonb` order,
shortest first, rather than as they were typed. That is how installed
tools have always been served; editing does not change it.

**Static tools on HTTP connectors answer with their value.** A tool
with `kind: static` returns the text its definition carries, on any
transport. Only the database engine used to honour it; on an HTTP
connector the call became a `GET` to the base URL, sent with the
credential, and returned whatever came back. The WooCommerce, WordPress,
Amazon Seller and API-Football reference cards are such tools. They now
answer as written and send nothing upstream, and the tool editor saves a
static tool on any connector.

**Generated API clients need regenerating.** The tool routes are new,
and the tool list and the revision restore return more fields.

### The history names who made a change

A revision kept the id of whoever made it but never their name, so the
history screens showed a date and nobody. A revision now records the
member's name, or their address when they gave none, as it is written.
Revisions written before the upgrade look the member up when they are
read, so they show a name too for as long as that person is still a
member; a former member's rows show none. Nothing to do. Erasure already
covers the column, as it did while it was empty.

## 1.2.0

No migration. Two things were removed; neither is something a running
instance uses.

### The database import command is gone

`import-legacy` and the legacy-key decryption behind it are removed. There
is no source database to import from, so a command that had only ever
met fixtures came out rather than shipping unverified. Nothing in an
existing deployment referred to it.

### `v1Fingerprint` is no longer an adapter field

The 257 shipped adapters carried a `metadata.v1Fingerprint` marker that
existed only for that import to match on. The field is gone from the
schema, the shipped adapters and the catalogue index. Strict validation
rejects unknown metadata keys, so an adapter of your own that copied the
field fails `supermcp adapter validate --strict` until the line is
deleted. Nothing else about the adapter changes.

### Two catalogue adapters are gone

`immobilienscout24` needs OAuth 1.0a and `sorare` a login that hashes
the password with a fetched bcrypt salt. Neither is implemented, so
neither connector could authenticate, and both are out of the catalogue
now: 255 adapters instead of 257. Installing either by slug answers 404.

A connector already installed from one of them is untouched. Nothing
looks its catalogue entry up again after install, so its rows, tools and
credentials stay as they were, and a call through it fails at
authentication exactly as it did before. Delete it when convenient.

## 1.1.0

The migrations apply in the chart's hook as usual. Two things need a
decision from you, and both default to off.

### Everybody signs in again, once more

A sign-in that leaves this instance and comes back — to an identity
provider and back — now has to return to the browser that started it. A
provider issues an answer to whoever asks for one, so without this,
somebody signs in as themselves, delivers the answer to another person's
browser, and that person is signed in as them: every credential they
connect afterwards lands in the attacker's workspace. The state parameter
does not stop it, because the attacker holds a state of their own.

Migration 00017 adds the column that carries it and replaces two
`SECURITY DEFINER` functions. A sign-in already in flight when the
upgrade lands still completes; every new one is bound.

### New, and off unless you turn them on

| Setting | Default | What it does |
|---|---|---|
| `SUPERMCP_AUDIT_ON_UNAVAILABLE=spool` | `degrade` | Writes audit events to disk when the database will not take them, and replays them. It needs a volume that outlives the pod: `audit.spool.enabled=true` in the chart provisions and mounts one. |
| `SUPERMCP_OTLP_ENDPOINT` | empty | Sends traces to a collector. `tracing.endpoint` in the chart. |
| `metrics.dashboard.enabled` | false | Ships the Grafana dashboard as a ConfigMap with the label the sidecar watches. |

### `keys rotate-dek` wants a direct connection

Rotating a data key holds an advisory lock on one connection for the
length of the run, so point `SUPERMCP_MAINT_DATABASE_URL` at Postgres
rather than at a transaction-pooling proxy while it runs. The runbook is
in `docs/operations.md`.

### Generated API clients need regenerating

SAML, the compliance reports, the dry run, the audit destinations, the
legal hold and the role editor all added endpoints.

## 1.0.0

### Everybody is signed out once

Sessions were held in the database by the value the cookie carried, so
read access to that table was enough to impersonate any live session. The
row now holds the digest of that value, the way API keys and refresh
tokens already were. Existing cookies no longer match a row, so every
signed-in person signs in again, once. No migration is needed and no rows
are removed; the stale ones expire and are swept up within a week.

### Chart: the key service settings changed name

`encryption.awskms.keyArn` is now `encryption.awskms.keyId` (a key id, an
alias or an ARN), and `encryption.awskms.region` and
`encryption.awskms.timeout` render the settings the binary actually
reads. The chart previously set `SUPERMCP_KEK_AWS_KEY_ARN`, which nothing
reads, and no region at all, so the AWS KMS path could not start.

`encryption.provider` now accepts only `local` and `awskms`, which are
the two the binary implements. `gcpkms`, `azurekv` and `vault` fail the
render with a message naming the setting, rather than producing a pod
that crash-loops.

### Generated API clients need regenerating

Three packages each exported a type called `Policy` and two exported a
`Finding`, which the OpenAPI registry refuses: registering the new
governance routes brought the server down at boot. The schemas are now
`PasswordPolicy`, `ScanPolicy`, `ApprovalPolicy`, `Finding` (data-loss)
and `ImportFinding`. Anything generated from a previous
`/api/openapi.json` needs generating again.

### Tool-call rows now obey the payload policy

`tool_invocations` stored the caller's arguments in full whatever the
workspace's audit payload policy said; the policy governed the audit
event alone. It now governs both. A workspace whose policy is
`metadata` (the default) or `none` will see fewer columns filled from
this release onwards; rows written before it are unchanged, and nothing
deletes them.

### The audit trail is rebuilt (migration 00006)

The hash chain covered the JSON columns as the writer had serialised them,
then read them back to check. Postgres does not return `jsonb` the way it
was given: it normalises whitespace, orders keys by length and drops
duplicates. Every event that carried a diff, a payload or metadata
therefore failed verification as soon as it was read, which defeats the
purpose of the table.

The fix stores those columns as `json`, so the bytes round-trip, and adds
a `content_hash` column. The chain now covers that digest rather than the
content, which also means content can be removed later without breaking
the links either side of it.

**What this means for you.** Events written before this migration cannot
be verified and are deleted by it, along with the anchors over them. There
is no released version that wrote them, so this affects development
instances only. After upgrading, `supermcp audit verify` starts from the
first event written by the new code.

Retention changed shape at the same time. An organisation's own window is
now honoured by removing the *content* of its older events while leaving
them in the chain; rows are deleted only by a single contiguous cut across
the whole instance, at the longest window any organisation still asks for.
Deleting one tenant's events out of the middle of a shared sequence leaves
a gap that no anchor can bridge, which is what the old behaviour did.
