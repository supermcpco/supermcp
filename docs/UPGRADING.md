# Upgrading

This file records the changes that need something from you beyond running
`supermcp migrate`. Versions with nothing here upgrade by applying the
migrations, which the Helm chart does in a hook before the new pods start.

## How migrations are checked

Upgrades roll: the migration Job runs first, and pods of the previous
release keep serving against the new schema until they are replaced. So a
migration may only add. CI runs `scripts/check-migrations.sh` (locally,
`make check-migrations`) on every pull request and on `main`. It refuses a
migration whose `-- +goose Up` section drops a table, schema or column,
renames anything, changes a column's type, sets a column `NOT NULL`, adds
a `NOT NULL` column without a default, drops an index it did not create,
or deletes rows with `DELETE FROM` or `TRUNCATE`.

A migration that has to do one of those carries the line
`-- supermcp:breaking`, and this file has a section naming its number that
says what it does to your data and what to do; the check refuses either
one without the other. So:

- Unless a section here says a migration breaks the rule, it only adds,
  and pods of the previous release keep working during the rollout.
- If one says so, read it before you upgrade and follow it; it also says
  whether migrating down undoes it.

Two shipped migrations break the rule, both in 1.0.0: 00006 and 00008
each delete the audit trail written by pre-release builds. Their sections
are under 1.0.0 below.

## Unreleased

Migration 00018 adds `tool_blobs` and needs nothing from you. Two fixes
change what people see, and two change what is on the audit trail and at
rest. Tools can now be created, edited and deleted, which brings
migration 00019 and a handful of changes to existing behaviour, listed
under "Tools can be edited" below. Two catalogue adapters that could not
authenticate are removed. Migration 00020 adds triggers that make a
revoked role or a changed data-loss policy apply on every replica at
once; see "Access changes reach every replica at once" below. Migration
00021 adds invites; see "Colleagues can be invited" below. Migration 00022
adds an index to `audit_events`; see "The audit export reads by workspace
and sequence" below. Migration 00024 records when a session last signed
in; see "Sensitive actions ask for a recent sign-in" below. Migration
00025 replaces an index on `tool_invocations` for the new usage
analytics; see "Usage analytics read an index of their own" below.

### Sensitive actions ask for a recent sign-in

A browser session now has to have signed in, or confirmed who is using
it, within the last five minutes for these actions:

- creating, rotating or revoking credentials
- setting connector credentials or connecting a connector through OAuth
- granting an OAuth client access
- approving a held tool call
- changing roles or who holds them
- changing the security, single sign-on, data-loss, approval and audit
  settings

An older session gets `403` with the code `reauth_required`. The
interface asks for the password and then repeats the action. For a
single sign-on user, it sends them back through their provider.
`docs/api.md` ("Recent sign-in") lists the operations.

API keys, OAuth access tokens and service accounts are not affected.
Nobody signs them in, so there is nobody to ask.

What it needs from you:

- **Nothing for migration 00024 in most cases.** It adds these columns:
  - `sessions.authenticated_at`: not null, default `now()`
  - `sessions.auth_provider_id`: nullable
  - `replaces_session` on `sso_requests` and on `saml_requests`: nullable

  It also adds seven functions. The new column is added with the
  constant default `'-infinity'`, which changes only the catalogue: no
  row is rewritten. The default then becomes `now()`. Live sessions
  (not revoked, not expired) then take `created_at` as their
  authentication time. That backfill runs in batches of 1000 rows, each
  committed on its own, and outside a transaction, so a sign-in waits
  for one batch at most. Revoked and expired sessions keep
  `'-infinity'`. If the migration is interrupted, run `supermcp migrate`
  again; every statement can be repeated safely.
- **Rollout order does not matter.** An older replica still running
  during the roll ignores the new columns. The default fills them for
  the sessions it creates, and the older replica keeps using the
  functions it already knows.
- **Sessions that exist at upgrade time count as old.** They signed in
  when they were created, so the first sensitive action after the
  upgrade asks the person to confirm who they are. Nobody is signed out.
- **Single sign-on sessions are fresh only if the provider says when
  the person authenticated.** A session counts as fresh only when that
  time is recent:
  - OpenID Connect: the `auth_time` claim of the verified ID token
  - SAML: `AuthnInstant`

  Re-authenticating through a provider sends `prompt=login` and
  `max_age=0` (OpenID Connect) or `ForceAuthn` (SAML). The server does
  not trust that the provider honoured these. It accepts the answer only
  when the provider's time is within the window and the person,
  workspace and provider match the session being replaced. Otherwise the
  old session is left as it was and the browser is sent to `/reauth`
  with the reason. Some OpenID Connect providers include `auth_time` only
  when asked, so a sign-in there may need one re-authentication before
  the first sensitive action.
- **GitHub, and any plain OAuth2 provider, cannot make a session
  fresh.** They never say when the person authenticated. People who sign
  in that way must sign in with a password to do these actions, or ask
  an administrator. The interface tells them so. If your administrators
  sign in only through GitHub, give at least one of them a password
  before upgrading.
- **A new setting, `SUPERMCP_AUTH_FRESH_WINDOW`** (default `5m`, allowed
  `1m` to `24h`). Like the session lifetimes, it applies to the whole
  instance by design. A value that does not parse, or is outside that
  range, stops the server from starting.
- **Scripts that drive the API with a session cookie** and do these
  operations need to call `POST /api/v1/auth/reauth` first if the session
  is older than the window. Such scripts would be better off with an API
  key.
- **The re-authentication endpoint uses the sign-in lockout and rate
  limit.** Wrong passwords count against the same `login_lockouts`
  counters as the sign-in form, and requests draw on the
  `SUPERMCP_RATELIMIT_SIGNIN` budget.

New audit actions: `session.reauth`, for success and failure. A failure
carries `meta.reason`:
- `reauth_mismatch`: a different person, workspace or provider
- `reauth_unconfirmed`: the provider gave no time
- `reauth_not_recent`: the provider's time is older than the window

A refusal of a stale session is recorded as `access.denied` with
`meta.reason = "reauth_required"`. A successful single sign-on
re-authentication also records `session.create` with
`meta.reauth = true`. The session it replaces is ended with the reason
`replaced by re-authentication`.

### Colleagues can be invited

Administrators can now invite a person by email address with a role. The
server sends no email: it returns a link once, and the administrator
sends it. The person opens the link and either signs in with an account
for that address or creates one with a password. This works with
`SUPERMCP_OPEN_REGISTRATION=off`. `docs/api.md` ("Invites") covers the
API.

What it needs from you:

- **Nothing for migration 00021.** It adds the `org_invites` table and
  two functions, and changes nothing that exists. An older replica
  still running during the roll never reads them.
- **Check who holds `org:members:manage`.** Until now, no endpoint
  checked this permission, so granting it had no effect. Now it lets the
  holder list, create and revoke invites, and manage members. The
  built-in `owner` and `admin` roles already have it. Check any custom
  role that includes it. Inviting someone to a role that grants `*`,
  such as `owner`, also requires the inviter to hold `*`.
- **Set `SUPERMCP_PUBLIC_URL`** to the address people use to reach the
  server. Invite links are built from it.
- **A new rate-limit budget,** `SUPERMCP_RATELIMIT_INVITE` (default
  `5/1h` per client address). It covers the two unauthenticated invite
  endpoints. If several people accept invites from behind one NAT at the
  same time, raise it. Failed invite lookups also count toward the
  sign-in lockout for that address, in `login_lockouts` under
  `invite:<address>`.
- **The link's token is in the page path** `/invite/<token>`. Proxies
  in front of the server may log it. See the shared-responsibility
  document.

New audit actions: `invite.create`, `invite.revoke`, `invite.accept`
(failures only), `member.join`, and `account.register` with
`meta.via = "invite"`.

### The audit export reads by workspace and sequence

The audit export sweep and the export-lag metric read one workspace's
events after a cursor. No index covered that, so on a large trail a
caught-up exporter walked every other workspace's newer events on each
sweep. Migration 00022 adds `audit_events_org_seq_idx` on
`(organization_id, seq)`.

It is built with `CREATE INDEX CONCURRENTLY`, so `audit_events` keeps
taking writes during the build and nothing needs a maintenance window.
What that means for you:

- **The migration takes longer than the others** on a large trail: it
  reads the table twice. A million events takes about a second; budget
  in proportion. If the role on `SUPERMCP_MAINT_DATABASE_URL` has a
  `statement_timeout`, it must allow for that.
- **The build waits for transactions already open on `audit_events`**
  to finish before it starts. A session left idle in a transaction
  holds it up; `pg_stat_activity` shows the migration waiting.
- **If the build fails or is cancelled**, Postgres leaves an invalid
  index behind and the migration is not recorded. Run
  `supermcp migrate` again: it drops the leftover and rebuilds.

### Usage analytics read an index of their own

The new analytics screen and `GET /api/v1/analytics/usage` count a
workspace's tool calls, errors and latency over up to 90 days. With the
index that was there, a large workspace's window was read from the whole
table. Migration 00025 replaces `tool_invocations_org_time_idx` with
`tool_invocations_org_time_cover_idx`: the same key,
`(organization_id, created_at DESC)`, plus the status, timing, tool,
connector and server columns, so the analytics read the index alone. The
tool-call list uses the new index the way it used the old one.

Both the build and the drop use `CONCURRENTLY`, so `tool_invocations`
keeps taking writes and nothing needs a maintenance window. What that
means for you:

- **The migration takes longer than the others** on a large table: it
  reads the table twice. Four million calls (a 3 GB table) took about a
  minute on a laptop; budget in proportion. If the role on
  `SUPERMCP_MAINT_DATABASE_URL` has a `statement_timeout`, it must allow
  for that.
- **The index is larger than the one it replaces,** about 90 bytes a call
  against 55. Every tool call still writes to the same number of indexes.
- **The build waits for transactions already open on `tool_invocations`**
  to finish before it starts, and the drop of the old index waits again.
  A session left idle in a transaction holds it up; `pg_stat_activity`
  shows the migration waiting.
- **If the build fails or is cancelled**, Postgres leaves an invalid
  index behind and the migration is not recorded. Run `supermcp migrate`
  again: it drops the leftover and rebuilds. The old index is dropped
  last, so the tool-call list keeps an index throughout.
- **Rollout order does not matter.** Replicas of the previous version
  read the new index as they read the old one, and the analytics endpoint
  answers without the index, only more slowly.
- **The migration carries the `-- supermcp:breaking` marker** because
  `scripts/check-migrations.sh` refuses any `DROP INDEX` of an index it
  did not create; it cannot tell that the replacement has the same key.
  It is the marker, not the migration, that is conservative.
- **The analytics stay index-only as long as autovacuum keeps up** on
  `tool_invocations`. It is an append-only table, which autovacuum visits
  after inserts on Postgres 13 and later; if you have turned autovacuum
  off for it, the queries still answer but read the table for recent
  calls.

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
With `metrics.prometheusRule.enabled=true` the chart also ships
`SupermcpCacheListenerDown`; behind PgBouncer in transaction mode, set
`metrics.prometheusRule.cacheInvalidation.expected=false` to leave it out.

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

### Audit retention can be set from the API and the audit screen

`GET` and `PUT /api/v1/audit/retention`, and a control on the audit
screen, read and set a workspace's `audit.retention_days`. Setting it
needs `audit:policy:manage`, whose description now says so. A value
below 90 or above 36 500 days is refused rather than clamped. A value
already stored out of range is still clamped by the sweep and reads back
clamped. No migration.

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

### API keys can be rotated

`POST /api/v1/api-keys/{id}/rotate` and a Rotate button on the API keys
screen issue a replacement with the same name, scopes and server, show
its secret once, and keep the old key working for a grace period you
choose (none to 7 days; 24 hours if the API caller does not say). The
event is `apikey.rotate`. A revoked, expired or already rotated key is
refused with 409.

Rotation used to shorten the old key and create the new one in two
transactions, so a failed create left the old key cut short with no
replacement. Both now happen in one, and two rotations of the same key at
once can no longer both succeed. Nothing to do.

**Generated API clients need regenerating** for the new route.

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

### The audit trail is rebuilt again (migration 00008)

The time an event was written was outside the hash chain. A row could be
backdated through the maintenance role and still verify, and because
retention cuts by age, one backdated row near the head could make a
routine cut delete most of a stream. The application now writes the
timestamp and the row's hash covers it.

**What this means for you.** Like 00006, this migration deletes every
audit event and anchor, because rows hashed without their time cannot be
verified. No released version wrote such rows, so this affects
development instances only. Migrating down does not bring them back: if
you want to keep them, take a `pg_dump` of `audit_events` and
`audit_anchors` first. After upgrading, `supermcp audit verify` starts
from the first event written by the new code.
