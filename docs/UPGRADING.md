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
or deletes rows with `DELETE FROM` or `TRUNCATE`. It also refuses
`ALTER TABLE ... DROP CONSTRAINT` unless the same Up section then adds a
constraint of the same name back to the same table, which is how a
`CHECK` list is widened; that the new constraint accepts every row the
previous release writes is confirmed in review, not by the script.

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
analytics; see "Usage analytics read an index of their own" below. Migration
00026 lets disabling a service account refuse the tokens it already
holds; see "Disabling a service account cuts it off" below. The chart can mount the master key as a file; see "The chart can mount the master key as a file" below.
Migration 00027 adds a search index to `audit_events`; see "The audit
trail can be searched" below. Migration 00028 lets the history keep data-loss policies, approval policies and sign-in providers; see "Policies and sign-in providers have a history" below.
Migration 00030 stops counting every OpenID Connect sign-in as a second factor; see "OpenID Connect sign-ins count a second factor only by a rule" below.
Migration 00031 adds workspace data-loss detectors; see "Workspaces can write their own data-loss detectors" below.

### OpenID Connect sign-ins count a second factor only by a rule

A sign-in through an OpenID Connect provider used to be recorded as
having a second factor whatever the provider did, so a password at the
provider was enough for the session's principal to carry the MFA flag.
Now each
OpenID Connect provider has a second-factor rule, `mfa` on
`/api/v1/idps` and on the Single sign-on settings screen: the `amr`
values (RFC 8176) and `acr` values that count. A sign-in has a second
factor only when its verified ID token names one of them
(`docs/api.md`, "The second-factor rule"). SAML is unchanged.

What changes when you upgrade:

- **Existing OpenID Connect providers have no rule**, so from the
  upgrade no sign-in through them counts as having a second factor.
  Give each a rule; the one a new provider gets is `amr`
  `["mfa", "otp", "hwk", "sc"]`. Google reports neither claim, so a
  rule changes nothing for it.
- **Existing OpenID Connect sessions stop counting as verified** at
  once, whatever their provider's rule, because nothing recorded what
  the provider said when they signed in. They count again after the
  person signs in afresh, or re-authenticates, through a provider whose
  rule the ID token meets.
- **What reads the flag.** No built-in check in this release refuses a
  request for want of a second factor. What changes is the `mfa` in
  the `amr` of access tokens consented from those sessions, and in
  what `/oauth/introspect` returns for them. If a resource server or
  anything else of yours acts on it, set the rules before you upgrade,
  or right after, and expect people to sign in again before their
  tokens say `mfa`.
- **Access tokens say more.** `amr` in a token consented from a single
  sign-on session now repeats the registered methods the provider
  reported (`pwd`, `otp`, `hwk`, `sc` and so on), and `mfa` when the
  sign-in met the rule. A SAML session's token now carries `pwd`, `sc`
  or `otp` when the assertion's authentication context names one.
  Tokens issued before the upgrade keep the `amr` they had until the
  session re-authenticates.
- **A re-authentication rewrites the `amr` of refresh tokens.** When a
  single sign-on re-authentication replaces a session, the refresh
  tokens it moves to the new session take that session's `amr`, where
  they used to keep the one from consent. A re-authentication without a
  second factor therefore removes `mfa` from the next refreshed token
  and from introspection.
- **The rule has a route of its own**, `PATCH /api/v1/idps/{id}/mfa`,
  which the settings screen uses, so saving the rule cannot undo a
  concurrent change to the rest of the provider. `PUT` is unchanged,
  except that it and the new route answer `404` for a provider that
  does not exist, where `PUT` used to answer `500`.
- **The data export** (`sessions.json`) reports `mfaVerifiedAt` as the
  server reads it, so empty for an OpenID Connect session from before
  the upgrade, and adds `authMethods`.
- **An invalid provider configuration is `400`**, not `500`, on
  `POST` and `PUT /api/v1/idps`.
- The `session.create` audit event of an OpenID Connect sign-in
  carries `meta.mfa`, and `meta.amr` and `meta.acr` when the ID token
  had them, so you can see what your provider sends.

What migration 00030 does:

- Adds two nullable `text[]` columns to `identity_providers`, `mfa_amr`
  and `mfa_acr`, and one to `sessions`, `auth_methods`: the methods the
  provider reported for a single sign-on session. None has a default,
  so adding them rewrites no row and each table is locked only for the
  catalogue change. The migration runs outside a transaction, so the
  lock on `sessions` is not held while the rest runs. If it is
  interrupted, run it again.
- Adds four functions: `auth_idp_load`; an `auth_session_open` taking
  the methods; `auth_session_get`, which reads an OpenID Connect
  session that has no `auth_methods` as having no second factor; and an
  `auth_session_replace` taking the new session's `amr`, which it gives
  the refresh tokens it moves. The existing versions of these functions
  stay as they were, and no row is changed.

**Rollout order does not matter.** A replica of the previous release
still reads providers, opens sessions and reads them through the
functions it used before. Sessions it opens during the roll still count
a second factor there, and not on this release's replicas, which see no
`auth_methods` on them. A re-authentication it handles moves refresh
tokens with their `amr` unchanged, as before. A provider rule set during the roll applies on
this release's replicas only.

Migrating down drops the functions and columns, with every provider's
rule and every session's methods. The previous release reads whether a
session was verified as it is stored: sessions this release opened keep
what it judged, and OpenID Connect sessions from before the upgrade
count as verified again.


### Workspaces can write their own data-loss detectors

A workspace can add detectors of its own, regular expressions for
identifiers the built-ins cannot know (customer numbers, contract ids),
and a data-loss policy names one as `custom:<name>` beside the built-ins
(`docs/api.md`, "Data-loss prevention"). The settings screen has a
Detectors tab for them.

Migration 00031 runs outside a transaction, each statement safe to run
again if it is interrupted:

- it creates `dlp_detectors`, with row-level security forced like the
  other workspace tables, a trigger that sends `dlp:<organization id>` on
  the `supermcp_cache` channel as `dlp_policies` does, and a trigger that
  moves a detector's `version` when its pattern changes without it. A new
  table takes no lock on anything a tool call reads.
- it replaces the check constraint on `revisions.entity_kind` with one
  kind more, `dlp_detector`, in two steps: the swap, `NOT VALID`, is a
  catalogue change under a brief exclusive lock on `revisions`, and the
  check of the existing rows, `VALIDATE CONSTRAINT`, runs under a lock
  that lets writes to `revisions` through.

No rollout order matters. A replica of the previous release neither
reads nor writes the new table, and the constraint's list is a superset.
During the roll, a policy that names a custom detector is screened with
it only on new replicas. An old replica does not know the name and skips
it, and where a policy names nothing but custom detectors it runs every
built-in instead, as it does for an empty list. Create custom detectors,
and the policies that use them, once the roll is done.

A new setting, `SUPERMCP_RATELIMIT_DLP_TEST` (default `60/1m` per
caller), is the budget for `POST /api/v1/dlp/preview` and the new
`POST /api/v1/dlp/detectors/test`. The preview drew on the API's
budget before.

A string in which one detector, built-in or custom, matches more than
100 times is now masked or refused whole, with one finding of rule
`too_many_matches`, instead of one finding per match.

What changes for callers of the API:

- `GET /api/v1/dlp/detectors` answers with a further list, `custom`,
  beside `detectors`, which is unchanged. Patterns in it are shown only
  to holders of `dlp:manage`, and samples to nobody.
- A policy's `detectors` accepts `custom:<name>`. A name the workspace
  does not have is `400`, as an unknown built-in is.
- `POST /api/v1/dlp/preview` runs the workspace's detectors too.

### The audit trail can be searched

The audit list and export take `q`, a free-text search over each event's
action, actor, target and the string values of its `meta`, never its
`diff` or `payload` (docs/api.md, "Audit search"); the audit screen has a
search box. Migration 00027 adds what it reads: a function,
`audit_search_document`, a GIN index over it, `audit_events_search_idx`,
and a function the list calls to search, `audit_search`. It adds no
column, so nothing about the rows changes: the hash chain,
`supermcp audit verify`, retention, scrubbing and legal holds work on
them as before.

`audit_search` is `SECURITY DEFINER`: it runs as the role that ran the
migration, because under the row-level security on `audit_events` the
application role's own query could not use the index. It reads the
workspace from the same setting the policy does, so it answers for no
workspace the caller could not already read, and only `supermcp_app` may
call it. That role is the one in `SUPERMCP_MAINT_DATABASE_URL`, which
the chart already expects to have `BYPASSRLS`. If yours does not,
searches still answer correctly, only slowly.

The index is built with `CREATE INDEX CONCURRENTLY`, so `audit_events`
keeps taking writes and nothing needs a maintenance window. What that
means for you:

- **The build is slow for its size.** Every event's text is parsed into
  words, twice, so it takes far longer than 00022's index did. A million
  events (260 MB of rows, 570 MB with the other indexes) took about 70
  seconds on a laptop and made an index of about 100 MB; budget time and
  disk in proportion. With
  the Helm chart the migration runs as a pre-upgrade hook, which
  `helm upgrade` waits for only as long as its `--timeout` (5 minutes by
  default): raise it for a large trail. Any deadline on your own
  migration job, the startup probe of a replica that migrates on start,
  and a `statement_timeout` or `lock_timeout` on the role in
  `SUPERMCP_MAINT_DATABASE_URL` must allow for it too; a pod killed
  mid-build leaves an invalid index behind.
- **Look for old snapshots before you start.** A concurrent build waits,
  in two phases, for every transaction in the *whole database* that holds
  a snapshot older than the step, not only for those that touch
  `audit_events`. A running `pg_dump`, a long report, or a session left
  idle in a transaction anywhere holds it up. The query in "Usage
  analytics read an index of their own" above shows them, before you
  start and while the migration waits.
- **Other replicas wait for it.** The migration holds the migration
  advisory lock from start to finish, so a replica starting meanwhile
  with `SUPERMCP_MIGRATE_ON_START` blocks until it is done.
- **Each event costs a little more to write** once the index is there:
  about 50 microseconds of database time per event in the same test, on
  top of about 80 without it. The audit writer batches events, so a
  request does not wait for it.
- **If the build fails or is cancelled**, Postgres leaves an invalid
  index behind and the migration is not recorded. Run `supermcp migrate`
  again: it drops the leftover and builds it again from the start.
- **Rollout order does not matter.** Replicas of the previous version
  never read the index and write to it without knowing; the new version
  answers a search whichever replica took the write.
- **Migrating down** drops the index and both functions; searches then
  fail, so roll the application back first.

Three things change with it that you may notice:

- **A failed tool call's error is redacted before it is kept,** on the
  tool-call row, in the audit event's `meta.error` and in the answer to
  the MCP client. A URL in it is cut to scheme, host and path: until
  now a connector whose API key travels in the query string recorded the
  key in plain text whenever a call failed before an answer came back
  (connection refused, timeout, TLS). Rows written before this release
  keep what they recorded; if you have such connectors, look for the key
  in `tool_invocations.error` and in the audit trail, and rotate it if it
  is there. The audit events cannot be edited without breaking the
  chain; retention removes them in time.
- **An audit exporter's URL is shown cut down** in the API, the audit
  screen and its `audit.exporter.*` events: scheme, host and path, the
  query as `?***`, and a path segment that looks like a token (as in a
  Slack or Discord webhook) as `***`. Only the display changes; what is
  delivered to is what you configured.
- **An audit export is bounded** to 100,000 events and ten minutes. One
  cut short ends with a `{"truncated": true, "afterSeq": N, ...}` line;
  export again with `afterSeq=N` for the rest (docs/api.md, "Audit
  search"). A tool that reads exports should stop at that line rather
  than treat it as an event.


### Policies and sign-in providers have a history

Data-loss policies, approval policies and OIDC and SAML sign-in
providers now keep revisions like connectors, servers and roles do, with
a History entry on their settings screens and a restore route for each
(`docs/api.md`, "Revisions").

Migration 00028 widens the check constraint on `revisions.entity_kind`
to the four new kinds. It drops and re-adds the constraint, which takes
an exclusive lock on `revisions` while Postgres checks the existing rows:
configuration changes wait for it, tool calls do not. It is quick unless
the history is very large. No rollout order matters: the new list is a
superset, so a replica of the previous release, which writes only the
old kinds, works against it. Changes made through such a replica during
the roll are not recorded in the history, as they were not before.

What changes for callers of the API:

- A restore of a sign-in provider never restores a secret. An OIDC
  provider keeps the client secret stored when the restore runs; a SAML
  provider keeps its signing key pair. A deleted provider cannot be
  restored from its history.
- `PUT /api/v1/idps/{id}` without a `clientSecret` is now refused with
  `422` when it changes the issuer or sets an endpoint on a host the
  provider does not use yet, and so is a restore that would. The stored
  secret is only ever sent where it was configured to go; send the secret
  for the new provider with the change.
- The `idp.update` and `saml.update` audit events now carry a before and
  after diff of the provider, including its endpoints and the identity
  provider certificates it trusts, instead of the provider as it stood
  afterwards.
- A deleted data-loss or approval policy can be restored, and comes back
  under its old id.
- Restores ask for `revisions:rollback` and the permission that edits the
  entity (`dlp:manage`, `org:settings:manage` or `idp:manage`), and a
  recent sign-in from a browser session.
- Nothing is backfilled at upgrade time. A policy or provider that
  predates the upgrade has its state recorded as revision 1, by nobody,
  when it is first changed or deleted, so that state can be restored.

Migration 00029 ties OAuth tokens to the browser session that consented,
so ending the session ends them; see "Ending a session ends the OAuth
tokens it granted" below.

### The chart can mount the master key as a file

Chart 1.3.0 adds `encryption.local.file.secretName` and
`encryption.local.file.key`, which mount the local master key read-only
at `/etc/supermcp/kek/<key>` and set `ENCRYPTION_KEK_FILE`, and
`encryption.previous.secretName` and `encryption.previous.key`, which set
`SUPERMCP_KEK_PREVIOUS` from a Secret. Without them the chart renders
what it rendered before; an existing install needs nothing.

- Use the file values only with this release's binary or later. Earlier
  binaries refuse any key file its group can read, and Kubernetes makes a
  Secret file group-readable whenever the pod has an `fsGroup`, which the
  chart sets.
- Do not switch a running install from `encryption.local.existingSecret`
  to the file values with the same key and nothing else. The key is
  recorded under the form it came in, so the pods would start and then
  fail to open every stored credential. Changing form is a rotation:
  follow "Rotating the master key", "On the Helm chart", in
  `docs/operations.md`.
- Outside Kubernetes, a key file with mode 0440 or 0640 is now accepted.
  A file others can read, or a group can write, is still refused.


### The migrate Job has its own ServiceAccount, and pods pause before stopping

Chart 1.4.0. A fresh install of an earlier chart could never finish: the
migrate Job ran before Helm created the release's ServiceAccount and was
set to run as it, so Kubernetes refused the pod until the install timed
out. Upgrades worked only because the account already existed. The Job
now gets its own account, `<release>-migrate`, created just before it and
deleted when it succeeds; it has no annotations and no token.

- If an admission policy limits which accounts may run in the namespace,
  allow `<release>-migrate` before you upgrade. With
  `serviceAccount.create=false`, nothing changes.
- Pods take up to five seconds longer to stop (`preStopSleepSeconds`),
  so a rolling upgrade no longer drops a request to a pod that has just
  been told to stop. Keep `preStopSleepSeconds` plus
  `SUPERMCP_SHUTDOWN_TIMEOUT` (20 s) under `terminationGracePeriodSeconds`
  (30 s). Kubernetes 1.29 cannot render the pause, so the chart leaves it
  out there; pass `--kube-version` when you render with `helm template`.
- If a first install of an earlier chart timed out on
  `serviceaccount "..." not found`, run `helm uninstall` and install this
  release.

CI now installs the chart on a kind cluster (1.29 and current), runs the
migrate Job, the smoke test, and one rolling upgrade under a readiness
probe. The required checks are `helm-install (1.29)` and
`helm-install (current)`.
### Connector secrets read `***`

A connector's `auth` and `transport` are meant to hold only
`{{env.*}}` references. Some held literal values instead: a refresh
token a provider rotated, a key from an imported document, or a password
in a DSN or base URL. The API returned those values as they were stored,
and the audit trail recorded them too. Now these places show every
secret value as `***`:

- the connector responses
- the `connector.install`, `connector.import`, `connector.update` and
  `connector.delete` audit diffs
- the re-sync preview's `notApplied`
- a connector's revision history

These values count as secrets:

- passwords, tokens and client secrets
- API key values
- `Authorization`-like headers
- the password inside a URL or connection string

What is stored does not change. Restoring a revision still puts the real
values back.

What it needs from you: nothing, unless a script reads a secret out of a
connector response. It now gets `***`. No endpoint accepts `auth` or
`transport` from a client, so nothing can write `***` back. Audit events
written before the upgrade keep what they recorded.

### Disabling a service account cuts it off

Disabling a service account used to stop only new tokens from its
secret. Its API keys, and access tokens it already held, kept working for
up to an hour. Now disabling it also does these things:

- It revokes every API key the account holds, with no grace period.
- It refuses access tokens it was already issued, at the MCP endpoint and
  at introspection, even before they expire.

Turning it back on restores neither. Deleting an account now also
refuses its outstanding access tokens.

What it needs from you:

- **Nothing for migration 00026.** It adds
  `service_accounts.token_epoch` (integer, not null, default 0). The
  default is a constant, so no row is rewritten. The table is locked only
  for the catalogue change.
- **Rollout order does not matter.** An older replica ignores the
  column. It issues tokens without the epoch claim, which counts as epoch
  0, and it does not check the claim. So until the roll finishes, a
  disabled account's old token can still pass on an older replica.
- **Clients holding tokens** from a disabled and re-enabled account get
  `401` and must request a new token, which a client credentials client
  does anyway when one is refused.

The audit event `service_account.update` for a disable carries
`meta.revokedKeys`: how many API keys it revoked. Revoked keys carry the
reason `service account disabled`.

### Ending a session ends the OAuth tokens it granted

An MCP client connected through the consent page used to keep its
tokens after the person who consented signed out: the refresh token
lived its 30 days unless the client was revoked or the person was
deactivated. Now the authorization code and every refresh token
descended from it remember the browser session that consented, and:

- Signing out, ending a session from the sessions list, a password
  change ending the other sessions, and deactivating a member (from the
  API or SCIM `active=false`) revoke the refresh tokens those sessions
  granted, by family.
- Access tokens carry the session's public id as `sid`, and the MCP
  endpoint and introspection refuse one whose session was ended, before
  it expires.
- A re-authentication through a single sign-on provider replaces the
  session; the refresh tokens move to the new session rather than end.
  An access token naming the old session is refused, and the client
  refreshes into one naming the new session.
- A session that merely expires ends nothing: its tokens live on, which
  is what `offline_access` is for. The session pruner now keeps such a
  session while a live refresh token names it, since a token whose
  session is not on record is refused.

Access tokens also carry `amr`; see the OAuth section of `docs/api.md`.

Other changes that come with it:

- **The sessions list shows a public id.** `GET /api/v1/auth/sessions`
  returns each session's new public id in `id` and `current`, and
  `DELETE /api/v1/auth/sessions/{id}` takes it. The server's own key for
  a session no longer leaves the server. An id copied from the list
  before the upgrade no longer matches anything. Read the list again.
- **Introspection is scoped.** `/oauth/introspect` answers
  `{"active": false}` unless the API key belongs to the token's
  workspace and holds `tools:read` on the token's server (a key scoped
  to MCP use passes with `mcp:tools:read` or `mcp:tools:invoke`). A
  resource server that introspected with another workspace's key has to
  use one from the token's workspace.
- **Signing out can fail visibly.** If the session cannot be ended,
  `POST /api/v1/auth/logout` now answers `500`, keeps the cookie and
  records `session.end` as a failure, instead of reporting success. On
  the audit trail, `session.end`, `session.revoke` (now also written for
  a password change) and `member.deactivate` or `scim.user.deactivate`
  carry `meta.revokedTokens`: how many live refresh tokens they revoked.

What it needs from you:

- **Nothing for migration 00029**, though it takes longer than most on a
  large `sessions` table. It adds `session_id` (text, null) and `amr`
  (text[], not null, default `{}`) to `oauth_codes` and
  `oauth_refresh_tokens`, and `public_id` (text, default a random UUID)
  to `sessions`. None of these rewrites a row, and each table is locked
  only for the catalogue change. Existing sessions get their
  `public_id` in batches of 1000, each committed on its own, so a
  request waits for one batch at most. It builds the unique index
  `sessions_public_id_idx` and `oauth_refresh_session_idx` with
  `CREATE INDEX CONCURRENTLY`, which blocks neither sign-ins nor token
  issuance. For both, the migration runs outside a transaction. It adds
  `auth_session_end`, `auth_session_end_others`, `auth_principal_end`,
  `auth_session_replace` and `auth_session_ended`. It points
  `auth_session_revoke`, `auth_session_revoke_others` and
  `auth_revoke_principal`, which keep their signatures, at the new
  functions. If it is interrupted, run it again.
- **Rollout order does not matter**, with these gaps until the roll
  finishes. A replica of the previous release issues codes and refresh
  tokens without a session. When it rotates a token that has one, the
  child names no session but stays in the family, and ending the
  session still revokes it. Tokens it issues from a new consent are tied
  to no session, as every token issued before the upgrade is: they end
  when the client or the member is revoked, or expire. It does not check
  `sid`, so an ended session's access token still passes there. A single
  sign-on re-authentication handled there ends the replaced session's
  refresh tokens instead of moving them, so that client has to connect
  again. It still prunes sessions that live refresh tokens name, and the
  tokens of a pruned session are then refused.
- **People who sign out** of the web interface now disconnect the MCP
  clients they connected from that session. They connect again from the
  client.

Migrating down restores the three functions as they were, and drops the
new functions, indexes and columns, including every session's public id.

### A refused audit batch is retried, and a loss is always recorded

Under `SUPERMCP_AUDIT_ON_UNAVAILABLE=degrade` (the default) or `block`, a
batch the database refused used to be dropped with one `audit append
failed` log line and no record in the trail. It is now kept at the head
of the queue and retried: for about eight seconds under `degrade`, until
it succeeds under `block`. Whatever `degrade` finally drops is counted in
the new `supermcp_audit_events_dropped_total` and recorded in the trail
as an `audit.events_dropped` event, which now also carries the range and
time of the lost events. Nothing to do; a database blip that used to
cost a batch of events now costs none. `docs/operations.md`, "When the
database refuses audit events", says what each mode does.

### Each replica keeps its own audit spool directory

With `audit.onUnavailable: spool`, replicas sharing the spool volume
could overwrite each other's segments (both named their first one alike)
and replay each other's files, so an event could be lost or recorded
twice. Each replica now writes under a directory named by
`SUPERMCP_INSTANCE_ID`, which the chart sets to the pod name through the
downward API (the host name when unset), and replays only that
directory. The directory of a replica whose heartbeat is older than
`SUPERMCP_AUDIT_SPOOL_ORPHAN_AGE` (chart: `audit.spool.orphanAge`,
default `10m`) is taken over by one live replica and replayed.

- **Nothing to do** under the chart. Segments left at the top of the
  spool directory by the previous release are taken over the same way
  once they are ten minutes old.
- **If you copy spool files by hand** (the disaster recovery runbook),
  they are now in subdirectories: copy every `*.ndjson` under the spool
  path.
- The chart also renders `audit.spool.maxBytes` as a plain integer now.
  It used to come out as `2.68435456e+08`, which the binary could not
  read, so a changed bound was ignored and 256 MiB applied.

### Sensitive actions ask for a recent sign-in

A browser session now has to have signed in, or confirmed who is using
it, within the last five minutes for these actions:

- creating, rotating or revoking credentials
- setting connector credentials or connecting a connector through OAuth
- widening what keys bound to a server can reach:
  - creating a server
  - changing which connectors a server serves, or turning it on
  - restoring a server or a connector from its revision history
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
- **Replicas starting together no longer hang on it.** Before this
  release, a second migrator (another `supermcp migrate`, or a replica
  with `SUPERMCP_MIGRATE_ON_START`) that started while the first was
  applying a `CREATE INDEX CONCURRENTLY` migration waited for the lock in
  a way that held a snapshot, and the build waited for that snapshot: both
  stayed stuck until one was killed, and Postgres reported no deadlock. A
  waiting migrator now polls for the lock and holds nothing between
  polls. If you hit this on an earlier release, cancel the waiting
  migrator (`pg_cancel_backend` on the session in `pg_stat_activity`
  whose `wait_event` is `advisory`); the build then finishes. A replica
  migrating on start now also waits for another migrator to finish and
  does not migrate after it; if migrations are still pending then, it
  exits with an error.

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

- **Look for old snapshots before you start.** A concurrent build or drop
  waits, in two phases, for every transaction in the *whole database*
  that holds a snapshot older than the step, not only for those that
  touch `tool_invocations`. A running `pg_dump`, a long report, or a
  session left idle in a transaction anywhere holds it up. Check first:

  ```sql
  SELECT pid, state, xact_start, backend_xmin, left(query, 60)
  FROM pg_stat_activity
  WHERE backend_xmin IS NOT NULL AND pid <> pg_backend_pid()
  ORDER BY xact_start;
  ```

  Anything old in that list, wait for or end it. During the migration
  the same query shows what it is waiting behind.
- **Other replicas wait for it.** The migration holds the migration
  advisory lock from start to finish, so a replica starting meanwhile
  with `SUPERMCP_MIGRATE_ON_START` blocks until it is done.
- **Size the timeouts to the table.** It reads `tool_invocations` twice.
  Four million calls (a 3 GB table) took about a minute on a laptop;
  budget in proportion. With the Helm chart the migration runs as a
  pre-upgrade hook, which `helm upgrade` waits for only as long as its
  `--timeout` (5 minutes by default): raise it for a large table. Any
  deadline you put on your own migration job, and the startup probe of a
  replica that migrates on start, must allow for it too: a pod killed
  mid-build leaves an invalid index behind. If the
  role on `SUPERMCP_MAINT_DATABASE_URL` has a `statement_timeout` or a
  `lock_timeout`, both must allow for it as well; a `lock_timeout` that
  is too short fails the waits described above.
- **The index is wider than the one it replaces,** by six fixed-size
  columns and ids. It does not include the tool name, which is unbounded
  text. Every tool call still writes to the same number of indexes.
- **If the migration fails or is cancelled**, Postgres leaves an invalid
  index behind and the migration is not recorded. Run `supermcp migrate`
  again: it drops the leftover and rebuilds. The old index is dropped
  last, so the tool-call list keeps an index throughout. A rerun always
  starts by dropping the new index, so if the failure was at the very
  last step (dropping the old index), the rerun builds the finished
  index again from scratch; budget the same time as the first attempt.
  Postgres cannot make that drop conditional inside a migration.
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

The analytics endpoint draws on a rate-limit budget of its own,
`SUPERMCP_RATELIMIT_ANALYTICS` (default `30/1m` per caller), instead of
the general API budget. Each replica also runs at most two analytics
queries per workspace at once, refusing a third with 429, and reuses an
answer for 60 seconds.

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

- `supermcp_kek_operations_total{provider,key,op,outcome}`: master key
  wraps and unwraps. With AWS KMS each one is a KMS request. `key` is
  `active` or `previous`, so during a move between two KMS keys a
  failing old key shows apart from the new one.
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
