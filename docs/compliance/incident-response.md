# Incident response

What to do when a supermcp instance may have been misused: who acts, how to
contain it with the tools that exist, what to keep as evidence and who to tell.
There is no supplier service behind an instance, so everything here is done by
whoever runs it. Where a step has no command, this document says so and gives the
manual step.

Examples use `$URL` for `SUPERMCP_PUBLIC_URL` and `$KEY` for an API key that
carries the `mcp:org` scope, owned by someone holding the permission named. Run
`supermcp` commands with the pods' environment, as in `dr-runbook.md`.

## Who is involved

| Role | What they do | How they are reached |
|---|---|---|
| **The instance operator** | Runs the cluster, the database and the keys. Decides containment, holds the evidence, and decides whether to notify. The only role with access to everything below. | Your own paging, fed by the chart's alerts |
| **Workspace owners** | Members holding `owner` in an affected workspace. They act inside their workspace and decide what they owe their own users. | `supermcp compliance access-review -org <id> -format csv` lists them |
| **The maintainers** | Fix flaws in supermcp itself. They have no access to your instance or data. | GitHub private vulnerability reporting, as in `SECURITY.md`. Never a public issue. |

## Triage

**A report under `SECURITY.md`** goes to the maintainers. They acknowledge it
within 3 business days, reproduce it on the reported version, and record a
severity in the private advisory. For high or critical, they ship a fix, or send
a plan with dates, within 30 days. Operators learn of the fix from the published
GitHub security advisory. Watch the repository's advisories and upgrade.

**Something you see on your own instance** is yours to grade. Decide the severity
by what the attacker needed first and what they got:

| Severity | Examples | Act |
|---|---|---|
| Critical | Master key or data key exposed; signs of reading across workspaces; an unexplained break from `audit verify`; the image or chart not what was signed | Now. Consider scaling to zero first. |
| High | A credential used by someone it was not issued to: API key, session, OAuth client, upstream credential | Now: cut off the credential, then investigate |
| Moderate | A credential exposed with no sign of use; a flaw that needs an account to exploit | Same day |

If the cause is a flaw in supermcp, also report it privately. Give the output of
`supermcp version` or the image digest (see "Keep the evidence").

## Contain

Do the steps your incident needs, in this order, and write down the time of each
for the record.

### Cut a person off

`PATCH $URL/api/v1/org/members/<userId>` with `{"status":"deactivated"}` needs
`org:members:manage`. In one transaction it switches the membership off, ends the
person's sessions in every workspace, and revokes their API keys and OAuth refresh
tokens in this workspace. Other replicas drop their cached grants within
milliseconds, or within thirty seconds on a replica whose cache listener is down.
An access token already issued still verifies, but it is refused,
because a deactivated member's bindings grant nothing. Repeat the call in each
workspace the person belongs to.

```bash
curl -X PATCH "$URL/api/v1/org/members/$USER_ID" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{"status":"deactivated"}'
```

- **A SCIM-provisioned member** returns `409 scim_managed`. Deactivate them in the
  identity provider. SCIM `active=false`, through `PUT` or `PATCH` on
  `/scim/v2/Users/<id>`, revokes the same credentials.
- **`409 last_owner`** means they are the only active owner, and **`409 self`**
  means the caller is the one being cut off. If that owner is the compromised
  account, no API call can remove it. As the maintenance database user, run
  `SELECT auth_revoke_principal('<org id>', '<user id>', 'incident');` and
  `UPDATE organization_members SET deactivated_at = now() WHERE organization_id =
  '<org id>' AND user_id = '<user id>';`. Neither statement writes an audit event,
  so record them yourself.

### Revoke or rotate an API key

`DELETE $URL/api/v1/api-keys/<id>` takes effect at once. Your own keys need
`apikeys:self:manage`, anyone's need `apikeys:org:manage`. To replace a key that
a legitimate client still depends on, call `POST $URL/api/v1/api-keys/<id>/rotate`
with `{"graceSeconds": 0}`. A grace above 0 leaves a leaked key working for that
long. `GET $URL/api/v1/api-keys` shows each key's last use and client address.

### Cut off a service account

Disabling it is enough: `POST $URL/api/v1/service-accounts/<id>/disabled` with
`{"disabled": true}` (`serviceaccounts:manage`). Its secret gets no new tokens, its
API keys are revoked at once with no grace period, and access tokens already
issued are refused before they expire. It holds no refresh tokens. The audit event
`service_account.update` records `meta.revokedKeys`. Turning it back on brings
none of the keys or tokens back. Issue new keys, and rotate its secret with
`POST .../service-accounts/<id>/rotate` if the secret leaked. `DELETE
$URL/api/v1/service-accounts/<id>` also removes it and its bindings.

### Reject an OAuth client

`supermcp oauth clients list`, then `supermcp oauth clients reject -by <you>
<client_id>`. The client can start no new sign-ins, and its refresh tokens are
revoked. The command prints how many. Access tokens it already holds stay valid
until they expire, at most an hour. To end them sooner, cut off the people behind
them, or replace the signing key below. A client that registered itself is back
if `SUPERMCP_DCR_MODE` is `open`. Use `approval` while you investigate.

### Replace upstream credentials

The credentials a connector holds are the vendor's secret. Re-keying this
instance does not un-leak them. Revoke them at the vendor, then store new ones
with `PUT $URL/api/v1/connectors/<id>/credentials` (`connectors:auth:update`), or
re-authorise an OAuth connector. Each connector is one call, and no command does
all of them.

### Rotate data keys, then the master key

- **`keys rotate-dek`** re-seals the stored values under a new data key. It
  protects against a data key being known, for example from a heap dump, or from
  a database copy together with its master key. The old data key is kept for
  opening old backups, so a backup that was taken stays readable to whoever holds
  it.
- **`keys rotate-kek`** re-wraps the data keys under a new master key and changes
  no ciphertext. It protects future copies of the database from an exposed master
  key. It does not help if the data keys were already unwrapped.

If the master key was exposed, do both, in this order. Follow
`docs/operations.md` for each step.

1. Deploy the new master key as active, with the exposed one in
   `SUPERMCP_KEK_PREVIOUS`.
2. Run `supermcp keys rotate-dek -all`, so the new data keys are wrapped by the
   new master key.
3. Run `supermcp keys rotate-kek`, then `supermcp keys verify`.
4. Deploy without `SUPERMCP_KEK_PREVIOUS`.

Keep the exposed key only in the escrow, because your own backups still need it.
With the chart, a local key's replacement needs a second reference, which means
`ENCRYPTION_KEK_FILE`, and the chart cannot mount one today. Moving to `awskms`,
with the local key in `SUPERMCP_KEK_PREVIOUS`, is the rotation the chart supports.
With `awskms`, restrict the key policy first. Only a local key can be named in
`SUPERMCP_KEK_PREVIOUS`.

### Replace the token signing key

If the key may be known, forged OAuth tokens and checkpoint signatures are
possible. Run `supermcp keys rotate-signing -revoke -by <you>`. It retires every
published key and makes a new one active in one transaction, so it is safe with
every replica running. Every access token issued so far stops verifying within a
minute on each replica, and within five minutes for a verifier outside the
instance that cached the JWKS. Clients refresh, and older checkpoints still
verify. The command records `signing_key.rotate` with `revoked: true`.
`rotate-dek -instance` re-seals the key without replacing it, which is not
enough here. `docs/operations.md` describes both forms of the command.

### Hold the audit trail

Nothing younger than 90 days is ever scrubbed or deleted. A hold is urgent only if
the window you need is older than that, or the investigation will run past it.
`POST $URL/api/v1/audit/legal-hold` with `{"from":"…","to":"…","reason":"…"}`
(`audit:export`) holds the calling workspace's events in the window and records
`audit.legal_hold.placed`. It holds the events that exist when you call it. Call
it again later to cover events written since. `DELETE` with the same body
releases the hold. For instance-level events, or a workspace you are not a member
of, run this as the maintenance user:
`UPDATE audit_events SET legal_hold = true WHERE ts BETWEEN '<from>' AND '<to>';`

### Export the audit trail for the window

`GET $URL/api/v1/audit/export?from=<RFC3339>&to=<RFC3339>` (`audit:export`)
streams one workspace's events as NDJSON, newest first. It also accepts
`category`, `action`, `actorId`, `targetId` and `outcome`, and records
`audit.exported`. `GET $URL/api/v1/tool-calls` lists tool calls. There is no
instance-wide export. For all workspaces, or for instance-level events, run
`\copy (SELECT * FROM audit_events WHERE ts BETWEEN '<from>' AND '<to>' ORDER BY seq) TO 'window.csv' CSV HEADER`
in `psql` as the maintenance user. An audit destination (webhook, syslog or CEF,
Splunk HEC, OTLP) holds an independent copy of what it accepted.

### Scale to zero

`kubectl scale deploy/<release> --replicas=0`. If `autoscaling.enabled` is true,
do it after `helm upgrade --reuse-values --set autoscaling.enabled=false`, or the
HPA scales it back up. With Compose, run `docker compose stop supermcp`. Every MCP
call, sign-in and admin request stops. Replicas flush queued audit events as they
stop. Exports pause and resume from their cursor later. The database and the keys
are untouched, so scaling to zero does nothing about a copy someone already has.

## Keep the evidence

Take these before containment changes more, keep them where only the
investigators can read them, and record the `sha256sum` of each:

- `supermcp audit verify -format json > verify.json`
- `supermcp compliance config-snapshot -format json -out config.json` and
  `supermcp compliance crypto-report -format json -out crypto.json`: the settings
  and every key's state, with secrets as digests
- `supermcp compliance access-review -format csv -out access.csv`: who could do
  what at that moment
- The audit exports and tool-call lists for the window, and the spool files if the
  spool is on
- Pod logs. supermcp writes them to standard output only, so they exist only if
  your log pipeline kept them:
  `kubectl logs -l app.kubernetes.io/instance=<release> --prefix --since=<window>`
- The running image digest:
  `kubectl get pods -l app.kubernetes.io/instance=<release> -o jsonpath='{..imageID}'`
- A `pg_dump` taken now, kept under the same controls as your backups

**What the audit chain proves:** every row from the first surviving one to the
head is in order and unaltered since it was written. That includes content, which
is checked by digest. Checkpoints were signed with the instance's signing key.
**What it does not prove:** that an event was ever written, because events lost
in an outage without the spool leave no row. It says nothing about actions taken
directly in SQL, which are not audited. Someone with database access and the
signing key could rebuild the chain from a point onward, or remove the head
together with its checkpoints. Scrubbed rows prove their place and not their
content. An audit destination's copy is the evidence that does not live in the
same database.

## Tell the workspaces

The operator decides whether and when to notify. Each workspace's owners decide
what they owe their own users, customers and regulators. You can give each
workspace:

- Its own events for the window: who signed in, what changed, which tools were
  called and what was refused. Use the export above, filtered to that workspace.
- What those records contain. That depends on the workspace's payload policy
  (`GET /api/v1/audit/policy`). The default keeps the shape of arguments and not
  their values.
- Which connectors, and therefore which vendors, could have received data.
- What is no longer there to look at: content older than the workspace's
  retention window was scrubbed and cannot be recovered. See `retention.md`.

Do not send one workspace another's events. The export is per workspace for that
reason.

## Record the incident

Keep one record per incident, with these headings:

1. Summary: what happened, in two sentences
2. Timeline: detection, each containment step, recovery, all in UTC
3. How it was detected: alert, report, audit finding
4. Scope: workspaces, principals, connectors, vendors and data affected
5. Root cause
6. Containment and recovery: each step, including manual SQL, with who ran it
7. Evidence: the files above, where they are, and their digests
8. Notifications: who was told, when, by whom and what
9. Follow-up: changes to configuration, alerts or this runbook, each with an owner
   and a date

## Which containment applies

| Incident | Contain with |
|---|---|
| Leaked API key | Revoke or rotate an API key. Export the window filtered by `actorId` for the key's owner. If the owner's account is in question too, cut a person off. |
| Compromised operator: someone with cluster or database access | Scale to zero if they may still be in. Change the database passwords and the cluster access. Rotate data keys, then the master key. Replace the token signing key. Replace upstream credentials. Keep the evidence, including `audit verify` against a destination's copy. |
| Upstream credential leaked | Replace upstream credentials. If it leaked from this instance's storage, handle it as database exposure. |
| Supply-chain compromise of the image | Scale to zero. Check the running digest with `cosign verify <image>@<digest> --certificate-identity-regexp 'https://github.com/supermcpco/supermcp/.github/workflows/release.yml@.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com`. Redeploy a verified release, pinned by digest (`image.tag: <version>@sha256:<digest>`). Then treat it as a compromised operator: that image held the master key or the KMS permission. |
| Database exposure | Rows sealed under a data key stay closed without the master key. Everything else is readable: tool-call records, audit diffs and payloads, names and addresses. Passwords (argon2id), API keys, session and refresh-token secrets are stored only as hashes. If the master key may also be exposed, rotate data keys then the master key, and replace upstream credentials and the token signing key. Tell the workspaces either way. |
