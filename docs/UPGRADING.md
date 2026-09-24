# Upgrading

This file records the changes that need something from you beyond running
`supermcp migrate`. Versions with nothing here upgrade by applying the
migrations, which the Helm chart does in a hook before the new pods start.

## Unreleased

Migration 00018 adds `tool_blobs` and needs nothing from you. Two fixes
change what people see, and two change what is on the audit trail and at
rest.

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
