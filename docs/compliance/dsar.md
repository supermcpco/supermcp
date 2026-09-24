# Subject access and erasure

Two commands about one person: what this instance holds about them, and
removing their name from it.

```
supermcp dsar export -user <id|email> [-out <dir|file.zip>] [-format text|json]
supermcp dsar erase  -user <id|email> [-yes] [-format text|json]
```

Both act on one account, found by its id or its email address. Both
record what they did in the audit stream, because reading out or
rewriting one person's record is a privileged act and belongs in the
record like any other.

Neither revokes anything. A session or an API key that worked before
still works afterwards: ending somebody's access is a separate decision,
and SCIM or `active: false` is what makes it.

## Export

The export is a directory of JSON files, or a zip when the path ends in
`.zip`. A zip is written to a temporary file and renamed into place, so
an interrupted run never leaves a half-written archive that looks like a
complete answer to a statutory request.

| File | What it holds |
|---|---|
| `subject.json` | The account |
| `memberships.json` | The workspaces it belongs to |
| `role-bindings.json` | The roles it holds and where each applies |
| `identities.json` | Linked single sign-on accounts |
| `provisioning.json` | What a provisioning system sent |
| `sessions.json` | Every sign-in session, live and ended |
| `api-keys.json` | The API keys issued to it, as metadata |
| `oauth-tokens.json` | The OAuth refresh tokens issued for it, as metadata |
| `tool-calls.json` | The tool calls it made |
| `approvals.json` | Approvals it raised or decided |
| `configuration-changes.json` | Configuration changes it made |
| `audit-events.json` | Every audit event naming it |
| `manifest.json` | What the export contains and what it leaves out |
| `README.txt` | How to read it, for the person it is about |

What is deliberately not in it, and why, is in `manifest.json` as well as
here:

- **Password and credential digests.** `users.password_hash`,
  `password_history.hash`, `api_keys.hash`,
  `oauth_refresh_tokens.token_hash` and `service_accounts.secret_hash`
  are not readable, and handing them over would be handing over material
  somebody could attack offline.
- **`sessions.id`.** A session is held by the digest of the cookie's
  secret, and the row's id *is* that digest. It says nothing about the
  person and would be a live credential's key if it were handed out.
- **`approval_requests.args_enc`.** The arguments sealed when an approval
  was raised. They are encrypted under the workspace's data key and are
  not opened by this command.
- **Events naming the person only in a diff.** An event whose actor and
  target are somebody else, and whose diff mentions this person, is that
  other person's record as much as this one's. A subject access request
  is not a way to read a colleague's.

What a tool call's record holds is decided by the workspace's audit
payload policy, which by default keeps the shape of the arguments and
none of their values. An export from a workspace that set the policy to
`full` holds every argument of every call.

## Erasure

Erasure pseudonymises the columns that name the person. The pseudonym is
derived from the account id — which stays in the database either way, as
the key every other row points at — so it is stable, unique, and a second
run of the command changes nothing.

```
name  →  erased-<12 hex>
email →  erased-<12 hex>@erased.invalid
```

The domain is reserved by RFC 2606 and can never be delivered to. The
local part is unique per account, so the unique index on the address
holds after an erasure as it did before.

It runs in one transaction: the person is either erased everywhere the
command reaches or nowhere. A half-finished erasure would leave the
address in one table and a pseudonym in another, which is the worst of
both — the person is still identifiable and the record no longer reads
consistently.

It asks before it acts. The prompt requires the operator to type the
address that is about to disappear, because a yes/no prompt is answered
by reflex and this is the one command here that cannot be undone. `-yes`
skips it.

### What it rewrites

| Table | Columns |
|---|---|
| `users` | `name`, `email` |
| `user_identities` | `email` |
| `scim_users` | `user_name`, `raw` |
| `audit_events` | `actor_display`, `target_display` |
| `revisions` | `actor_display` |
| `approval_requests` | `requester_display` |

`scim_users.raw` is nulled rather than rewritten: it is whatever the
provisioning system sent, and what a future provisioning system will send
is not something this command can rewrite field by field.

The erasure runs through the maintenance role, for two reasons. The
person's rows are in every workspace they belonged to, which no tenant
policy admits; and after migration `00006` the application role may
update `audit_events` only to null a scrubbed row's content. Rewriting a
display column is a maintenance act by construction, which is the right
shape for it.

## The audit chain

The chain is why the list above stops where it does.

Each row's hash is computed over its predecessor's hash and these
columns:

```
id, ts, organization_id, category, action, outcome,
actor_kind, actor_id, target_kind, target_id,
content_hash  (a digest of diff, payload and meta)
```

Everything else in the row is outside the hash: `actor_display`,
`target_display`, `on_behalf_of`, `request_id`, `session_id`, `ip`,
`user_agent`, `legal_hold` and `scrubbed_at`.

`actor_display` and `target_display` exist separately from the ids beside
them for exactly this reason: a name may lawfully have to change, an
identity may not. Rewriting them changes no input to any hash, so the
chain still verifies. Run `supermcp audit verify` afterwards; a report
that says the chain is intact is worth less than the command that proves
it.

### What is left, and why

The command reports each of these with a count, every time it runs.

| Where | Why it stays |
|---|---|
| `audit_events.actor_id`, `target_id`, `on_behalf_of` | Inside the chain hash. Changing one would make every row from that point on fail verification, and a tamper-evident record that has been tampered with is no record at all. These are generated identifiers, not names. |
| `audit_events.diff`, `payload`, `meta` | The chain covers a **digest** of these three columns, so their content cannot be rewritten. See below. |
| `revisions.snapshot`, `revisions.diff` | A revision is the record of what a configuration was, and rewriting it would falsify the history it exists to keep. Nothing hashes it, so an operator who decides the address must go can remove it; this command does not decide that. |
| `tool_invocations.principal_id` | The link between a call and who made it. Removing it would leave calls nobody can account for. |
| `tool_invocations.input`, `output` | Arguments and results, kept according to the payload policy. **Nothing removes these rows, ever.** |
| `sessions.ip`, `sessions.user_agent` | An address and a browser string are personal data and are not a name. Neither is hashed anywhere, so both can be cleared by an operator who decides they should be; this command pseudonymises names and addresses. |
| `users.password_hash`, `password_history.hash` | argon2id digests. Clearing them would silently change whether the account can sign in, which is a separate decision from erasure. |
| `sessions`, `api_keys`, `oauth_refresh_tokens` | An erasure revokes nothing. |

### The address inside an audit diff

An administrator who changed somebody's email address left both addresses
in that event's `diff`. The chain covers a digest of that column, so the
diff cannot be rewritten — but it can be *removed*, by the mechanism that
already exists for it. `audit.Reader.Scrub` nulls `diff` and `payload`
and marks the row `scrubbed_at`; verification then proves the row's place
in the sequence and says it could not check what the row held, counting
those rows separately rather than reporting the chain as unqualified
valid.

That scrub takes a workspace and a date, not a person. Running it from
here would erase everybody else's content in the same window, so this
command does not run it. It reports the count of rows whose content still
contains the address and leaves the decision where it belongs.

If an erasure request requires that content to go, the options are: wait
for the workspace's retention window to scrub it, shorten that window, or
run the retention sweep against a date that covers the events in
question and accept that it takes everything else of that age with it.

## What is still missing

- The erasure does not reach `tool_invocations.input`. Nothing removes
  those rows at all — see `retention.md`.
- There is no API or screen for either command; both are the CLI only,
  which means an operator with shell access, not a workspace
  administrator with a permission.
- There is no record of the request that prompted an erasure, only of the
  erasure. Tying the two together is the operator's.
- `revisions` and `tool_invocations` keep the address where it appears
  inside a payload, and no mechanism removes it.
