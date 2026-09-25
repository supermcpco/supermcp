# Data flow

What enters this system, where each kind of data is held, how long it
stays, and what leaves it.

This describes the software as it is built. It says nothing about how a
particular operator has configured or hosted it; that division is set
out in `shared-responsibility.md`.

## The shape of the system

One process, one Postgres database, and optionally one Redis. The
process holds no durable state of its own except in memory. Everything
that survives a restart is in Postgres.

A call arrives at the MCP endpoint from an AI client, is authorised, is
rendered into an upstream request using credentials held in the
database, is sent to the upstream system the connector names, and the
response is transformed and returned. Two records are written: a row in
`tool_invocations` and an event in the append-only audit stream.

## What enters

| Data | Enters through | Supplied by |
|---|---|---|
| Upstream credentials | Installing a connector, or `PUT /api/v1/connectors/{id}/credentials` | An administrator |
| Upstream tokens | Obtained at run time by the OAuth2 or login auth flows | The upstream vendor |
| Tool arguments | `tools/call` on the MCP endpoint | The AI client, on a person's behalf |
| Tool results | The upstream system's response | The upstream system |
| Account details | Registration, single sign-on, SCIM | A person, or the identity provider |
| Passwords | Registration and password change | A person |
| Request metadata | Every request | The client: IP address, user agent |
| Configuration | The admin API | An administrator |
| Adapter definitions | Compiled into the binary | The supermcp catalogue |

## Credentials

Everything in this section is encrypted at rest with envelope
encryption. A per-workspace data key, 256-bit, encrypts the value with
AES-256-GCM. A master key wraps the data key. The master key is either
32 bytes held by the process (from the environment or a file) or a key
in AWS KMS that never leaves AWS.

The ciphertext is `0x01 | data key id (16 bytes) | nonce (12 bytes) |
AES-256-GCM ciphertext and tag`. The additional authenticated data is
`table | column | row id | workspace id`, so a ciphertext moved to
another row, another column or another workspace fails to open rather
than decrypting into the wrong place.

| What | Where | Lifetime |
|---|---|---|
| Connector credentials (API keys, client secrets, refresh tokens an administrator supplied) | `connector_credentials.value_enc` | Until overwritten or the connector is deleted |
| Upstream access and refresh tokens obtained at run time | `connector_tokens.token_enc` | Until refreshed or the connector is deleted |
| Identity provider client secrets | `identity_providers.client_secret_enc` | Until the provider is deleted |
| The private half of the token signing keys | `signing_keys.private_enc`, under the instance data key | Until the key is retired |
| Audit exporter endpoint and signing secret | `audit_exporters.config_enc` | Until the exporter is removed |

Credential **values never leave the database in readable form through
the API**. The connector document stores only `{{env.NAME}}`
placeholders; the API returns the names of a connector's credentials and
whether each is marked secret, never a value. They are decrypted in
memory when a tool call renders its request, and the decrypted data key
is cached for the life of the process.

These are hashed rather than encrypted, because nothing ever needs to
read them back:

| What | How |
|---|---|
| Passwords | argon2id (t=3, 64 MiB, p=2). A bcrypt hash imported from elsewhere is verified and upgraded on the next successful sign-in. |
| API keys | SHA-256 of the whole key. The 12-character prefix is stored separately so a presented key can be found; the comparison is constant time. |
| OAuth refresh tokens | SHA-256. |
| OAuth client secrets | SHA-256. |
| Service account secrets | SHA-256. |
| Password history | The same argon2id hashes, trimmed to the policy's depth. |

| Browser sessions | SHA-256 of the cookie's secret. The cookie carries the secret; the table carries the digest, so reading the table does not take over a session. |

One credential is **not** protected this way, and an auditor should know
it:

- **OAuth authorisation codes.** Stored in clear as the primary key of
  `oauth_codes` for their five-minute life. They are single-use under a
  row lock and bound to a PKCE challenge, so a code alone is not enough
  to obtain a token, but the value is readable in the database while it
  lives.

The PKCE verifiers for sign-in and for connector consent
(`sso_requests.code_verifier`, `connector_auth_requests.code_verifier`)
are also in clear. Each is a nonce for one exchange, minutes long, and
useless without the matching code from the provider.

## Tool arguments and results

These are the ones that carry a customer's own business data, and there
are three separate copies with three different rules.

### In flight

Before anything is rendered, a data-loss rule may read the arguments,
and after the transform it may read the result. A rule covers the
organisation, one connector or one tool, and it masks what its detectors
find, refuses the call, or records the finding and lets it through. The
scan has a byte budget (64 KiB by default) and reports when it ran out,
because a rule that silently read half a value would be worse than none.
A finding records the detector, the kind, a count and the field paths,
never an excerpt of what it matched. With no rule configured, nothing is
inspected.

The detectors are the built-ins (card numbers, bank accounts, email
addresses, telephone numbers, national identifiers, credentials) and
any the workspace writes itself: a regular expression for an identifier
of its own, such as a contract id, which a rule runs only when it names
it. A workspace detector stores its pattern and the sample strings it is
tested against on every save, in the clear, in its row in
`dlp_detectors` and nowhere else: the revision history and the audit
trail record how many samples there are, not what they are, and only
holders of `dlp:manage` can read them back. The samples are meant to be
invented, and nothing a tool call carried is ever written there.

Some calls do not reach an upstream at all: an approval rule holds the
call, seals its arguments under the workspace's data key, and answers
the caller with the identifier of the request it raised. What runs, when
somebody approves it, is the arguments that were sealed.

Arguments are rendered into the upstream request and sent to whatever
the connector's `baseUrl` or `dsn` names. That is the whole point of the
system: **arguments and results reach the upstream vendor the connector
points at**, and which vendors those are is the operator's choice, made
one connector at a time.

The result is read into memory (capped at 16 MiB), transformed by the
tool's JMESPath expression if it has one, and returned to the client
that asked. Nothing about it is written to disk except as described
below.

### The tool-call log

Every call writes a row to `tool_invocations` carrying the metadata, and
as much of the arguments and the first text result (truncated to 64 KiB)
as the workspace's audit payload policy allows — the same policy that
governs the audit event, applied in both places.

Two things follow, and neither is obvious:

- Nothing deletes it. There is no retention sweep for this table.
- The API does not serve these columns. `GET /api/v1/tool-calls`
  returns the tool name, status, duration and error text only. The data
  is stored and, at present, never read back through the product.

The table is under row-level security, so one workspace cannot read
another's rows.

### The audit stream

The same call also writes an event to `audit_events`, and this one does
obey the workspace's policy:

| Policy | What the event's payload holds |
|---|---|
| `none` | Nothing |
| `metadata` (the default) | The *shape* of the arguments and result: which arguments were given and what kind each was. No values. |
| `masked` | The values, with anything matching a payment card, an email address, an IBAN, a US social security number or a recognisable API key replaced by `<redacted>`, and any field whose *name* contains `password`, `secret`, `token`, `apikey`, `authorization`, `credential`, `passwd` or `pwd` replaced wholesale. |
| `full` | The values as given. |

A payload larger than 64 KiB is replaced by a marker recording its size.

`masked` is a floor, not data-loss prevention: it catches the obvious
shapes and nothing else. Do not rely on it to keep a category of data
out of the record. `none` and `metadata` are the settings that do that.

## Audit records

One append-only stream, `audit_events`, covering sign-ins, every
administrative change with a before-and-after diff, secret operations,
tool calls, and refused access.

Each row carries the hash of the one before it. The hash covers the
event id, the write time, the workspace, the category, the action, the
outcome, the actor, the target, and a digest of the three JSON columns.
Removing or editing a row breaks the chain at a point
`supermcp audit verify` names.

The write time is inside the hash deliberately. Retention deletes by
age, so a row that could be backdated without breaking the chain could
drag the whole stream into a deletion that afterwards looked lawful.

Secret values never enter a diff. A field whose name looks like a secret
is replaced by `<redacted:` plus eight hex characters of its digest, so
a reader can see that a value changed without learning either value.

Only the maintenance database role may append. The application role is
denied `INSERT`, `DELETE` and all `UPDATE` except on the three columns a
retention scrub touches.

`retention.md` covers how long events live and what removes them.

## Personal data

| Data | Where | Notes |
|---|---|---|
| Name, email address | `users` | The email is the account identifier. |
| Password hash, when to change | `users`, `password_history` | See above. |
| Workspace memberships | `organization_members` | |
| Sessions: client IP, user agent, times, authentication method | `sessions` | |
| API key last-used time and IP | `api_keys` | Recorded at most once every five minutes per key. |
| The link between an identity provider's subject and a local user, plus the email it carried | `user_identities` | The subject, not the address, is the identity: an address can be reassigned. |
| The SCIM record as the provider sent it | `scim_users.raw` | Whatever attributes the provider chose to send. |
| Actor, IP address and user agent on every audit event | `audit_events` | |
| Actor on every configuration revision | `revisions` | |

Personal data also appears inside tool arguments and results whenever a
tool is called with any. That is governed by the sections above, not by
this one.

There is no self-service subject-access export and no self-service
erasure. Removing a person's identifying columns from the audit stream
is possible in principle — the chain hash covers the actor id but not
the display name, so a display name can be replaced without breaking it
— but no command or endpoint does this today.

## What leaves, and to whom

| Leaves to | What | When | Controls on it |
|---|---|---|---|
| **The upstream system a connector names** | The rendered request: tool arguments, the connector's credential, and the caller's identity if the adapter's templates ask for it | Every tool call | The SSRF guard refuses private, loopback, link-local and reserved addresses. TLS is whatever the upstream offers. 16 MiB response cap, 30-second default timeout, circuit breaker, at most 5 redirects, each re-checked. |
| **A webhook the workspace configured** | The audit stream as newline-delimited JSON, including whatever the payload policy stored | Continuously, at most once a minute, at-least-once with a cursor | The URL goes through the SSRF-guarded client. Each delivery carries `X-Supermcp-Timestamp` and an HMAC-SHA256 signature over the timestamp and body. `http` as well as `https` is accepted. |
| **An identity provider** | Discovery, token exchange and userinfo requests during a sign-in | Each sign-in | Through the SSRF-guarded client, because an issuer URL is administrator-supplied. |
| **AWS KMS**, when that key provider is chosen | The 32-byte data key, for one `Encrypt` or `Decrypt` call | First use of a workspace's key, and on a key rotation | No customer data passes: only the data key. The encryption context names this installation. |
| **A person with `audit:export`** | The audit stream as NDJSON over HTTPS | On request | The export is itself recorded as an event before the first byte goes out. |
| **The principal that made a tool call** | A large binary result, once | Within 15 minutes | Bound to that one principal; anyone else gets a 404. |
| **A Prometheus scraper** | Counts and latencies by connector type, status and error class; optionally per tool name | Continuously | Served only on the admin listener, which must not be the public one. |

**Nothing is sent to the supplier of this software.** There is no
telemetry, no usage reporting, no licence check and no crash reporting
in the server binary. The adapter catalogue is compiled in, so listing
or installing an adapter reaches no network.

## What Redis holds, when it is configured

- Rate-limit counters, keyed by principal or client address.
- Cached tool results, for tools whose adapter declared a cache
  duration. The cached value is the rendered text of a successful
  read-only result, so **a Redis instance holds business data**. The key
  covers the workspace, and a read verifies the workspace recorded
  inside the entry before returning it.
- Large binary tool results awaiting collection, for 15 minutes, keyed
  by an unguessable id and returned only to the principal that caused
  them. This is business data too, and it is sealed under the workspace's
  data key, bound to the workspace and the principal, before it reaches
  Redis.

Redis is optional. Without it the counters and the cache fall back to
per-process state, and binary results are held in Postgres, in
`tool_blobs`, under the workspace's row-level security — sealed the same
way, for 15 minutes, and swept every five.

## What is only ever in memory

- Unwrapped data keys, for the life of the process.
- Cached role bindings (30 seconds), audit payload policies (30
  seconds), identity provider metadata and signing keys (one minute).
- The queue of audit events not yet written, up to 256 events.

## Logs

Structured logs go to standard output: request id, method, path, status,
byte count, duration and client IP for every request; the reason for
every cross-tenant database access at debug level; errors with their
text. No log statement writes tool arguments or tool results. Where the
logs go from standard output is the operator's decision.
