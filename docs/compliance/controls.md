# Control mapping

Common control expectations, and the mechanism in this system that
answers each one. Where a mechanism is partial, the row says so and says
what is missing. Nothing here is a certification; it is a map from the
questions an assessor asks to the places in the software that answer
them.

`shared-responsibility.md` divides these between the software and the
operator. Several controls below are answered only in part by the
software and depend on the operator for the rest; those rows say which.

## Access control

| Expectation | Mechanism | Complete? |
|---|---|---|
| Federated sign-in | SAML 2.0 and OpenID Connect, per workspace. An assertion or a code only completes the sign-in it answers, in the browser that started it: a cookie set at the start is checked at the end, so an answer obtained for one account cannot be delivered into somebody else's browser. | Yes |
| Unique identity per person | One `users` row per email address. Single sign-on links a provider subject — not an address — to that row. Service accounts are separate principals with their own client credentials. | Yes |
| Role-based authorisation | A closed set of 35 permissions; seven built-in roles; bindings that can be scoped to the workspace, one MCP server, one connector or one tool, and that can carry an expiry. | Yes |
| Deny by default | `Evaluate` returns a denial for an anonymous principal, a workspace mismatch, a server-bound credential at the wrong server, a missing scope, and — the general case — for no matching binding. There is no implicit grant. | Yes |
| Explicit deny overrides grant | A `deny` rule on a tool for any role the principal holds wins over every grant. Where `allow` rules exist for a tool, they are a whitelist. | Yes |
| Least privilege for credentials | API keys and OAuth tokens carry scopes that can only narrow what their owner's roles allow, and can be bound to a single MCP server. | Yes |
| Joiner, mover, leaver | SCIM 2.0 creates, updates and deactivates accounts. `active: false` revokes that person's sessions, API keys and refresh tokens immediately. Single sign-on reconciles provider-sourced role bindings to the person's groups on every sign-in, leaving manual bindings alone. Without SCIM, an administrator holding `org:members:manage` changes a member's role, deactivates or reactivates them, or removes them through `/api/v1/org/members`; deactivation and removal revoke the person's sessions, API keys and refresh tokens in the same transaction, the evaluator grants nothing to a deactivated member, and each change is an audit event naming the person. The API refuses to act on the caller, to leave a workspace without an active owner, and to deactivate or remove a SCIM-provisioned member behind the identity provider's back. | Yes |
| Access review | `supermcp compliance access-review` lists, for every workspace unless one is named, each person, service account, API key and provisioned group, the roles they hold, where each binding applies, when it expires and when the principal was last used, and flags what a reviewer should question: principals dormant for 90 days (configurable) or never used, privileged bindings and credentials that never expire, expired bindings, disabled principals still bound, and service account secrets never rotated. It writes text, JSON, or CSV with one row per principal and binding, and changes nothing. `GET /api/v1/roles` and `GET /api/v1/roles/{id}/bindings` answer who holds each role over the API, and `GET /api/v1/org/members` (`org:read`) lists every member with their status, how they sign in, each role binding they hold and when they last signed in. | Partial — there is no attestation workflow; a reviewer's decisions are recorded outside the system |
| Session management | Server-side sessions, 12-hour idle and 30-day absolute expiry, `HttpOnly` `SameSite=Lax` cookie with the `__Host-` prefix over HTTPS, self-service device list and revocation, and every other session ended on a password change. Sessions are held by the digest of the cookie's secret, not by the secret, so database read access does not take over a live session, and rows past their expiry are removed hourly. | Yes |
| Multi-factor authentication | **Not provided.** This system issues no second factor. Enterprise sign-in delegates to an identity provider, which enforces its own; the session records `mfa_verified_at` and the principal carries an MFA flag so a policy could require it. Password sign-in has no second factor. |
| Brute-force protection | Lockout counted per email address and per client address, ten failures and a hundred respectively, with exponential backoff capped at 24 hours. A sign-in for an unknown address takes the same time as one for a known address. Separate rate-limit budgets for sign-in, registration and client registration. | Yes |
| Password policy | argon2id (t=3, 64 MiB, p=2), minimum 12 characters and two character classes by default, per-workspace overrides for length, classes, history depth and maximum age, and reuse checked against the stored history. | Yes |
| Privileged access is recorded | Every administrative mutation writes an audit event with a before-and-after diff. | Yes |

## Audit logging

| Expectation | Mechanism | Complete? |
|---|---|---|
| Security-relevant events are recorded | One stream covering sign-in and sign-out, registration, workspace switching, password change, OAuth client registration, consent, token issue and refusal (ten refusals per client and minute in full, the rest counted into one event, so a client cannot flood the trail), refresh-token replay and revocation, every administrative mutation, secret operations, SCIM provisioning, tool calls and refused access. | Yes |
| Records are tamper-evident | Each row carries the hash of the one before it. The hash covers the event id, its write time, the workspace, category, action, outcome, actor and target, plus a digest of the JSON columns. `supermcp audit verify` names the first row that does not follow from its predecessor, and distinguishes "modified after it was written" from "records a different predecessor". | Yes |
| Records cannot be altered by the application | The application database role is denied `INSERT` and `DELETE` on `audit_events`, and `UPDATE` on everything except the three columns a lawful retention scrub touches. Appending runs as the maintenance role. | Yes |
| Deletion is detectable | Retention writes a `retention_cut` anchor recording the hash of the last removed row, and verification refuses a stream whose first row follows a predecessor that is neither the genesis row nor explained by an anchor. | Yes |
| Periodic signed checkpoints | A checkpoint is written every ten minutes at the head of the stream and signed with the instance's active signing key, named by its key id so a verifier knows which published key to check it against. The same table records a retention cut. Verification matches every checkpoint in the range against its row and checks its signature, retired keys included, so a chain rewritten and rehashed from some row onward, or cut short at the head, fails even though its links still agree. | Yes |
| Records reach a system the subject cannot edit | An exporter ships the stream at-least-once with a cursor, to one of four kinds of destination: a webhook (newline-delimited JSON, each delivery signed with HMAC-SHA256 over a timestamp and the body), syslog over TCP or TLS (RFC 5424 framing with an RFC 5424 or CEF payload), a Splunk HTTP Event Collector, or an OTLP/HTTP logs endpoint. `/api/v1/audit/exporters` lists them under `audit:export` and creates and deletes them under `org:settings:manage`; the configuration is sealed, credentials are never read back, and each change is recorded in the stream. A new exporter starts at the head of the stream; earlier events are exported with `GET /api/v1/audit/export`. | Partial — the settings screen configures webhooks only, the other three kinds through the API; an exporter cannot be edited in place, only deleted and recreated; there is no object storage destination |
| Records are exportable | `GET /api/v1/audit/export` streams NDJSON under a separate `audit:export` permission, and records the export itself as an event before the first byte goes out. | Yes |
| Sensitive values are not recorded | Diffs replace any field whose name looks like a secret with a short digest of the value. The tool-call payload policy defaults to keeping only the shape of arguments and results. | Yes |
| Logging failures are visible | The queue depth and the spool depth are published as metrics, the queue depth with an alert rule. How far each kind of export destination is behind is published too, and alerts past fifteen minutes. Events the queue could not take, or the database refused past the writer's retries, are counted (`supermcp_audit_events_dropped_total`) and reported into the stream itself, with their count and when they were accepted, on the next successful append, because a gap nobody records is indistinguishable from a quiet period. | Yes |
| Time is trustworthy | The write time is supplied by the application and covered by the row's hash, so a backdated row fails verification. **Partial:** clock synchronisation is the operator's. |

## Encryption

| Expectation | Mechanism | Complete? |
|---|---|---|
| Credentials encrypted at rest | AES-256-GCM under a per-workspace data key, with `table \| column \| row \| workspace` as additional authenticated data so a ciphertext cannot be moved between rows. Covers connector credentials, upstream tokens, identity provider client secrets, audit exporter configuration, the token signing keys' private halves, and binary tool results awaiting collection (bound to workspace and principal, in Redis and Postgres alike). | Yes |
| Passwords and bearer credentials not recoverable | Passwords argon2id; API keys, refresh tokens, OAuth client secrets and service account secrets stored as SHA-256. | Yes |
| Whole-database encryption | **Not provided by this software.** Disk or volume encryption for Postgres is the operator's. Tool-call arguments, audit payloads and all configuration are stored in clear within the database. |
| In transit, client to gateway | **Not provided by this software.** The binary serves plain HTTP; TLS is terminated by the ingress or reverse proxy. The binary does enforce that `SUPERMCP_PUBLIC_URL` is `https` unless it points at loopback, and sets `Secure` on the session cookie accordingly. |
| In transit, gateway to upstream | Whatever the upstream offers. Adapters use `https` base URLs; nothing forces it. A connector may opt in to `InsecureSkipVerify`, and only in combination with an explicit outbound proxy. | Partial |
| In transit, gateway to database and Redis | Whatever the connection string asks for. Use `sslmode=require` or stronger and `rediss://`. | Operator |
| Browser protections | Enforced Content-Security-Policy with no inline allowance, `frame-ancestors 'none'`, `base-uri 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and CSRF checks on cookie-authenticated mutations via `Sec-Fetch-Site` and `Origin`. | Yes |

## Key management

| Expectation | Mechanism | Complete? |
|---|---|---|
| A key hierarchy | Master key wraps per-workspace and instance data keys; data keys encrypt rows. Re-wrapping the data keys changes the master key without touching a single ciphertext. | Yes |
| Keys held outside the application | AWS KMS, where the data key reaches AWS only as one `Encrypt` or `Decrypt` call and no master key exists in the pod. The Helm chart offers only `local` and `awskms` and fails the render for any other provider, and the variables it renders for AWS KMS are the ones the binary reads. Tested end to end against AWS KMS on 2026-09-25: a rotation from a local key to AWS KMS, `supermcp keys verify` over the result, and the encryption context binding wrapped keys to `SUPERMCP_KMS_DEPLOYMENT`. | Partial — AWS KMS is the only external provider; GCP KMS, Azure Key Vault and Vault transit are not implemented |
| Key separation between environments | The KMS encryption context names the installation, so a wrapped key lifted from one database cannot be unwrapped against another that shares the AWS key. Set `SUPERMCP_KMS_DEPLOYMENT`; the chart passes it only through `extraEnv`. Left unset, the context falls back to the key reference, which separates installations only as far as they use different keys. | Partial — only when `SUPERMCP_KMS_DEPLOYMENT` is set |
| Master key rotation | `supermcp keys rotate-kek` re-wraps every data key, proves each new wrapping opens before overwriting the old, skips what it has already moved so an interrupted run resumes, and runs without a maintenance window when the decrypt-only key is configured during the roll. `supermcp keys verify` proves the result. Procedure in `docs/operations.md`. **Partial:** it is a manual operation; nothing rotates on a schedule. |
| Data key rotation | `supermcp keys rotate-dek` re-seals a workspace's rows under a new data key in batches, proves each value opens before overwriting the row that holds it, refuses to start if any sealed column in the schema has no rotation target, and leaves the superseded key `decrypt_only` until a census finds nothing referencing it. Safe to interrupt and re-run; one rotation per scope across replicas. Procedure in `docs/operations.md`. | Partial — it is a manual operation; nothing rotates on a schedule |
| Signing key rotation | A sweep every six hours, run by one replica at a time, publishes a next key once the active key is 90 days old, promotes it after it has been published for a day so a verifier that cached the key set still accepts the new tokens, and retires the old key 30 days later. `supermcp keys rotate-signing` starts the same rotation on demand, and with `-revoke` retires every published key and makes a new one active at once, for a key that may be known; both record `signing_key.rotate`. Retired public keys stay in the table, so checkpoints signed before a rotation still verify. The private halves are sealed under the instance data key, which `supermcp keys rotate-dek -instance` rotates. | Yes |
| Misconfiguration fails safe | A key provider that cannot be built is a boot failure, never a downgrade. A local key that is not exactly 32 bytes is refused rather than padded. A decrypt-only key sharing a reference with the active key is refused, because a rotation between them would skip every row as already done. A data key whose recorded reference this process does not hold is refused outright rather than tried against every key in turn. | Yes |
| Key custody and escrow | **Operator.** Losing the master key makes every stored credential unrecoverable, and a database backup without it is unreadable. |

## Tenant isolation

| Expectation | Mechanism | Complete? |
|---|---|---|
| Data is separated per tenant | Row-level security, enabled and forced, on every table carrying `organization_id`, with `FORCE` so it applies to the owner too. The policy compares the column to a transaction-local setting; a missing setting matches nothing. | Yes |
| The application cannot bypass it | The application pool's role is `NOBYPASSRLS` and every connection issues `SET ROLE` before use. | Yes |
| Cross-tenant access is deliberate and visible | A separate pool and a helper that refuses to run without a stated reason, which is logged. Used by migrations, the audit writer, retention, the audit exporter and the authorisation server's pre-authentication lookups. | Partial — the reason is logged, not written to the audit stream |
| Pre-authentication lookups do not widen policies | Narrow `SECURITY DEFINER` functions with fixed return shapes, granted only to the application role and revoked from `PUBLIC`. | Yes |
| Credentials are separated cryptographically | A data key per workspace, and the workspace id inside the additional authenticated data, so a ciphertext copied between workspaces fails to open. | Yes |
| Caches do not cross tenants | The tool-response cache key covers the workspace, and a read compares the workspace recorded inside the entry with the one expected, in constant time, so any keying failure becomes a miss rather than a leak. Role bindings and audit policies are cached per workspace. A change to roles, bindings, tool access rules or data-loss policies invalidates every replica's cache on commit, through Postgres `NOTIFY`; a 30-second expiry is the backstop, and the only mechanism behind a transaction-pooling PgBouncer. | Yes |
| Tokens do not cross servers | An access token's audience is `<public URL>/mcp/<server id>` derived from the RFC 8707 resource indicator, and a server-bound credential is refused at any other server. | Yes |
| Errors do not disclose other tenants | An object in another workspace is a 404, not a 403. A tool outside the caller's surface is refused with a deliberately ambiguous "tool not available". A blob belonging to someone else is a 404. | Yes |
| Isolation is tested | An integration test generated from `information_schema` asserts that every table carrying `organization_id` returns no rows under the wrong workspace, and runs in CI against a real Postgres. | Yes |
| Physical separation | **Not provided.** Isolation is logical. A customer requiring physical separation needs a separate instance and database, which is the same binary. |

## Change management

| Expectation | Mechanism | Complete? |
|---|---|---|
| Configuration changes are recorded | Every mutating administrative call writes an audit event with a before-and-after diff, secrets digested. Rejected attempts are recorded too, because a refused change is as interesting as an accepted one. | Yes |
| Configuration changes are versioned | `revisions` holds one row per change to a connector, a tool, an MCP server or a role, written in the same transaction as the change itself, with a full snapshot, a diff, and the name of the person who made it. The revision number is allocated under an advisory lock inside that transaction, so two racing writers cannot both become revision four. | Yes — for those four kinds only; identity providers and workspace settings are audited but not versioned |
| Changes can be reversed | `POST /api/v1/{kind}/{id}/revisions/{revision}/restore` puts an earlier snapshot back through the service that owns the entity, which records it as an ordinary update. The history of a mistake survives its correction and the numbering only goes forwards. Requires `revisions:rollback`. | Yes |
| Approval before a change takes effect | A tool call matching an approval rule is held: the caller is answered immediately with the identifier of the request it raised, and the call runs only when somebody else approves it and the caller replays it with that identifier. The arguments are sealed when the request is raised and it is those that run, so approving a payment of ten does not approve a payment of ten thousand. Deleting the tool, or editing what its call does, cancels its pending and approved requests, so an approval is never spent on a definition nobody approved. A database constraint, not a rule in the service, refuses a decision by the person who asked. | Yes — for tool calls; a configuration change is recorded and reversible but is not held |
| Separation of duties | Role bindings can be scoped and time-limited, and `audit:read`, `audit:export` and `audit:policy:manage` are separate permissions that the built-in `auditor` role holds without any write permission. Editing a tool's description is `tools:update`; changing what its call does, or adding or deleting a tool, also needs `connectors:update`, and serving a destructive operation as non-destructive also needs `tools:invoke:destructive`, which the audit event flags as `meta.declassified`. | Partial — nothing prevents one person holding every role |
| Code changes are reviewed and tested | CI runs `gofmt`, `go vet`, golangci-lint, `go test -race` with a coverage floor, an integration suite against a real Postgres including the row-level-security matrix and an end-to-end MCP client, adapter validation in strict mode, offline replay of every recorded exchange, a check that the converted catalogue matches the vendored corpus, a check that the generated TypeScript client is current, browser tests with accessibility assertions, `helm lint` and `kubeconform`. | Yes |
| Dependencies and images are scanned | `govulncheck`, `gosec`, `gitleaks` with a rule for this system's own key format, and Trivy on the built image, all reporting SARIF to code scanning. | Yes |
| Releases are verifiable | goreleaser builds static binaries on a distroless base; cosign signs the checksums and the image keylessly; syft produces an SBOM; SLSA provenance is attached; the chart is signed and pushed to a registry. | Yes |
| Schema changes are safe to roll | Migrations run under an advisory lock before the new pods start, `/readyz` fails while the schema is behind the binary, and a check script blocks a `DROP`, `RENAME` or `NOT NULL` without an explicit marker and a section in `docs/UPGRADING.md`. | Yes |

## Availability and resilience

| Expectation | Mechanism | Complete? |
|---|---|---|
| No single point of failure in the application | Stateless request handling, so replicas are interchangeable. The MCP transport runs in stateless mode with no session held between requests. | Yes |
| Graceful degradation | The rate limiter divides budgets per replica when Redis is gone rather than allowing traffic through, and reports it as a metric. The response cache resolves every error to a miss. The audit writer queues in memory; a batch the database refuses is retried at the head of the queue, and by default what it finally drops, or what the full queue cannot take, is counted and recorded as a gap. It can instead make the caller wait, or spool the event to local disk, fsynced, and replay it in order when the database returns (`audit.onUnavailable: spool` with `audit.spool.enabled`, which mounts a volume; 256 MiB by default, past which events are dropped and counted). | Partial — an audit queue overflow drops events by default; the disk spool is opt-in, bounded, and lost with its volume |
| Protection from a failing upstream | Per-connector circuit breaker (trips at ten requests and 60 per cent failures, ignoring 4xx), concurrency cap, timeouts at every layer, retries only on transient statuses and only when the body can be replayed, and a 16 MiB response cap. | Yes |
| Rollout safety | `maxUnavailable: 0`, a pod disruption budget requiring one replica to survive, readiness gated on the schema version, and a 20-second graceful drain. | Yes |
| Backup and recovery | **Not provided.** No backup command and no backup job. Postgres backups, their encryption, their retention and restore testing are the operator's. The restore procedure and a rehearsal are in `dr-runbook.md`. |
| Monitoring | Prometheus exposition on a separate listener with counts and latencies by connector type, status and error class, breaker state, audit queue and spool depth, audit export lag by destination kind, master key operations by outcome, database pool statistics and limiter health, plus ten alert rules in the chart, among them an unreachable key service, audit export lag, a saturated connection pool and a failed migration job (the last read from kube-state-metrics). | Yes |
| Tracing | OpenTelemetry spans over OTLP/HTTP for each MCP request, each tool call and each upstream call, off unless `SUPERMCP_OTLP_ENDPOINT` (the chart's `tracing.endpoint`) names a collector, and sampled at one per cent by default. Trace context is not sent upstream. | Partial — only the MCP path is traced, not the administrative API or background jobs, and an incoming trace context is not joined, so a trace starts at the gateway |

## Data protection

| Expectation | Mechanism | Complete? |
|---|---|---|
| Data minimisation in records | The audit payload policy decides what is kept of a tool call, and it governs both places a call is recorded: the audit event and the `tool_invocations` row the tool-call screen reads. It defaults to keeping the shape of the arguments and the result and none of their values. | Yes |
| Sensitive values are kept out of a call | A data-loss rule scans the arguments on the way out and the result on the way back, inside a byte budget, and either records what it found, masks it, or refuses the call. The built-in detectors cover payment cards, IBANs, email addresses, telephone numbers, US social security numbers, German tax identifiers, credentials with a recognisable issuer prefix, and fields named as secrets; each one's documented exclusions ship with it. A finding records the detector, the kind, a count and the field paths, and never an excerpt, a digest or an offset of what it matched. | Yes |
| Retention limits | Per-workspace audit window, default 365 days, 90 to 36 500. Set through `GET`/`PUT /api/v1/audit/retention` or the audit screen by someone holding `audit:policy:manage` (not the `audit:export` that places a hold), and every change is recorded. Enforced hourly by scrubbing content and by a contiguous cut across the stream. | Partial — the audit stream only; see `retention.md` for the four stores nothing removes |
| Legal hold | Held rows are never scrubbed, and a held row below a retention cut stops the cut rather than being skipped. A hold is placed and released over a time window through the API by someone holding `audit:export`, and both are recorded in the stream they govern. | Yes |
| Subject access and erasure | `supermcp dsar export` writes everything the instance holds about one person as JSON with a manifest; `supermcp dsar erase` pseudonymises them. The erasure rewrites only the display columns the audit digest does not cover, so the chain still verifies afterwards, and it reports what is left in the payloads it must not touch — the only lawful removal there is a scrub by workspace and date. | Partial — payloads, `tool_invocations.input` and revision snapshots are counted, not rewritten |
| Control over where data goes | Every connector is an explicit decision to send tool arguments to one named vendor, made by someone holding `connectors:create`. The SSRF guard prevents a connector or an import being pointed at an internal address. | Partial — the guard is an in-process control, not an egress policy |
| No disclosure to the supplier | There is no telemetry, usage reporting, licence check or crash reporting in the server binary, and the adapter catalogue is compiled in, so browsing or installing an adapter reaches no network. Traces, when enabled, go only to the collector the operator names. | Yes |

## Summary of what is missing

For an assessor reading only one section:

- No multi-factor authentication of our own; it is delegated to the
  identity provider, and password sign-in has none.
- No backup or restore mechanism. The procedure is documented in
  `dr-runbook.md`; the tooling is the operator's.
- Data key and master key rotation are manual; nothing runs them on a
  schedule. Signing keys rotate on their own, ninety days apart.
- Only one external key provider.
- By default an audit event is dropped, and counted, when the writer's
  queue overflows. Holding them instead is opt-in:
  `SUPERMCP_AUDIT_ON_UNAVAILABLE=spool` (a bounded disk spool) or `block`.
- No attestation or sign-off workflow around the access review.
- `tool_invocations` rows are kept indefinitely; what they hold is
  governed by the payload policy, but nothing deletes them.
- Audit export reaches webhook, syslog, Splunk and OTLP destinations,
  but the settings screen configures webhooks only, and there is no
  object storage destination.
- No approval step in front of a configuration change. A tool call can be
  held; an administrative change is recorded and reversible but not held.
- Tracing covers the MCP request path only and starts at the gateway;
  the administrative API and background jobs are not traced.
- Logical tenant isolation only.
