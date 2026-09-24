# supermcp tasks

Source of truth for progress against `docs/plan.md`. Tick items as they land; keep the order.

## M0 Skeleton

- [x] Repo, Go module, layout, Makefile
- [x] `pkg/adapter` v2 types, JSON Schema, validator, index
- [x] `pkg/adapter/v1` fingerprint port (golden 257/257)
- [x] `pkg/adapter/v1compat` converter, 257 converted, 0 blockers
- [x] CLI `adapter convert|validate|index`, `serve`, `migrate`, `openapi`
- [x] config, slog, pgx pools, goose migrate with advisory lock
- [x] chi+huma API, `/healthz`, `/readyz`, catalog endpoints, OpenAPI
- [x] Vite + React + Kumo SPA, generated client, embedded in binary
- [x] Dockerfile distroless, goreleaser, cosign/SBOM/SLSA release workflow
- [x] CI: lint, test, integration, security, adapters, web (eslint with jsx-a11y, typecheck, build), docker, helm
- [x] Helm chart v0, compose quickstart
- [x] golangci-lint clean
- [x] goreleaser snapshot verified (source archive needs a tag)
- [x] first tagged release — superseded: no `v0.1.0` was cut, the first tag
      is `v1.0.0`

## M1 Core

- [x] `pkg/tmpl` placeholder engine
- [x] `internal/ssrf` policy + dialer
- [x] `internal/httpclient` per-connector client (pool, timeouts, breaker, semaphore, retry)
- [x] `internal/transform` JMESPath
- [x] `internal/engine` interfaces + `rest` engine (byte-exact query/body encoding)
- [x] `graphql` engine
- [x] `internal/dbpool` + `database` engine (validator, dialect binding)
- [x] `internal/upstreamauth`: none, apiKey, bearer, basic, query, oauth2 (client_credentials, refresh_token), hmac, login (body, setCookie)
- [x] domain schema migrations (users, orgs, members, connectors, tools, servers, api keys, tool invocations; grants in M2)
- [x] `internal/tenant` RLS: `supermcp_app` role via SET ROLE, `Tx` with `set_config`, CI matrix from `information_schema`
- [x] `internal/secrets` envelope encryption, local KEK, ciphertext format, Postgres key store
- [x] `internal/identity`: users, orgs, sessions, argon2id (bcrypt upgrade), lockout
- [x] `internal/authz`: permissions registry, built-in roles, bindings, evaluator (fail closed)
- [x] `internal/mcpauth` API keys: hashed, prefix lookup, scopes, expiry, rotation
- [x] `internal/connector` CRUD, sealed credentials, catalog install (resync in M4)
- [x] `internal/tool` annotations derivation (catalog cache in M5)
- [x] `internal/mcpserver` CRUD, composed instructions
- [x] `internal/mcp` Streamable HTTP endpoint (stateless, surface builder, hidden-tool guard; demo in M4)
- [x] `internal/invoke` pipeline + tool-call log
- [x] parity test vs the TS engine: 1741 recorded requests, 0 unexplained differences
- [x] UI: login/register, connectors, catalog, servers with endpoint URL, api keys, tool calls (users/orgs screens in M2)
- [x] e2e: register → connector → server → API key → MCP client tools/list and tools/call, with cross-tenant refusal

## M2 Identity

- [x] OAuth 2.1 AS: ES256 keyring, JWKS, rotation
- [x] per-server `aud` from resource indicator, scopes
- [x] authorize (PKCE S256 mandatory), token (code, refresh rotation with family revocation, client_credentials)
- [x] DCR with `open|approval|closed` modes and redirect-URI rules
- [x] `/oauth/revoke`, `/oauth/introspect`, well-known documents incl. JWKS and protected-resource metadata
- [x] consent + server-picker Go template (no JavaScript, strict CSP)
- [x] OIDC RP: Entra, Google, Okta, Auth0, GitHub, generic (ID token verified against the provider's JWKS)
- [x] SCIM 2.0 users + groups; deactivation revokes sessions, keys and refresh tokens
- [x] service accounts with `client_credentials`, password policy with history
- [x] UI: security settings, sessions/devices, service accounts, SSO/SCIM, provider buttons on sign-in

M2 is complete.

## M3 Governance

- [x] `audit_events` hash chain over a content digest, writer, anchors; wired into
      auth, admin, secrets, tool and authz-denial paths
- [x] audit read API, export, `supermcp audit verify` (exit 1 on a broken chain)
- [x] webhook exporter (HMAC signed, cursor, back-off), payload policy, retention
      (per-org scrub, then one contiguous cut)
- [x] admin mutation before/after diffs, secrets recorded as digests
- [x] periodic signed anchors at the head of the stream, every ten minutes
- [x] exporter configuration and legal hold through the API and the audit screen
- [x] spool to disk when the database is unavailable — landed in v1.1.
      Monthly partitions are not done: a breaking migration, listed under
      "Waiting on something"
- [x] revisions + rollback for connectors, tools and servers
- [x] roles API and a read-only roles screen
- [x] KEK provider: AWS KMS, KEK rotation with no maintenance window, `keys verify`
- [x] UI: audit explorer with chain status, export and the payload policy
- [x] UI: revisions, on each connector's history screen

## M4 Catalog parity

- [x] oauth2 authorization_code, with the consent flow and one redirect URI for
      the instance (four adapters declare it, not thirty; the rest are
      mis-declared as refresh_token and want converting)
- [x] parsers: openapi 3.0 and 3.1, with a dry run that shows what would be made
- [x] response cache (Redis or per replica, keyed so a cross-tenant hit cannot
      happen), binary and oversized content as links
- [x] `adapter record|test` with cassettes: 49 recorded across 11 keyless
      adapters, replayed offline in CI
- [x] parity across 2385 tools: 1741 compared against the old engine, 554 it
      refused at build time and this one builds, 68 graphql and database tools
      rendered by their own engines, 22 static
- [x] nightly live keyless probe (reports, never fails the build)

## M5 Hardening

- [x] Redis-backed rate limit with memory fallback that never allows all
- [x] Prometheus `/metrics` on the admin listener
- [x] alert rules and a service monitor in the chart; the dashboard landed in
      v1.1. Six of the plan's alerts exist; MigrationJobFailed,
      AuditExportLag, DBConnPoolSaturated and KMSUnreachable do not
- [x] k6 load test in hack/load; the surface is assembled once per server,
      version and caller, which took tools/list at 500 tools from 11.2 ms and
      158k allocations to 2.4 ms and 30k
- [x] migrations compatibility test: previous tag's migrations, then this one
- [x] CSP enforced and checked on every screen by the browser suite
- [x] HPA/PDB tuning: memory as a second signal, windows that cannot cut a call short
- [x] UI: status
- [x] browser tests (Playwright + axe): 30 in 9 files covering install →
      server → key → tool call, tenant isolation, audit, password rules,
      service accounts, SSO, SAML, roles, revisions, import, dry-run, status,
      audit export and the governance gates; running in CI
- [x] coverage gate on `internal/` and `pkg/`, floor 60%, currently 63.2%
      with a database in the job (the plan asked for 70%)

## Governance, wired on 2026-09-23

- [x] data-loss rules: eight detectors, per-scope policies, masking and refusal
      on both halves of a call, findings without an excerpt of what they found
- [x] approvals: policies, the queue, four eyes enforced by a constraint, the
      approved arguments replayed rather than whatever is asked for next
- [x] session secrets held as digests; hourly sweeps for sessions and spent
      OAuth material, signing-key rotation every six hours

## M6 GA

- [x] docs: install, adapter authoring, API reference, UPGRADING.md
- [x] compliance pack: data flow, retention schedule, shared responsibility,
      control mapping
- [x] `v1.0.0`

## v1.1

Built 2026-09-23, after 1.0.0 was tagged: everything that needed no
decision from anybody. What is left needs something that is not time, and
is listed under "Waiting on something" below.

Each item below works end to end. A review against `docs/plan.md` on
2026-09-23 found most of them narrower than the plan; what is missing is
written under the item and tracked under "Found in review".

- [x] SAML 2.0 service provider, and a browser binding on both sign-in paths.
      The sign-in page offers no SAML button: `/auth/saml-providers` exists
      and nothing calls it
- [x] dry-run preview of a rendered request (`_dry_run` on any tool call,
      and one tool at a time through the API). The plan's names were
      `_supermcp.dry_run` and a `supermcp_dry_run` tool; neither exists, the
      tool schema does not advertise `_dry_run`, and there is no screen
- [x] exporters: syslog/CEF, Splunk HEC, OTLP logs. API only: the audit
      screen's form still creates webhooks and nothing else
- [x] spool to disk when the database is unavailable. `on_unavailable` is one
      instance setting, not per organisation as the plan has it
- [x] DEK rotation, from the CLI (`keys rotate-dek`). No scheduled job; an
      advisory lock per scope rather than `SKIP LOCKED`
- [x] access review, crypto report, config snapshot; subject access and
      erasure. The CLI commands themselves have no tests
- [x] parsers: postman, curl, graphql introspection
- [x] air-gap bundle (`make airgap`). Checksums are not signed although
      `docs/install-airgap.md` says so, the chart is packaged without a
      pinned version, the image is a `docker save` rather than an OCI layout,
      and neither CI nor the release builds or tests it
- [x] Grafana dashboard. Off by default, and CI never renders the template
- [x] OTel traces: `mcp.request`, `tool.call`, `upstream.<type>`. The plan's
      `mcp.surface.build`, `tmpl.resolve`, `upstreamauth.apply`,
      `transform.apply`, `dlp.scan` and `audit.write` spans do not exist, and
      no `traceparent` goes upstream (deliberately, see `docs/operations.md`)
- [x] revisions for roles; side-by-side diff viewer
- [x] permission builder with effective-permission preview, inline on
      `/settings/roles` rather than at `/roles/:id`

## Found in review, 2026-09-23

Every ticked item above was checked against the code after 1.1.0. These
are what that turned up.

### Bugs

- [x] SCIM keys with `scim:write` are refused: `authz.Evaluate` sent any
      scoped credential without `mcp:org` to its default branch. Fixed:
      the scope reaches `scim:manage` and nothing else, and the API keys
      screen can create one
- [x] Password maximum age was never enforced, and a password set at
      registration never aged. Fixed: checked on every password-session
      request; until it is changed only the password, session and sign-out
      endpoints answer, and the interface shows the change form
- [x] DCR `approval` mode — the default — was a dead end: nothing could
      approve a pending client. Fixed: `supermcp oauth clients
      list|approve|reject`, audited; a rejected client is refused at the
      token endpoint too and its refresh tokens are revoked
- [x] `audit verify` checked hash links and retention cuts but not the
      signed checkpoints. Fixed: each is matched against its row and its
      signature checked, retired keys included; a checkpoint past the last
      row reports a truncated head
- [x] The OAuth endpoints wrote no audit events. Fixed: registration,
      consent, token issue and refusal, refresh-token replay and revocation
      are recorded
- [x] The blob store was per process, so with more than one replica
      `/api/v1/blobs/{id}` 404'd on the wrong pod. Fixed: Redis when
      configured, Postgres (`tool_blobs`, migration 00018) behind it or
      alone, swept every five minutes

### Self-check of those fixes, after they merged

- [x] With Redis down, a blob that was only in Redis answered 500 instead
      of 404: the fallback store passed Redis's error through. Fixed
- [x] The password-age check costs two queries per request on a password
      session (policy, then the user's password date). Fixed: a password
      found within its age is trusted for a minute per user and workspace;
      an expired one is re-read every time, so a change is seen at once
      and no replica holds anyone past it. Setting the policy forgets the
      cache
- [x] Refused token requests are audited, bounded only by the rate
      limiter, which is optional. Fixed: ten per client and minute are
      recorded, the rest counted into one `oauth.token` failure event with
      `meta.suppressed` on the next refusal
- [x] The expired-password screen has no permanent browser test. Fixed:
      `web/e2e/db.ts` runs one statement against the suite's private
      database the way `start-server.mjs` already does, and
      `password-age.spec.ts` ages the account, sets the rule, and walks
      the gate through to a changed password
- [x] The Redis blob test skips in CI, which runs no Redis. Fixed: a Redis
      service and `REDIS_URL` on both `go-test` and `go-integration`
- [x] Blob results sit unencrypted in Postgres or Redis for 15 minutes.
      Decided and done: `SealedBlobStore` wraps whichever store is
      configured and seals under the workspace's data key, bound to
      workspace and principal. Not a `rotate-dek` target, by design; see
      `docs/UPGRADING.md`
- [x] `supermcp oauth clients` has no test of its own. Fixed: the
      argument refusals that happen before a database is opened, and the
      table and JSON output, are tested in `cmd/supermcp/oauth_test.go`

### Deferred to a milestone that never picked it up

- [ ] catalog re-sync on a fingerprint change: no job, endpoint or screen
      (M1 said "resync in M4"; it is also an M4 exit criterion)
- [ ] `/mcp/demo` (M1 said "demo in M4")
- [ ] users, organisations and members: screens and API. `org:members:manage`
      is declared and nothing checks it (M1 said "in M2")
- [ ] tool create and edit; only enable/disable exists
- [ ] API key rotation with grace: `Keys.Rotate` has no route and no button
- [ ] ABAC hooks in the evaluator (plan v1.1); nothing, and not cut either
- [ ] lingui: not installed, although "Cut from scope" says the interface
      stays translatable with it

### Plan detail not built

- [ ] OAuth: userinfo endpoint, DCR software statements, `amr`/`sid` claims
- [ ] `RequireFreshAuth` on sensitive operations; per-org session lifetimes
- [ ] audit read API `q` full-text; per-org retention through the API
- [ ] 409 on concurrent edits; revisions for DLP policies, approval policies
      and identity providers
- [ ] authz cache invalidation across replicas (NOTIFY); today a 30s TTL
- [ ] approvals: `supermcp_approval_status`/`supermcp_approval_cancel` tools
      and MCP elicitation
- [ ] DLP: custom regex and an external detector (Presidio, webhook)
- [ ] `system.ratelimit_degraded` as an event, not only a gauge
- [ ] the four missing alert rules (see M5)

### CI, release and documents

- [ ] CodeQL analysis (only SARIF upload runs), helm install on kind,
      `scripts/check-migrations.sh`, web size limit, CODEOWNERS, PR template
- [ ] coverage floor to the plan's 70%
- [ ] `SECURITY.md`, `docs/compliance/dr-runbook.md`,
      `docs/compliance/incident-response.md`, backup CronJob
- [ ] `docs/compliance/controls.md` is behind the code: it says there is no
      tracing and no DEK rotation, that the webhook is the only destination
      and that the spool is in memory
- [ ] stale strings: `upstreamauth` refusals still say "planned for M4";
      `httpapi/revisions.go:42-46` says roles are not a revision kind

## Waiting on something, not on time

- **S3 and GCS as audit destinations** — needs a bucket to prove delivery
  against. The HTTP destinations do not.
- **KEK providers: GCP KMS, Azure Key Vault, Vault transit** — each is the
  same small implementation as AWS KMS, unverifiable without an account.
  One provider proves the interface.
- **Cassettes for the credentialed adapters** — needs each vendor's
  credentials. The nightly live probe covers them instead.
- **Monthly partitions on `audit_events`** — a breaking migration, and the
  schema policy is expand-only within a major version. It belongs at a
  major boundary, and the writer already records the gap it drops.
- **The two-replica rolling upgrade test** — needs a cluster. The half that
  pays (previous tag's migrations, then this one) runs in CI.
- **SOAP, WS-Security, WSDL, mTLS, the MCP bridge engine, oauth1 and login
  bcrypt-with-salt** — see "Cut from scope": between zero and one adapter
  each. They come back when an adapter needs them.
- **The analytics screen** — cut; the status screen and the tool-call log
  answer what people actually ask.

## Cut from scope

Dropped deliberately, with what covers the need instead.

- **Second factor of our own** (TOTP enrolment, recovery codes, per-org MFA
  policy, WebAuthn). An enterprise signs in through its identity provider,
  which already enforces its own second factor and tells us so in `amr`. The
  session carries `mfa_verified_at` and the principal an `MFA` flag, so a
  policy can still require a verified factor; we do not issue one.
- **German translation.** The interface stays translatable (lingui, message
  ids, no concatenated strings) and ships in English. A locale is cheap to add
  once someone needs it and expensive to keep honest before that.

### Cut 2026-09-23, after counting what the catalog actually uses

Of the 257 adapters: 247 are HTTP, 5 GraphQL, 5 database. None is SOAP and
none is an MCP bridge. Auth types: bearer 71, apiKey 54, basic 44, oauth2 30,
none 26, query 13, login 12, database 5, hmac 1, oauth1 1.

- **SOAP engine, WS-Security, the WSDL parser and mTLS.** Three hard pieces of
  work serving zero adapters. The one SOAP-shaped case, KashFlow, already goes
  out through the raw-body escape hatch on the HTTP engine. They come back when
  an adapter needs them.
- **MCP bridge engine.** No adapter declares that transport.
- **oauth1 and login bcrypt-with-salt.** One adapter each (ImmobilienScout24,
  Sorare). The other eleven login adapters use the dialects already built.
- **A cassette for every adapter.** The parity harness replays 1741 recorded
  requests and is what actually holds the converter honest. Cassettes are
  recorded for the keyless adapters; the nightly live probe covers the rest.
- **Redis session store and blob cache.** Sessions are in Postgres and already
  work across replicas. Redis stays for rate limiting, where it is needed.
- **The two-replica rolling upgrade test.** Kept the half that pays: apply the
  previous tag's migrations, then this one.
- **Three of the four KMS providers, and the analytics screen.** One provider
  proves the interface; the others are the same small implementation again.

## Flagged, still in scope

Large items worth a second look before their milestone starts.

- **SCIM 2.0 groups** (M2). User provisioning earns its keep; group sync is 17
  routes and a second authorization path into role bindings. Users first,
  groups only if a customer maps them.
- **Air-gap bundle** (M6). Moved to v1.1 on 2026-09-23: a signed tarball plus a
  disconnected-kind test in CI, with no buyer asking for it yet.

## Open — these need you, not the code

Answered on 2026-09-23: the licence is MIT, the organisation is
`supermcpco`, and `v1.0.0` is tagged.

- [ ] An AWS account with a KMS key, to run the key-service path once end to
      end. The local master key is covered; the KMS provider is not, beyond
      its unit tests.
- [x] Registry credentials: none needed. The release workflow logs in to
      `ghcr.io` with `GITHUB_TOKEN` (`packages: write`), and the `v1.1.0`
      run pushed `ghcr.io/supermcpco/supermcp` (amd64, arm64, `1`, `latest`)
      and `oci://ghcr.io/supermcpco/charts/supermcp:1.1.0`, both public,
      anonymously pullable and cosign-signed (checked 2026-09-24).
- [x] A git remote: `origin` is `github.com/supermcpco/supermcp`.
