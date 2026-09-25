# supermcp — Go MCP gateway with full enterprise features

## Context

The v1 prototype (NestJS + Prisma + Next.js, ~66k LOC backend) turned REST/GraphQL/SQL/SOAP/MCP upstreams into MCP tools and shipped 257 JSON adapters. An audit on 2026-09-21 found a solid core but enterprise blockers that were structural, not patchable:

- No Helm/k8s/Terraform. Migrations race on multi-replica. Stateful MCP sessions in-process.
- Secrets: single env DEK, no key version in ciphertext, no KMS. MCP API keys and connector `envVars` stored plaintext.
- Audit: `security_events` write-only, admin actions unaudited, no export, no tamper evidence, retention cloud-only. Full tool payloads stored unmasked.
- No SAML, no MFA, no token scopes (HS256 shared secret, no JWKS). `MCP_AUTH_MODE=none` default. `ToolRoleAccess` fails open.
- No metrics endpoint, no circuit breaker, `pg.Pool` per query, rate limiter fails open without Redis.
- RLS shipped but `tenantTx()` has zero callers.
- Knowledge graph + AI skills: direction bug, stalled watermark, unbounded growth, prompt-injection path into server instructions, near-zero tests.

**Decisions (user, 2026-09-21):** new repo **`supermcp`**, Go backend, rebuilt frontend, adapter format v2 with converter for all 257, Helm + compose on day one, **no knowledge graph, no AI skills**.

## Locked decisions

| Area | Choice |
|---|---|
| Backend | Go 1.25, single static binary. Subcommands: `serve`, `migrate`, `worker`, `adapter {validate,convert,new,probe,record,test,index}`, `keys`, `secrets`, `audit verify`, `backup`, `compliance` |
| HTTP | chi + huma v2 (code-first OpenAPI 3.1 at `/api/openapi.json`, drives generated TS client) |
| DB | Postgres 16+ only. pgx + sqlc. goose migrations embedded. Two pools: `app` (RLS, no bypass) and `maint` (BYPASSRLS, jobs/migrations/site-admin) |
| Redis | Optional. Rate limit + session cache + blob cache. Nothing fails open without it |
| MCP | `github.com/modelcontextprotocol/go-sdk` v1.7 (verified: `NewStreamableHTTPHandler(getServer func(*http.Request) *mcp.Server, opts)` builds server per request in stateless mode; `JSONResponse`, `EventStore`, `SessionTimeout`, `PropagateRequestCancellation` supported; no pluggable session store) |
| Frontend | Vite + React 19 SPA, TanStack Router/Query/Table, Cloudflare Kumo design system (`cloudflare/kumo@kumo-design` skill), lingui (English; the interface stays translatable, no second locale ships), CodeMirror 6, generated client via `@hey-api/openapi-ts`. Embedded via `//go:embed`. OAuth consent/device pages are Go `html/template` (no JS, strict CSP) |
| Adapters | YAML v2, one dir per adapter with cassettes, JSON Schema published at `/schema/adapter/v2.json`, embedded via `//go:embed` |
| Deploy | Helm chart primary, docker-compose quickstart, air-gap tarball. distroless static image, cosign keyless, SBOM, SLSA provenance |
| Dropped | Knowledge graph, AI skills, `_intent` param, `ee/cloud` crons, LLM client, `McpResource`/`McpPrompt` tables (never served), `select` transform mode (0 uses), Sentry SDK in UI, GTM/cookie consent. Cut 2026-09-23 after counting the catalog (247 HTTP, 5 GraphQL, 5 database, 0 SOAP, 0 MCP bridge): SOAP engine, WS-Security, WSDL parser, mTLS, MCP bridge engine, oauth1, login bcrypt-with-salt (their only two catalog adapters, `immobilienscout24` and `sorare`, removed 2026-09-25; the corpus keeps them for the converter tests), cassettes for credentialed adapters, Redis session store and blob cache, three of four KMS providers, the two-replica upgrade chaos test and the air-gap bundle — all v1.1. The air-gap bundle has since been built (`make airgap`, `docs/install-airgap.md`). The analytics screen was cut with them and is back in scope as of 2026-09-25 |
| Timeline | ~102 engineer-weeks as first planned; ~84 after the 2026-09-23 cuts |

Settled on 2026-09-23: the rewrite ships under MIT, in the `supermcpco` organisation. The system it replaces is AGPL-3.0 owned by HelpCode-ai; this is a clean-room rewrite by the same owner, so it carries its own terms.

## What must be reproduced (inventory of current system)

Read these while porting; they are the executable spec:

| Area | File(s) under `packages/backend/src` |
|---|---|
| MCP endpoint, visibility | `mcp-server/mcp-endpoint.controller.ts`, `mcp-server/tool-annotations.ts`, `mcp-server/error-hints.ts`, `mcp-server/well-known-oauth.controller.ts`, `mcp-server/dynamic-mcp-tools.ts` (executor pipeline) |
| MCP auth + OAuth middleware | `auth/mcp-combined-auth.guard.ts`, `auth/*.middleware.ts`, `auth/login.controller.ts` (consent + server picker) |
| Engines | `connectors/engines/{rest,graphql,soap,database,mcp-client}.engine.ts`, `oauth2-token.service.ts`, `login-token.service.ts`, `oauth1-signer.ts` |
| Parsers | `connectors/parsers/{openapi,openapi-3.1-normalizer,postman,curl,graphql,wsdl}.parser.ts` |
| Transform | `connectors/response-transform.util.ts` (JMESPath only in practice) |
| SSRF | `common/ssrf.util.ts`, `common/ssrf-policy.service.ts` |
| Reconcile / fingerprint | `connectors/catalog-reconciler.service.ts`, `adapters/catalog-fingerprint.ts` |
| SSO / SCIM | `identity-providers/sso.service.ts`, `identity-providers/scim/*` |
| Schema | `prisma/schema.prisma` (41 models), `prisma/rls/enable-rls.sql` (table list to carry forward) |
| Legacy crypto | `common/crypto/encryption.util.ts` (`base64(iv16|ct|tag16)`, key = first 32 utf-8 bytes) for one-shot import |

**Surface**: 173 REST routes, 8 MCP routes, 6 well-known, 17 SCIM. 257 adapters / 2385 tools.

**Adapter v1 reality** (smaller than docs): connector types REST 247 / GRAPHQL 5 / DATABASE 5; 10 auth types; 6 tool keys; 10 endpointMapping keys; transform jmespath only (13 tools); `authConfig` untyped with 46 distinct keys (OAUTH2 10 shapes, QUERY_AUTH 11, LOGIN_TOKEN 3 dialects incl. sorare bcrypt-with-fetched-salt). Five placeholder syntaxes resolved positionally in `rest.engine.ts:1103`, duplicated in `scripts/probe-keyless.mjs:74`. Kaufland HMAC template stores literal `\n` two chars.

**Semantics to keep, and the fixes**:
- Absence of `McpConnectionGrant` = whole org; grants are a filter after authz, never authority.
- `ToolRoleAccess` fails open → v2 fails closed, migration report lists principals losing access.
- `sessionsValidFrom` watermark (checked in 3 places) → server-side sessions table.
- Tokens instance-wide audience → per-server `aud` from RFC 8707 resource indicator.
- `/revoke` advertised, unimplemented → implement plus `/introspect`.
- Retry never on 500 (write safety); 401 → one refresh/relogin retry, outside retry loop.
- DB read-only default: strip literals/comments, must start SELECT/WITH, single statement, no data-modifying CTE, MAX_ROWS 1000, per-dialect binding (`$n`, `?`, `@pN`, `:bN`).
- OAuth2 rotated refresh token persisted back before use (DATEV pattern); serialize refresh across replicas with `SELECT … FOR UPDATE`.
- Query encoder leaves `: $ ,` unescaped, `+` for space, repeated keys `k=a&k=b`; `__raw`, `__rawquery`, `__spread` escape hatches. Byte-for-byte tests.
- No anonymous demo endpoint. The old product's `/mcp/demo` served a public try-it surface for a hosted service; a self-hosted gateway has no use for one, and it would be the only route that calls tools with no identity. Cut 2026-09-25.

## Architecture

### Repo layout (domain packages, not layers)

```
cmd/supermcp/            main + subcommands
internal/app/            wiring, lifecycle, graceful drain
internal/config/         env/yaml → typed Config, validation, fails on bad KEK length
internal/httpapi/        chi+huma router, middleware, handlers by domain file, embedded SPA
internal/store/          pgx pools (app/maint), sqlc queries, goose migrations, LISTEN/NOTIFY bus
internal/tenant/         RLS context, Tx helper, Bypass(ctx, reason) audited
internal/secrets/        envelope crypto, kek/{local,awskms,gcpkms,azurekv,vault}, rotation
internal/identity/       users, orgs, invites, password (argon2id, lockout, history), session, sso/{oidc,saml}, scim, serviceaccount
internal/authz/          permissions registry, roles, bindings, evaluator, middleware
internal/mcpauth/        OAuth 2.1 AS, ES256 keyring + JWKS, api keys, DCR, revoke, introspect, consent templates
internal/grant/          McpConnectionGrant filter
internal/audit/          hash-chained event stream, writer, spool, read API, exporters/*, retention, dsar
internal/governance/     dlp/, approvals/, revisions/, dryrun, changerequests
internal/hardening/      csp nonces, csrf, headers, ratelimit (redis + memory fallback), redact
internal/connector/      CRUD, env vars, auth cache, test, import-spec, discover-tools, reconcile/resync, upstream OAuth callback
internal/tool/           McpTool CRUD, annotations derivation, catalog cache (NOTIFY-invalidated)
internal/mcpserver/      McpServerConfig, composed instructions
internal/mcp/            Streamable HTTP endpoint, surface builder, session ownership store, error hints
internal/invoke/         executor: resolve → tmpl → auth → engine → transform → dlp → content → audit
internal/engine/         Engine iface + rest/ graphql/ database/ (soap/ and mcpbridge/ are v1.1)
internal/upstreamauth/   none apikey query bearer basic oauth2 hmac login database (oauth1, wssecurity, mtls are v1.1)
internal/httpclient/     per-connector *http.Client: pooled transport, SSRF dialer, breaker, semaphore, retry
internal/ssrf/           policy (env + DB allowlist), IP classification, resolver
internal/dbpool/         registry keyed by connector+cred hash, per-dialect openers, idle eviction
internal/parser/         openapi (3.0/3.1); postman, curl, graphql and wsdl are v1.1
internal/transform/      JMESPath, maxBytes, fallbackToRaw
internal/jobs/           scheduler, advisory-lock leader election, job registry
internal/telemetry/      slog, otel tracer, prometheus registry
internal/health/         /healthz, /readyz (schema version), /health/server-info
internal/catalog/        embedded adapters, index.gen.json, public endpoints
internal/compliance/     access review, crypto report, config snapshot
internal/web/            //go:embed all:dist
pkg/adapter/             v2 types, load, validate, v1compat converter, fingerprint
pkg/tmpl/                placeholder engine (single syntax)
web/                     Vite SPA
charts/supermcp/         Helm
deploy/compose/          quickstart
docs/                    install, helm ref, adapter authoring, api ref, runbooks, compliance/
```

### Core interfaces

```go
// internal/engine
type Engine interface {
    Kind() Kind
    Execute(ctx context.Context, req *Request) (*Response, error)
    DryRun(ctx context.Context, req *Request) (*Preview, error) // rendered request, secrets redacted; EXPLAIN for SQL
    Test(ctx context.Context, conn *ResolvedConnector) error
}
type Response struct {
    Body      any            // decoded JSON / parsed XML / rows; nil when Stream != nil
    Stream    io.ReadCloser  // binary or > MaxInlineBytes; MediaType set
    MediaType string
    Status    int
    Headers   map[string]string // exposeHeaders only
    Meta      Meta              // rowCount, truncated, upstreamDurationMs, retries
}

// internal/upstreamauth — optional capabilities by type assertion
type Authenticator interface{ Apply(ctx context.Context, req *http.Request) error }
type Signer interface{ Sign(ctx context.Context, req *http.Request, body []byte) error }       // oauth1, hmac
type Refresher interface{ Refresh(ctx context.Context) (retry bool, err error) }               // oauth2, login
type TLSConfigurer interface{ TLSConfig(ctx context.Context) (*tls.Config, error) }            // mtls
type SOAPHeaderProvider interface{ SOAPHeaders(ctx context.Context) ([]xmlNode, error) }       // wssecurity

// internal/authz
type Principal struct {
    Kind PrincipalKind // User | ServiceAccount | APIKey | OAuthClientOnBehalf
    ID, OrgID, SessionID, ServerID, AuthMethod string
    Scopes []string
    MFA bool
}
func (e *Evaluator) Evaluate(ctx context.Context, r Request) Decision // fail-closed, see Authorization

// internal/secrets
type Sealer interface {
    Seal(ctx context.Context, scope Scope, plaintext []byte, aad AAD) ([]byte, error)
    Open(ctx context.Context, ciphertext []byte, aad AAD) ([]byte, error)
}
type KEK interface{ Wrap(ctx, dek []byte) ([]byte, error); Unwrap(ctx, wrapped []byte) ([]byte, error); Ref() string }

// internal/jobs
type Job interface{ Name() string; Every() time.Duration; Run(ctx context.Context) error; Singleton() bool; Scope() Scope /* PerOrg | Instance */ }
```

### `pkg/tmpl` — one placeholder syntax

`{{ns.path [| filter]}}`. Namespaces: `params.*`, `env.*`, `caller.email|sub|org`, `auth.token|username|<credential>`, `req.method|url|body|timestamp` (hmac/login contexts only). A string that is exactly one placeholder substitutes typed (unset param drops the key). Any other occurrence is string interpolation, URL-escaped in path segments unless `| raw`. Filters: `default:<json>`, `json`, `urlencode`, `raw`, `join:","`, `base64`. Literal braces via `{{ "{{" }}`. Linter rejects unresolved `{{`. `SQL(t, params, dialect) (sql, args)` binds `{{params.x}}` to `$1`/`?`/`@p0`/`:b0`. The five v1 syntaxes exist only in `pkg/adapter/v1compat`.

### MCP transport (`internal/mcp`)

- Routes `POST|GET|DELETE /mcp/{serverId}`. Auth middleware sets `Principal`; 401 carries `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp/{serverId}"`. GET without session in stateless mode → 405 before auth (Copilot probe).
- One `*mcp.StreamableHTTPHandler` per process with `Stateless: true`; `getServer(req)` calls `SurfaceBuilder.Build(principal, serverID)`: server config (cached 30s) → inactive 403 → membership (instance principals exempt) → grant reach → `authz.Evaluate(tools:invoke)` per tool → dedupe by name → `server.AddTool` with stored `parameters` (credential-named params stripped), derived annotations → `AddReceivingMiddleware` refusing hidden `tools/call` with `-32600`. Precomputed `*mcp.Tool` values shared read-only per connector version. Benchmark gate < 5 ms at 500 tools.
- Stateful mode (`MCP_STATEFUL_SESSIONS=true`, opt-in): `Stateless: false`, `SessionTimeout: 30m`. go-sdk sessions are in-process, so document sticky routing; `session.Store` (memory + Redis) records `sid → {ServerID, PrincipalKey, OrgID}` so a foreign replica 404s fast and the client re-initializes. Catalog NOTIFY → diff surface → `AddTool`/`RemoveTools` → `tools/list_changed`.
- Framing `MCP_RESPONSE_MODE=sse|json` → `JSONResponse`. Default sse.
- Content: engine `Stream` + `MediaType` → `image/*` ImageContent, `audio/*` AudioContent, other binary → EmbeddedResource blob ≤ 8 MiB else ResourceLink to `GET /api/blobs/{id}` (TTL, principal-bound, Redis or Postgres bytea fallback). Progress notifications every N bytes when client sent `progressToken`. `PropagateRequestCancellation: true` aborts upstream on client disconnect.

### Upstream HTTP policy (`internal/httpclient`)

Per connector: one `*http.Transport` (`MaxIdleConnsPerHost 16`, HTTP/2), timeouts connect 10s / TLS 10s / header 30s / total 30s (connector `transport.timeout`, tool `timeout` ≤ connector max), semaphore default 32, `gobreaker` (trip ≥10 req and ≥60% 5xx/network; 4xx not counted), retry `[300,900,2500]ms` on 421/429/502/503/504 + dial/reset/TLS errors only when body replayable, `io.LimitReader` 16 MiB. Order: semaphore → breaker → retry → `client.Do`. 401 refresh handled once in REST engine outside retry loop. Entry rebuilt when connector version changes; idle eviction 15 min.

SSRF dialer in `DialContext`: parse IP or resolve all A/AAAA, reject if any non-public (169.254/16, 0/8, 224/4, 240/4, IPv6 equivalents unconditional; 10/8, 172.16/12, 192.168/16, 100.64/10, loopback by policy), then dial the checked IPs, not the name (no rebinding window). `CheckRedirect` re-runs policy, max 5. Same dialer injected into mcpbridge client, token fetches, parser URL fetches, WSDL, GraphQL introspection, exporters. Policy = env + `site_settings.ssrf_allowed_hosts`.

### DB connector pooling (`internal/dbpool`)

Key `sha256(connectorID | dialect | dsn | readOnly)`. Drivers: pgx (`default_transaction_read_only=on`, `statement_timeout`), go-sql-driver/mysql, microsoft/go-mssqldb, sijms/go-ora, modernc sqlite (`mode=ro`, path under `SQLITE_ROOT`), mongo-go-driver. Idle > 10 min closed, cap 200 pools LRU. SSRF via driver `DialContext` where supported; mssql/oracle pre-resolve + connect by IP with SNI. Validator ported verbatim.

### Background jobs (`internal/jobs`)

Runs in `serve` or only in `worker` (`JOBS_MODE=worker`). Leader via `pg_try_advisory_lock(hashtext('supermcp:leader'))` on dedicated conn; per-job `pg_try_advisory_xact_lock`. `PerOrg` jobs iterate orgs under Bypass then run body under `WithOrg` on app pool; `Instance` jobs use maint pool. Jobs: audit_retention, audit_partition_maint, audit_exporters, oauth_token_refresh (1m), catalog_resync (15m), auth_cache_prune, session_reaper, api_key_grace_revoke, approval_expiry, key_rotation, dek_rotation, dbpool/httpclient sweep, metrics_snapshot, license_heartbeat.

### Observability

Prometheus on admin listener: `supermcp_tool_calls_total{connector_type,status,error_class}`, `supermcp_tool_call_duration_seconds{connector_type}`, per-tool series opt-in (`METRICS_PER_TOOL`, cap 5000 then `_other`), `supermcp_upstream_*{connector_id,…}`, `supermcp_breaker_state`, `supermcp_mcp_requests_total{endpoint,method,code}`, `supermcp_surface_build_seconds`, dbpool/cache/ssrf/jobs/leader gauges. Spans: `mcp.request` → `mcp.surface.build` → `tool.call` → `tmpl.resolve` → `upstreamauth.apply` → `engine.*` → `http.client`/`db.query` → `transform.apply` → `dlp.scan` → `audit.write`. `traceparent` to upstream only when connector `propagateTrace: true`. slog fields: req_id, trace_id, org_id, server_id, principal, tool, connector, duration_ms, status, error_class; secret values masked by per-request bloom of decrypted plaintexts.

## Enterprise layer

### Tenancy (RLS from M1)

Two Postgres roles `supermcp_app` (NOBYPASSRLS, no UPDATE/DELETE on `audit_events`) and `supermcp_maint`. Every query goes through `tenant.Tx` which runs `set_config('app.current_org', $1, true)` (transaction-local). `AfterRelease` resets; `BeforeAcquire` rejects dirty connections. Policies `current_setting('app.current_org', true) = organization_id`; NULL matches nothing. Pre-auth lookups (login by email, session load, SSO callback, token endpoint) via SECURITY DEFINER functions, not widened policies. CI test generated from `information_schema` asserts every table with `organization_id` returns 0 rows under the wrong org. No per-tenant schemas: RLS + per-org DEK cover the threat model; physical isolation = dedicated instance, same binary.

### Secrets (envelope, M1)

KEK (local env/file, AWS KMS, GCP KMS, Azure KV, Vault transit) wraps per-org DEK and an instance DEK. Ciphertext bytea: `0x01 | dek_id(16) | nonce(12) | AES-256-GCM ct||tag`, AAD = `table|column|row_id|org_id` mandatory. Tables `kek_configs`, `data_keys(scope_kind, scope_id, kek_id, wrapped, version, status)`. Encrypted: connector auth, **env vars value-level**, headers values, auth cache tokens, IdP secrets, SAML SP key, signing keys. Local KEK must be exactly 32 bytes base64; wrong length fails boot. KEK rotation re-wraps DEKs only; DEK rotation re-seals rows in batches of 500 with `SKIP LOCKED`, resumable.

### Identity

- Sessions table (`idle_expires_at` 12h, `absolute_expires_at` 30d, org overrides), cookie `__Host-sm_sess` HttpOnly Secure SameSite=Lax, `last_seen_at` throttled 60s, device list + revoke, `RequireFreshAuth(5m)` on sensitive ops. No token in browser storage.
- Passwords argon2id (bcrypt verified and upgraded on login), policy per org (min 12, history 5, max age), lockout table keyed `user:`/`ip:` with exponential lock.
- MFA: not ours to issue. Enterprise sign-in goes through the identity provider, which enforces its own second factor and reports it in `amr`; the session stores `mfa_verified_at` and the principal an `MFA` flag so a policy can require a verified factor. No TOTP enrolment, recovery codes or WebAuthn. (Cut 2026-09-22.)
- SSO: OIDC parity (Entra, Google, Okta, Auth0, GitHub, generic) M2; SAML 2.0 SP via crewjam/saml (metadata, ACS, replay table) v1.1. SCIM 2.0 parity; `active=false` revokes sessions + keys + refresh tokens; SCIM token becomes api key with scope `scim:write`.
- Service accounts: org-scoped, `client_credentials` or bound API key, same role bindings.

### Authorization (fail closed)

Permissions closed set (`connectors:read`, `tools:invoke`, `tools:invoke:destructive`, `audit:export`, `approvals:decide`, …). Built-in roles owner/admin/editor/viewer/approver/auditor/mcp-consumer; custom roles = permission sets. Tables `roles(permissions text[])`, `role_bindings(principal_kind user|service_account|idp_group, scope_kind org|server|connector|tool, source, expires_at)`, `tool_access_rules(effect allow|deny)`. Evaluator: org match → token scopes → bindings (cached 30s, NOTIFY-invalidated) → scope containment → explicit deny wins → whitelist semantics when allow rows exist → destructive needs extra permission when policy says so → ABAC hooks (v1.1). Every deny audited (sampled for list storms). Migration: org roles → org-scoped bindings, MCP roles → roles with `tools:*`, `tool_role_access` → allow rules, principals losing access listed in `supermcp migrate --report`, temporary `authz.legacy_open_tools` flag for two minors.

### MCP auth (`internal/mcpauth`)

ES256 keyring in `signing_keys` (private sealed with instance DEK), `/.well-known/jwks.json` serves active+retiring+next, rotation 90d with 24h pre-publish. Claims: `aud = <public_url>/mcp/<server>` from resource indicator (consent forces server pick if absent), `scope` from `mcp:tools:read mcp:tools:invoke mcp:server:<id> offline_access`, `amr`, `sid`, `jti`. AT 1h, refresh 30d rotating with family revocation on reuse. Endpoints: authorize (PKCE S256 only), token (code, refresh, client_credentials), `/oauth/revoke`, `/oauth/introspect`, DCR with rate limit + `dcr.mode open|approval|closed` + software statements, userinfo, well-known with `jwks_uri`, `revocation_endpoint`, `introspection_endpoint`, `scopes_supported`. API keys `smk_<prefix12><secret43>`: sha256 hash at rest, prefix lookup, scopes, server audience, expiry default 90d, rotate with grace, last-used throttled; legacy `mcp_` keys hashed on import and accepted 90 days flagged for rotation. `MCP_AUTH_MODE` removed; `--dev` flag only on loopback.

### Audit

`audit_events` partitioned monthly, uuidv7 id, global `seq`, `prev_hash`/`hash` = sha256(prev || canonical row || sha256(payload)), append-only enforced by role grants plus RULE allowing only legal_hold/actor pseudonymization/payload scrub. Single writer goroutine per process, advisory lock serializes across replicas, batch 200, local NDJSON spool when DB down, `audit.on_unavailable=block|degrade` per org. Anchors every 10 min / 10k events, ES256-signed, optional external anchor. Coverage: auth, every mutating admin call with before/after diff (secrets as `<redacted:sha256-8>`), tool invocations (meta always; payload per org `none|metadata|masked|full`, max 64 KiB, DLP findings always masked), authz denials, secrets ops, governance, system. Read API with filters and `q` full-text; `GET …/audit/verify`. Exporters table with cursor: webhook (HMAC signed) M3; syslog/CEF, S3/GCS, OTLP logs, Splunk HEC v1.1. Retention per org (default 365, min 90) drops partitions, `retention_cut` anchor keeps chain verifiable; legal holds; DSAR export zip and erasure by pseudonymizing display columns (hash excludes them).

### Governance

- **Revisions** (M3): `revisions(entity_kind, entity_id, revision, snapshot, diff)` written in same tx as every mutation of connector/tool/server/role/policy/idp; optimistic concurrency 409; diff and rollback API; secrets as pointers.
- **DLP** (v1.1): `Detector` interface; built-ins pan/iban/email/phone/ssn/secret patterns/custom regex; external Presidio/webhook via SSRF guard; `dlp_policies(scope, direction, detectors, action mask|block|alert, mask_style)`; pipeline after JMESPath, before audit.
- **Approvals** (v1.1): `approval_policies(trigger destructive|all|flagged|arg_match, approvers, timeout, notify)`, `approval_requests` state machine pending→approved/denied/expired/cancelled→executing→executed/failed; input sealed and replayed under requester principal. Client experience: MCP elicitation when client supports it (hold call ≤55s per round), else immediate `pending_approval` result plus built-in `supermcp_approval_status`/`supermcp_approval_cancel` tools.
- **Dry-run** (v1.1): `_supermcp.dry_run` arg or `supermcp_dry_run` tool → `Engine.DryRun`.
- **4-eyes change approval** (later): reuse approval tables with `trigger=admin_change`.

### Hardening

CSP with per-response nonces + `strict-dynamic`, report-only one release. OpenAPI JSON behind session; Swagger UI off in prod. CSRF: `Origin`/`Sec-Fetch-Site` check + double-submit `sm_csrf`; bearer requests exempt. `SUPERMCP_PUBLIC_URL` must be https unless loopback. Rate limiter: Redis sliding window; memory token-bucket fallback with limits divided by `expected_replicas`, emits `system.ratelimit_degraded`, never allow-all. CI: golangci-lint, govulncheck, gosec, gitleaks (custom `smk_` rule, runs on cassettes), CodeQL, go test -race, RLS matrix, Trivy. Release: goreleaser, distroless, syft SBOM, cosign keyless, SLSA L3 provenance. SECURITY.md: reachable dependency CVEs in scope, SLA critical 7d / high 30d.

### Compliance pack (M6)

`supermcp compliance access-review|crypto-report|config-snapshot`, `audit verify` output, SBOM + attestations linked from About page, `docs/compliance/{dr-runbook,incident-response,shared-responsibility,data-flow,retention-schedule,control-mapping}.md`. Residency knobs: org `data.region` label, per-org exporter buckets, per-org KEK override, egress allowlist, `audit.payload.mode=none`.

## Adapter format v2

YAML, one directory per adapter: `adapters/<region>/<slug>/{adapter.yaml, tests/*.yaml, cassettes/*.yaml}`. First line `# yaml-language-server: $schema=https://supermcp.dev/schema/adapter/v2.json`. Linter forbids anchors, custom tags, implicit-type drift (round-trips via JSON).

```yaml
apiVersion: supermcp.dev/v2
kind: Adapter
metadata: { slug, name, description, region (enum, == dir), category (enum of 32), icon, docsUrl, priority, featured, selfHostOnly, v1Fingerprint, lint: { allow: [rule-ids] } }
credentials:                      # single declaration site
  KAUFLAND_SECRET_KEY: { required: true, secret: true, usage: template|manual, description }
transport: { type: http|graphql|database|soap|mcp, baseUrl|dsn, headers, timeout, rateLimit, proxy }   # soap and mcp are accepted by the schema; their engines ship in v1.1
auth: { type: none|apiKey|bearer|basic|query|oauth2|oauth1|login|hmac|database, ... }   # discriminated union
healthcheck: { tool, params, expect } | { http: { method, path, status } }
instructions: |
tools:
  - name, description, input (JSON Schema subset), output, annotations, timeout, rateLimit, proxy
    operation:  # union keyed by transport.type
      # http: method, path, query, headers, body { encoding: json|form|multipart|raw, value }
      # graphql: kind query|mutation, document, variables
      # database: kind sql|schema|static, statement (| raw), maxRows
      # soap: action, envelope
      # mcp: tool, argsMap
    response: { transform: { jmespath }, cache: 60s, exposeHeaders }
```

**Auth union highlights**: `oauth2 { grant, clientId, clientSecret, tokenUrl, authorizationUrl, scopes[], clientAuth basic|body, refreshToken, inject }`; `query { params }` covers all 11 v1 shapes verbatim; `login { request, credentials, preprocess[] (bcrypt with salt fetch), token { source body|cookie|setCookie, jsonPath, cookieName }, inject, expiry }` covers 3 dialects; `apiKey { in header|query|cookie, optional }` for the coingecko/dchub pattern.

**Converter** `supermcp adapter convert --from v1 --in <dir> --out adapters/ --report report.json` (`pkg/adapter/v1compat`): deterministic yaml.Node emission, block scalars for instructions/document/statement/stringToSign. OAUTH2 grant inference: explicit `grant` → `refreshToken` present → `authorizationUrl` present → client_credentials. Unknown authConfig key → BLOCKER (never silent drop). Placeholder rewrites: `{x}` path → `{{params.x}}`; `"$x"` → `"{{params.x}}"`; `${x}` → `{{params.x}}` or `{{auth.x}}` in authConfig or `{{req.*}}` in HMAC; `{{ENV}}` → `{{env.ENV}}` and must be in `credentials`. Kaufland `\n` JSON-unescaped then block scalar; cassette asserts identical signature. Category merge table reported. Expected ~30 review items, ~2 blockers (null-authConfig OAuth adapters: google-analytics-4, fatture-in-cloud). `metadata.v1Fingerprint` = port of `catalog-fingerprint.ts` with golden test over 257 files; M6 import rewrites `connectors.catalog_version` to new `contentHash`.

**Parity proof**: `scripts/dump-v1-requests.mjs` in old repo drives the TS engine dry-run for every tool → `{method,url,headers,body}`; Go `TestV1RequestParity` replays through `Engine.DryRun` and diffs. This, not schema validity, proves the converter.

**Validate** `supermcp adapter validate [--strict] [--format text|json|sarif]`: JSON Schema then rules `slug-dir, region-dir, tool-name-prefix, tool-name-unique-catalog, description-min-60, instructions-min-800, env-declared, env-unused, placeholder-unknown, healthcheck-present, jmespath-parses, graphql-parses, sql-readonly, yaml-no-anchors, yaml-type-drift, auth-optional-consistency, icon-https, schema-subset`.

**Catalog**: `//go:embed adapters/*/*/adapter.yaml` + `index.gen.json` (`go generate`, CI diff check); lazy parse per slug; `SUPERMCP_CATALOG_EXTRA_DIRS` overlay. Endpoints `GET /api/v1/catalog` (ETag), `/catalog/{slug}`, `/catalog/{slug}/adapter.yaml`, `/catalog/schema`.

**Contributor flow**: `adapter new`, `validate`, `probe`, `record` (go-vcr v4, credentials → `<REDACTED:ENV>`, drop Authorization/Cookie/Set-Cookie), `test` (offline replay default, `--live` when env set; replaces `probe-keyless.mjs` and live specs). Cassettes are recorded for the keyless adapters in v1.0; the credentialed ones rely on the request-parity harness and the nightly probe until v1.1. PR template + CODEOWNERS by region + index diff comment.

## Deploy, CI, release

- **Image**: goreleaser static binaries (linux/darwin/windows × amd64/arm64), `distroless/static:nonroot`, multi-arch. `/healthz` process, `/readyz` DB + schema version.
- **Helm** `charts/supermcp`: deployment, service, ingress, hpa, pdb, networkpolicy, serviceaccount (workload identity annotations), secret/existingSecret, migrate hook Job (`pre-install,pre-upgrade`, `supermcp migrate --wait-lock` under `pg_advisory_lock(hashtext('supermcp:migrate'))`), cronjob-backup (`pg_dump -Fc` → S3, `supermcp backup verify` restores to scratch and checks `keys verify`), servicemonitor, prometheusrule (SupermcpDown, HighToolErrorRate, ToolLatencyP99High, MigrationJobFailed, AuditExportLag, DBConnPoolSaturated, KMSUnreachable), grafana dashboard configmap. Restricted PodSecurity, readOnlyRootFilesystem. `serve` never migrates unless `SUPERMCP_MIGRATE_ON_START=true` (compose only).
- **Compose quickstart**: supermcp + postgres:17, optional caddy profile, `.env` with `ENCRYPTION_KEK` required.
- **Air-gap**: tarball with OCI image layout, chart tgz, adapters export, SBOM, signed checksums, INSTALL-AIRGAP.md.
- **CI**: go-lint, go-test (race, 70% gate on internal/), go-integration (testcontainers Postgres 17 + Redis), security (govulncheck, gosec, gitleaks, CodeQL), adapters (validate --strict sarif, test, index diff), web (eslint jsx-a11y, tsc, vitest, generated client freshness, size-limit 600 KB gz), e2e (binary + Postgres, Playwright + axe), helm (lint, kubeconform 1.29/1.31, ct install on kind), image-scan (Trivy fail HIGH/CRITICAL).
- **Release**: release-please bumps VERSION + chart; goreleaser; cosign sign + attest SBOM; SLSA generators; chart push to `oci://ghcr.io/supermcpco/charts`. Schema policy N-1 expand-only; `scripts/check-migrations.sh` blocks DROP/RENAME/NOT NULL without `-- supermcp:breaking` marker + UPGRADING.md section; integration test applies previous-tag migrations then current. Two minors get security fixes.

## Frontend (`web/`)

Vite + React 19 + TanStack Router/Query/Table, generated client only (no hand-written api layer), react-hook-form + zod, shadcn/ui, CodeMirror 6, `@git-diff-view/react`, recharts, lingui, English only, jsx-a11y + vitest-axe + axe in Playwright. Session cookie from Go; `GET /api/v1/auth/session` bootstraps; 401 → `/login?next=`; 403 `reauth_required` → fresh sign-in. Served by Go with SPA fallback, immutable hashed assets, `no-store` index.

Screens: auth pages, `/connectors` (list, detail, import YAML/OpenAPI/Postman/cURL/WSDL, tool editor with dry-run request preview and mapping preview, catalog re-sync diff), `/store`, `/servers` (tool selection, client config snippet), `/users`, `/orgs`, `/roles` + `/roles/:id` permission builder with effective-permission preview, `/settings` (org, SSO/SCIM, license, api-keys with scopes/expiry/rotate, service-accounts, dlp editor), `/account/security` (password, sessions/devices), `/tool-calls`, `/audit` explorer with chain badge + async export, `/approvals` inbox, `/:kind/:id/revisions` diff + restore, `/analytics`, `/status`. Go-template pages: OAuth consent, server picker, device code.

## Phased delivery (3 engineers: A core/adapters, B identity/governance, C platform/frontend)

| M | Goal | Scope | Exit criteria | ew / weeks |
|---|---|---|---|---|
| **M0** Skeleton | Repo, contract, tooling | Layout, config, slog, `serve` + healthz; goose + advisory-lock migrate; huma OpenAPI emission; `pkg/adapter` v2 schema/types/validator/converter/index; all 257 converted, report reviewed; CI jobs; goreleaser + distroless; Helm v0; compose; Vite skeleton with generated client, shadcn, lingui, axe | `helm install` on kind; `docker compose up` serves shell; `adapter validate --strict` 257/257, 0 blockers; release dry-run produces signed image + SBOM | 12 / 4 |
| **M1** Core | Usable single-org product | Engines http/graphql/database; `pkg/tmpl`; upstream auth all except oauth2 auth-code, oauth1, login-bcrypt; MCP endpoint (stateless, annotations); connectors/servers/tools CRUD; catalog install + resync; **envelope encryption local KEK**; **RLS enforced with two pools + CI matrix**; sessions + argon2id + lockout; authz model with built-in roles; api keys hashed with scopes; tool-call log (basic audit table); parity test on ~60 adapters; UI: auth, connectors, store, servers, api-keys, tool-calls, users/orgs | Install kaufland/postgres from catalog, call tools from Claude Desktop via API key; parity green on subset; RLS matrix green; e2e green | 18 / 6 |
| **M2** Identity | Enterprise login | OAuth 2.1 AS (ES256/JWKS, per-server aud, scopes, PKCE, DCR modes, revoke, introspect, consent templates, resource indicators); OIDC RP parity; SCIM parity; service accounts; password policy; UI: security settings, sessions, service accounts, SSO/SCIM | Claude/Cursor connect via OAuth, no API key; Okta/Entra OIDC + SCIM fixtures pass; token for `/mcp/a` rejected at `/mcp/b` | 15 / 5 |
| **M3** Governance | Auditable changes | Hash-chained `audit_events` + spool + anchors + read API + webhook exporter + payload policy + retention; admin mutation diffs; revisions + rollback for connectors/tools/servers; roles API + read-only roles screen; AWS KMS + KEK rotation; UI: audit explorer/export, revisions | `audit verify` passes after 100k events with retention cut; rollback round-trip in e2e; KEK rotate on kind with localstack | 14 / 5 |
| **M4** Catalog parity | All 257 run | oauth2 auth-code (M2 callback); parsers openapi 3.0/3.1; transform + cache; binary/streaming content; cassettes for the keyless adapters; parity across 2385 tools; nightly live keyless probe | parity green across 2385 tools; nightly probe green; re-sync UI on fingerprint change | 9 / 3 |
| **M5** Hardening | Prod scale | Redis-backed rate limit with memory fallback; Prometheus `/metrics` + alert rules; k6 (500 rps tool calls, p99 overhead < 300 ms); migrations compatibility test against the previous tag; HPA/PDB tuning; CSP enforce; `/status` UI; browser smoke test (Playwright + axe); coverage gate on `internal/`; gosec/Trivy clean | Load targets met; migrations compatibility green; CSP enforced with zero violations in e2e | 9 / 3 |
| **M6** GA | Ship | docs (install, adapter authoring, API reference, UPGRADING.md); compliance pack (data flow, retention schedule, shared responsibility); v1.1 backlog groomed | v1.0.0 tagged, signed, provenance attached | 10 / 3 |

**Critical path**: M0 adapter lib → M1 engines + tmpl → M4 cassettes and parity → M5 load → M6 import. Second chain: M1 sessions/authz → M2 AS → M3 audit actors. M2 (B) and M4 (A) overlap; C lags API by ~2 weeks per milestone.

**Top risks**: (1) surface build cost with large catalogs → precomputed tools, NOTIFY cache, benchmark gate; (2) byte-level parity of query encoding/body forms across 254 adapters → parity harness before any traffic; (3) go-sdk has no external session store → stateless default, sticky routing documented; (4) OAuth2 refresh rotation races across replicas → row lock + singleflight; (5) SSRF for drivers owning sockets (mssql, oracle, mongo) → connect-by-IP + SNI, deny-by-default, stub-DNS tests; (6) converter blockers in bodyTemplate (8) and null-authConfig adapters; (7) cassette secret leakage → gitleaks on cassettes + record-time allowlist test; (8) import needs old `ENCRYPTION_KEY` → document first.

## Verification

- **Unit**: `pkg/tmpl` tables ported 1:1 from `rest.engine.spec.ts`, `env-interpolation.spec.ts`, `caller-context.spec.ts`; SSRF classifier; SQL validator + binders; annotations; error hints; transform; authz evaluator matrix; secrets seal/open + AAD mismatch; audit hash chain.
- **Engine conformance**: `TestParityWithLegacyEngine` replays 1741 recorded requests from the TS engine and diffs method, URL, query, headers and body; go-vcr cassettes for the keyless adapters replayed in CI.
- **Integration** (testcontainers): migrations up/down; RLS matrix generated from `information_schema`; rbac/grant matrices; reconcile by operationId; dbpool eviction; two-scheduler leader election; audit writer under concurrent replicas; retention cut + verify.
- **MCP conformance**: httptest + go-sdk client, both framings, both protocol revisions: list filtering, hidden call `-32600`, membership 403, stateful ownership rejection, image/blob content, cancellation aborts upstream.
- **OAuth contract**: PKCE required S256, aud from resource, refresh rotation + family revoke, client_credentials, DCR modes, revoke, introspect, JWKS rotation, well-known shapes per RFC 8414/9728.
- **E2E** (Playwright + axe against real binary): login, install adapter → create server → call tool via MCP client, OAuth connect from a client, rollback round-trip, audit export, air-gap install on disconnected kind.
- **Load**: k6 in `hack/` at 500 rps, `go test -bench` on `SurfaceBuilder.Build` at 500 tools.
- **Browser**: Playwright with axe on install → server → key → tool call, which is the path the Go tests reach only through the service layer.
