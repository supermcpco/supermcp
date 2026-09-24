# Shared responsibility

supermcp is software you run. There is no hosted service behind it, no
account with the supplier, and nothing phones home. Everything below the
application — the cluster, the database, the network, the keys, the
backups — is yours.

This document says which is which, and is deliberately unflattering
about the operator's side, because a list that makes the operator's job
look small is worse than no list.

## What the software does

### Tenant isolation

Every tenant-scoped table carries `organization_id` and has row-level
security enabled and forced. Each policy compares that column to
`current_setting('app.current_org')`, which is set per transaction. A
missing setting matches nothing, so an unscoped query returns no rows
rather than all of them.

The application connects as a Postgres role created by the migrations
with `NOBYPASSRLS`, and every connection in that pool issues `SET ROLE`
before it is used. Cross-tenant work — migrations, the audit writer,
the retention sweep, the audit exporter — goes through a separate pool
and a helper that requires a stated reason, which is logged.

Lookups that happen before a tenant is known — sign-in by email,
loading a session, resolving an API key, the single sign-on callback,
the token endpoint — go through narrow `SECURITY DEFINER` functions
with fixed shapes, rather than through widened table policies.

### Encryption of stored credentials

Envelope encryption, described in `data-flow.md`. Per-workspace data
keys, AES-256-GCM, with the row's identity bound into the additional
authenticated data. A master key that cannot be built at boot is a boot
failure, never a silent downgrade to a weaker one.

### Authentication and authorisation

Server-side sessions with idle and absolute expiry; argon2id passwords
with a configurable policy, history and lockout; OAuth 2.1 for MCP
clients with mandatory PKCE `S256`, per-server token audiences, rotating
refresh tokens with family revocation on reuse, and ES256 tokens
verifiable from a published JWKS; API keys stored as SHA-256 with
expiry, server binding and scopes. Permission checks fail closed: no
binding means no access.

### The audit trail

An append-only, hash-chained stream the application role cannot write
to, covering sign-ins, administrative changes with before-and-after
diffs, secret operations, tool calls and refused access.
`supermcp audit verify` walks it and names the row where it breaks.

### Outbound request control

Every outbound connection — upstream calls, identity provider calls,
audit webhook deliveries, OpenAPI imports — goes through a dialer that
resolves the name, classifies every address, refuses private, loopback,
link-local and reserved ones unless policy allows, and then connects to
an address it checked rather than to the name. Redirects are re-checked.

### Resilience on the request path

Per-connector connection pools, timeouts, a concurrency cap, a circuit
breaker that ignores 4xx, retries only on transient statuses and only
when the body can be replayed, and a 16 MiB response cap. Rate limiting
that divides the budget when Redis is gone rather than allowing
everything through.

### Migrations

Applied under a Postgres advisory lock, so replicas starting together do
not race. `/readyz` fails while the schema is older than the binary, so
a rolling upgrade does not serve traffic from a pod whose migration has
not finished.

## What the operator must do

### Key custody

This is the largest single responsibility and the one with no recovery
path.

- **Escrow the master key somewhere other than the cluster.** With the
  `local` provider the key is an environment variable or a file. A
  Postgres backup without it is unreadable: every connector credential,
  every upstream token, every identity provider secret and the token
  signing keys are encrypted under data keys that only it can unwrap.
  The Helm chart prints this warning after every install with the local
  provider, and it is not a formality.
- **Keep old master keys for as long as you keep backups.** A restored
  dump still carries data keys wrapped by whichever key was active when
  it was taken.
- **Rotate deliberately.** The procedure is in `docs/operations.md` and
  needs no maintenance window if the steps are taken in order. It is not
  automatic; nothing rotates a master key on a schedule.
- **Decide whether the key should be in the pod at all.** The AWS KMS
  provider keeps it out; `docs/install.md` has the settings.
- **The token signing keys rotate on their own.** A key is created on
  first boot, and after ninety days the next one is published for a day
  before it takes over, so a client that cached the key set can still
  verify what is signed after the change. The one it replaces keeps
  verifying for thirty days.
- **Nothing rotates data keys.** `RotateDataKey` exists in the code and
  no command or job calls it. Re-keying a workspace's stored values is
  not an operation this release offers.

### Backups and recovery

There is no backup command and no backup job. The chart renders no
CronJob for it.

- Back up Postgres yourself, with whatever your platform provides.
- Encrypt the backups and decide how long they live. They contain the
  ciphertext of every credential, the tool-call log with its arguments,
  and the audit trail.
- Test restores. After a restore, run `supermcp audit verify` and
  `supermcp keys verify` before trusting the instance.
- Redis, where it is used, holds cached tool results and therefore
  business data. Decide whether it needs the same treatment.
- There is no documented disaster-recovery procedure beyond the
  paragraph above.

### Network

- **Terminate TLS.** The binary serves plain HTTP on its listener.
  Certificates, cipher suites, protocol versions and HSTS are the
  ingress controller's or the reverse proxy's. `SUPERMCP_PUBLIC_URL`
  must be the `https` address, and the binary refuses to start with a
  non-loopback `http` one.
- **Keep the admin listener off the ingress.** `/metrics` describes the
  shape of the estate. The chart gives it its own port and does not
  route it; if you change that, you are publishing it.
- **Egress is yours.** The SSRF guard is an in-process control against a
  connector or an import being pointed somewhere it should not go. It is
  not a substitute for a network policy or an egress proxy. The chart's
  network policy defaults to allowing all egress, which is honest for a
  system whose job is to call arbitrary APIs and is not a security
  control. If your policy is that this system may reach a named list of
  vendors and nothing else, enforce that at the network, and set
  `SUPERMCP_SSRF_ALLOWED_HOSTS` for anything internal it must reach.
- **Postgres and Redis.** Their network reachability, their TLS, their
  authentication and their own patching are yours. Use `sslmode=require`
  or stronger in `DATABASE_URL` and `rediss://` for Redis.

### Database roles

The migrations create the `supermcp_app` role and grant it what it
needs. Deciding which database *users* the two pools log in as is yours.
Leaving `SUPERMCP_MAINT_DATABASE_URL` unset means both pools use the
same login user and the separation rests on `SET ROLE` alone. Giving the
maintenance pool its own user, and the application pool a user with no
rights beyond `supermcp_app`, is the stronger arrangement and the one to
choose if an auditor will ask.

### Upgrades

- Read `docs/UPGRADING.md` before every upgrade. It records the changes
  that need something beyond running the migrations.
- Migrations run as a Helm hook before the new pods start. If you
  disable the hook, run `supermcp migrate` yourself before rolling.
- The schema policy is expand-only across one minor version. Skipping
  several minors is not tested.
- Watch your own CVE feeds for the base image, Postgres and Redis. The
  release pipeline signs images and produces an SBOM; acting on what the
  SBOM says is yours.

### Access to the system itself

- Who holds the `owner` and `admin` roles, and reviewing that.
- Turning `SUPERMCP_OPEN_REGISTRATION` off again after the first
  account, if you turned it on to create it.
- Choosing `SUPERMCP_DCR_MODE`. The default, `approval`, means the
  operator must approve each MCP client that registers itself, with
  `supermcp oauth clients approve`. Set
  it to `open` and any client that can reach the instance can register.
- Deciding who may read and export the audit trail (`audit:read`,
  `audit:export`) — an export is a copy of the record leaving the
  instance.
- Second factors. This system issues none. Enterprise sign-in goes
  through an identity provider, which enforces its own factor and
  reports it; the session records that it happened. If you rely on
  password sign-in, there is no second factor at all.

### Data decisions

- The audit payload policy, per workspace. The default keeps no values.
- The audit retention window, per workspace, floor 90 days.
- **Bounding `tool_invocations` yourself.** Nothing deletes it and it
  holds full tool arguments. See `retention.md`.
- Which connectors exist at all, and therefore which vendors receive
  your data. Every credential an administrator installs is a decision
  to send tool arguments to that vendor.
- Whether to configure an audit webhook exporter, and to what. Note that
  there is no API for this: exporter rows can only be created by writing
  to the database directly.

### Monitoring and response

- Scrape `/metrics` and deliver the alerts. The chart ships six rules;
  routing them to someone is yours.
- Run `supermcp audit verify` on a schedule and after every restore. A
  broken chain means either a bug or someone editing the database
  directly, and both deserve the same attention.
- Run `supermcp keys verify` after any change to key configuration.
- Watch the audit-writer queue depth. A full queue drops events, which
  is a gap in the record; the default behaviour is to drop and record
  the gap, and `SUPERMCP_AUDIT_ON_UNAVAILABLE=block` changes it to make
  callers wait instead.
- There is no incident-response runbook in this repository beyond the
  troubleshooting section of `docs/operations.md`.

## What neither side has

Stated so that nobody assumes otherwise:

- No dry-run preview of a rendered request.
- No TOTP, WebAuthn or recovery codes.
- No distributed tracing.
- No customer-managed key per workspace: the master key is per
  instance.
- No physical separation between workspaces. Isolation is row-level
  security plus a data key per workspace. A customer requiring physical
  separation needs its own instance and database, which is the same
  binary.
- No air-gapped installation bundle.
- No `soap` or `mcp` upstream engines, and no `oauth1`, `wsSecurity` or
  `mtls` upstream authentication, although the adapter schema accepts
  all of them.
