# The API

This describes the shape of the interface rather than listing every
endpoint. The exhaustive list is generated from the code and served by
the running instance:

```
GET /api/openapi.json     OpenAPI 3.1
GET /api/openapi.yaml     the same document as YAML
GET /api/openapi-3.0.json OpenAPI 3.0, for tools that cannot read 3.1
```

The same document can be produced without a database, which is what CI
uses to generate the TypeScript client:

```bash
supermcp openapi -format json > openapi.json
```

An interactive documentation page is served at `/api/docs`, but only
when `SUPERMCP_DEV` is set.

## Four surfaces

| Surface | Path | Shape | Described by |
|---|---|---|---|
| Admin API | `/api/v1/...` | JSON over HTTP, generated OpenAPI | `/api/openapi.json` |
| MCP endpoint | `/mcp/{server}` | JSON-RPC 2.0 over Streamable HTTP | the MCP specification |
| OAuth 2.1 authorisation server | `/oauth/...`, `/.well-known/...` | RFC 6749, 7591, 7009, 7662, 8414, 9728 | its own metadata documents |
| SCIM 2.0 | `/scim/v2/...` | RFC 7644 | `/scim/v2/ServiceProviderConfig` |

Only the admin API is in the OpenAPI document. The other three speak
their own media types and error shapes and are described by their own
specifications, which is why they are mounted beside the API rather than
inside it.

Two things are missing from the generated document and are documented
here instead: `GET /api/v1/blobs/{id}` (registered only when a blob
store is wired, which the document generator does not do) and every
route outside `/api/v1`.

## Authentication

Three kinds of credential reach the same place: a `Principal` carrying
an identity, a workspace, an authentication method, optionally a bound
MCP server, and optionally a set of scopes. Everything downstream —
the permission evaluator, the tenant isolation, the audit record —
reads that one structure and does not care which credential produced it.

Authentication never rejects a request on its own. It resolves a
principal when it can, and handlers decide what anonymous access means.
A credential that fails to verify is treated as no credential at all.

### A person: the session cookie

```
POST /api/v1/auth/login
Content-Type: application/json

{"email":"admin@example.com","password":"..."}
```

The response sets an `HttpOnly`, `SameSite=Lax` cookie named
`__Host-sm_sess` when the public URL is `https`, and `sm_sess` when it
is not — browsers reject a `__Host-` cookie over plain HTTP, which is
the case on a loopback development instance. No token is ever put in
browser storage.

Sessions are server-side rows. They expire 12 hours after the last
request and 30 days after they were created, whichever comes first. The
idle timer is refreshed at most once a minute. A session can be revoked
by its owner (`DELETE /api/v1/auth/sessions/{id}`), by a password
change (which ends every other session), or by SCIM deactivating the
account.

Failed sign-ins are counted against both the email address and the
client address, with an exponentially growing lock after ten failures
per address and a hundred per IP, capped at 24 hours. A sign-in for an
address that does not exist takes the same time as one that does.

`GET /api/v1/auth/session` describes the current session: the user, the
active workspace, every workspace they belong to, and the permissions
they hold in the active one. A signed-out caller gets
`{"anonymous": true}`. `POST /api/v1/auth/switch-org` changes the
active workspace after re-checking membership.

Cookie-authenticated mutations are checked against `Sec-Fetch-Site` and
`Origin`. Requests carrying an API key are exempt, because they carry no
ambient credential a browser could attach on someone else's behalf.

### A program: an API key

```
X-API-Key: smk_<12-character prefix><43-character secret>
```

or, equivalently:

```
Authorization: Bearer smk_...
```

A key is `smk_` followed by a 12-character prefix and a 43-character
secret. Only the SHA-256 of the whole string is stored; the prefix is
indexed so a presented key can be found without a table scan, and the
comparison is constant time. The secret is shown once, when the key is
created, and cannot be recovered.

| Property | Behaviour |
|---|---|
| Expiry | 90 days by default. `ttlDays` on creation overrides it; a negative TTL means never. |
| Server binding | `serverId` on creation binds the key to one MCP server. A bound key is refused at any other server. |
| Scopes | Default `mcp:tools:read mcp:tools:invoke`. See below. |
| Ownership | A key acts as the user or service account that owns it, and inherits that principal's role bindings. It never has more access than its owner. |
| Last use | Recorded at most once every five minutes per key, with the client address. |
| Rotation | `Rotate` issues a replacement and gives the old key a grace period (24 hours by default) rather than revoking it immediately. |
| Revocation | Immediate. A revoked key is indistinguishable from an unknown one. |

### A program: an OAuth access token

```
Authorization: Bearer eyJ...
```

Access tokens are ES256 JWTs signed by a key held in `signing_keys`,
whose private half is sealed with the instance data key. The public keys
are published at `/.well-known/jwks.json`, so a resource server — or a
customer's own verifier — can check a token without sharing a secret.

Claims: `iss` (the public URL), `sub` (`user_<id>` or `svc_<id>`),
`aud` (`<public URL>/mcp` or `<public URL>/mcp/<server id>`), `org`,
`client_id`, `scope`, `jti`, `iat`, `exp`, and `mcp_server` when the
token is bound to one. Access tokens live one hour. Refresh tokens live
30 days, rotate on every use, and are hashed at rest.

Presenting a rotated refresh token a second time revokes every token in
its family. That is the only reliable signal that a token was stolen,
and the response says so.

### A program: a service account

A service account is a non-human principal in one workspace. It takes
the same role bindings as a person, so nothing downstream needs to know
which it is.

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=<service account client id>
&client_secret=<secret>
&resource=https://mcp.example.com/mcp/<server id>
```

There is no refresh token: the account re-authenticates with the secret
it holds anyway. The `resource` parameter names the server the token is
for. An account bound to one server may not ask for another, and asking
for a resource that does not name an MCP server on this instance is
`invalid_target`. Requested scopes are narrowed to what the account is
allowed to hold.

A service account can also be given an API key instead, in which case it
authenticates exactly like the key above.

### Scopes and permissions are two different things

**Permissions** are what a principal may do, and come from role
bindings. The set is closed; a role naming anything outside it fails
validation.

```
org:read org:update org:delete org:members:manage org:settings:manage
org:billing:manage
connectors:read connectors:create connectors:update connectors:delete
connectors:auth:update connectors:test
tools:read tools:update tools:invoke tools:invoke:destructive
servers:read servers:create servers:update servers:delete
roles:read roles:manage
apikeys:self:manage apikeys:org:manage serviceaccounts:manage
idp:manage scim:manage
audit:read audit:export audit:policy:manage
approvals:request approvals:decide
dlp:manage revisions:rollback secrets:rotate
```

`GET /api/v1/permissions` describes them. Seven built-in roles exist —
`owner`, `admin`, `editor`, `viewer`, `approver`, `auditor` and
`mcp-consumer`. `owner` holds the wildcard.

**Scopes** are a ceiling on a credential, not a grant. They appear on
API keys and OAuth tokens. A credential carrying scopes can do strictly
less than its owner, never more:

| Scope | Permits |
|---|---|
| `mcp:tools:read` | `tools:read` only. |
| `mcp:tools:invoke` | `tools:invoke`, `tools:invoke:destructive`, and `tools:read`. |
| `scim:write` | `scim:manage` only: the SCIM endpoints. |
| `mcp:org` | Removes the ceiling: the credential can do whatever its owner's roles allow. |

Any permission other than `tools:read`, `tools:invoke` and `scim:manage`
is refused outright for a scoped credential that does not hold `mcp:org`.
A SCIM provisioning key holds `scim:write`, and its owner needs a
`scim:manage` role binding; the key can provision and do nothing else.

### How a decision is made

Every check is `Evaluate(principal, permission, resource)` and fails
closed. In order:

1. An anonymous principal is denied.
2. The resource's workspace must be the principal's workspace.
3. A server-bound credential must match the server named in the
   resource.
4. A scoped credential must carry the matching scope, per the table
   above.
5. Role bindings are loaded for the principal (cached 30 seconds).
   Expired bindings are skipped. A binding applies when its scope
   contains the resource: `org` always, `server`, `connector` or `tool`
   only on an exact match.
6. **No binding is a denial.** There is no implicit access.
7. An explicit `deny` rule on the tool, for any role the principal
   holds, wins over everything.
8. Some role the principal holds must grant the permission, or hold the
   wildcard.
9. If any `allow` rule exists for that tool, the principal must hold one
   of those roles. A tool with allow rules is a whitelist.
10. A tool annotated as destructive additionally requires
    `tools:invoke:destructive`.

Denials are recorded in the audit trail, except for read-only
permissions: someone browsing a screen they cannot see produces one per
page load, and drowning the record is its own kind of failure.

## The MCP endpoint

```
POST /mcp/{server}
```

`{server}` is an MCP server's id or its slug. The transport is
Streamable HTTP in **stateless** mode: every request carries everything
needed to serve it and no session is held between requests. There is
therefore no stream to resume, and a `GET` is answered `405` with
`Allow: POST, DELETE` immediately, rather than hanging a client that
probes with one.

Responses are server-sent events by default, or `application/json` when
`SUPERMCP_MCP_RESPONSE_MODE=json`. Request bodies are capped at 4 MiB.
A client that disconnects cancels the upstream call it caused.

### What happens on each request

The tool surface is computed per request, because it depends on who is
calling.

1. Authenticate. No principal is `401`, carrying
   `WWW-Authenticate: Bearer realm="supermcp", resource_metadata="<public URL>/.well-known/oauth-protected-resource/mcp/<server>"`.
   That is what a compliant client follows to learn how to obtain a
   token for this exact server.
2. Resolve the server by id, then by slug. Unknown is `404`; disabled is
   `403`.
3. The caller's workspace must be the server's workspace, and a
   server-bound credential must match this server. Otherwise `403`.
4. Collect the server's connectors' enabled tools, evaluate `tools:read`
   for the caller on each, and drop the ones that are refused.
   Duplicate names are dropped after the first.
5. Build the MCP server from what is left, with the composed
   instructions of its connectors.

Every failure here is a refusal, not an empty surface. Misconfiguration
cannot silently widen access, and it cannot silently produce a server
with no tools that looks like a working one.

### tools/list

Returns the surface from step 4. Each tool carries its name,
description, input schema and annotations, exactly as the adapter
declared them. Annotations the adapter did not set are derived from the
transport and from whether the connector is read-only.

### tools/call

The name is re-checked against the surface before anything else. A name
outside it is refused with JSON-RPC code `-32600` and the message "tool
not available" — deliberately ambiguous, because a client must not
learn whether a tool exists in a workspace it cannot see.

`tools:invoke` is then evaluated again for this principal on this tool,
with the destructive flag from the tool's annotations. A refusal is
returned as an error *result* rather than a protocol error, so the model
sees a sentence it can act on: "This tool is not available to you. It
may belong to another workspace, or your role may not allow it."

Then the call runs: resolve the connector and open its credentials,
render the templates, apply upstream authentication, execute through the
transport's engine, apply the response transform, convert the result to
MCP content, and record it.

### What comes back

| Upstream result | MCP result |
|---|---|
| JSON or rows | Text content with the transformed body rendered as indented JSON. When the tool declares an `output` schema, also structured content. |
| An image or audio media type | Image or audio content. |
| Other binary, up to 8 MiB | An embedded resource. |
| Other binary, above that | A resource link to `GET /api/v1/blobs/{id}`. |
| An HTTP error status from the upstream | `isError: true` and text beginning "Upstream returned HTTP N", truncated to 4000 characters. |
| A failure on our side | `isError: true` and a sentence naming the class of problem. |

A blob link is readable by exactly the principal whose call produced it,
and by nobody else — not another member of the same workspace, not an
administrator. Anyone else gets `404` rather than `403`, because "this
identifier exists but is not yours" is a fact about someone else's tool
call. Blobs expire after 15 minutes. They are held in Redis when it is
configured and in Postgres (`tool_blobs`) otherwise, or when Redis fails,
so any replica answers a link; expired rows are swept every five
minutes.

A tool whose adapter declares `response.cache` has successful read-only
results remembered for that long, clamped to 24 hours. The cache key
covers the workspace, the connector and its version, the tool and its
version, and the arguments. It narrows to the individual caller whenever
the connector or the tool mentions the `caller` or `req` namespaces
anywhere, so a tool that sends the caller's identity upstream never
serves one person's answer to another. Every error path in the cache
resolves to a miss.

## Errors

### The admin API

RFC 7807, served as `application/problem+json`:

```json
{
  "title": "Forbidden",
  "status": 403,
  "detail": "permission denied: connectors:create (no binding)",
  "errors": [
    {"message": "expected string", "location": "body.name", "value": 5}
  ]
}
```

`errors` appears on validation failures and names the location in the
request. `detail` on a permission failure names the permission and the
reason the evaluator gave. A `500` hides its detail from the client; the
router logs it with the request id.

| Status | Means |
|---|---|
| 400 | The request is malformed, or a value violates a policy (a weak password, a reused password, an unknown scope). |
| 401 | No credential, or one that did not verify. |
| 403 | Authenticated, but the permission is not held — or no workspace is selected, or the account is disabled, or registration is closed. |
| 404 | No such object *in your workspace*. Objects in other workspaces are not distinguishable from objects that do not exist. |
| 409 | A role binding that already exists, or removing the last owner of a workspace. |
| 429 | Over a rate-limit budget, locked out after failed sign-ins, or the limiter could not be evaluated. |
| 503 | The database is unreachable or the schema is behind the binary (`/readyz`), or a subsystem the endpoint needs is not configured. |

### The MCP endpoint

Refusals before the JSON-RPC layer are an HTTP status *and* a JSON-RPC
error object, so a client sees something it can parse either way:

```json
{"jsonrpc":"2.0","error":{"code":-32001,"message":"access denied"},"id":null}
```

`-32001` for 401, 403 and 404; `-32600` for a call to a name outside the
surface; `-32603` for anything else.

### The OAuth endpoints

RFC 6749 error bodies with `Cache-Control: no-store`:

```json
{"error":"invalid_grant","error_description":"this authorization code was already used"}
```

`/oauth/revoke` always reports success, even for a token that never
existed: saying otherwise leaks which tokens are real.

### Rate limiting

Every limited response carries the draft `RateLimit-Limit`,
`RateLimit-Remaining` and `RateLimit-Reset` headers, and a refusal also
carries `Retry-After`. Budgets are charged against the authenticated
principal where there is one, and against the client address otherwise,
so an office behind one NAT is not a single bucket.

A budget that cannot be evaluated — an unreachable Redis where the
in-memory fallback also failed — is answered `429`, not allowed
through. Failing open would make an unreachable limiter the cheapest way
to turn every budget off.

## Discovery

A client or an integrator needs these and nothing else.

| What | Where | Needs a credential |
|---|---|---|
| Is the process up | `GET /healthz` | no |
| Is it ready to serve | `GET /readyz` | no |
| Build version | `GET /api/v1/version` | no |
| The admin API | `GET /api/openapi.json` | no |
| The adapter catalogue | `GET /api/v1/catalog` (ETag on the catalogue hash), `/{slug}`, `/{slug}/adapter.yaml` | no |
| The adapter JSON Schema | `GET /schema/adapter/v2.json` | no |
| Authorisation server metadata | `GET /.well-known/oauth-authorization-server` (and `/.well-known/openid-configuration`) | no |
| Signing keys | `GET /.well-known/jwks.json` | no |
| Protected resource metadata | `GET /.well-known/oauth-protected-resource/mcp/{server}` | no |
| SCIM capabilities | `GET /scim/v2/ServiceProviderConfig` | yes |
| Who am I and what may I do | `GET /api/v1/auth/session` | yes |
| What every permission means | `GET /api/v1/permissions` | yes |

The OpenAPI document is currently served without authentication. It
describes the shape of the API, not any instance's data.

The authorisation server metadata advertises `authorization_code`,
`refresh_token` and `client_credentials`; `S256` as the only PKCE
method; `none`, `client_secret_basic` and `client_secret_post` as client
authentication methods; and `mcp:tools:read`, `mcp:tools:invoke` and
`offline_access` as scopes.

## Connecting an MCP client

The sequence a compliant client follows, with nothing configured but the
endpoint address:

1. `POST /mcp/<server>` with no credential → `401` with
   `WWW-Authenticate` naming the protected-resource metadata.
2. `GET` that metadata → it names this instance as the authorisation
   server.
3. `GET /.well-known/oauth-authorization-server` → endpoints and
   capabilities.
4. `POST /oauth/register` if the client has no `client_id`. With
   `SUPERMCP_DCR_MODE=approval` (the default) the registration is
   recorded as `pending`, and an authorisation attempt is refused with
   `unauthorized_client` until the instance operator approves it with
   `supermcp oauth clients approve <client_id>`. A rejected client is
   refused at the token endpoint as well, and its refresh tokens are
   revoked. With `closed` the registration itself is refused.
5. `GET /oauth/authorize?...&code_challenge=...&code_challenge_method=S256&resource=<public URL>/mcp/<server>`.
   PKCE with `S256` is mandatory. A signed-out person is sent to
   `/login` and returned to the same request. The consent page then
   shows which client is asking, what the scopes permit in plain words,
   and — if the client did not name a server through `resource` — which
   MCP server to grant.
6. `POST /oauth/token` with the code and the verifier. The code is
   single-use under a row lock, so two concurrent redemptions cannot
   both succeed, and it is spent even when the verifier fails.
7. `POST /mcp/<server>` with the access token.

Redirect URIs are matched exactly against the registered list. `https`
anywhere, `http` only on `127.0.0.1` or `[::1]`, a private-use scheme
containing a dot for native apps; no wildcards and no fragments. An
unregistered URI is never redirected to.

A client that cannot do any of this uses an API key bound to the server,
sent as `Authorization: Bearer smk_...`.

## SCIM

Mounted at `/scim/v2` with the usual `Users` and `Groups` resources and
`GET`, `POST`, `PUT`, `PATCH`, `DELETE` on each, plus
`ServiceProviderConfig`, `ResourceTypes` and `Schemas`.

Authentication is an ordinary credential — in practice an API key held
by the identity provider — and every route requires the `scim:manage`
permission. As noted above, the key must also carry the `mcp:org` scope,
or the scope ceiling refuses it.

Setting a user `active: false`, through `PUT` or through a `PATCH` on
the `active` attribute, revokes that person's sessions, API keys and
refresh tokens in that workspace and marks the membership deactivated. A
deactivated account stops working immediately rather than at the next
token expiry.

SCIM does not assign roles. Group membership from an identity provider
maps to roles through single sign-on instead: bind a role to a principal
of kind `idp_group` whose id is the group name, and every sign-in
through that provider reconciles the person's provider-sourced bindings
to match their groups. Bindings an administrator made by hand are left
alone — the provider owns what it granted and nothing else.

## Versioning

The admin API is at `/api/v1`. The schema policy is expand-only across
one minor version: `scripts/check-migrations.sh` blocks a `DROP`,
`RENAME` or `NOT NULL` without an explicit marker and a section in
`docs/UPGRADING.md`.
