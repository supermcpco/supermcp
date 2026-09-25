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

### Recent sign-in

A session cookie lives for up to 30 days. The operations that create
credentials, decide who may do what, or change how the workspace is
secured also require the session to have signed in, or confirmed who is
using it, within the last five minutes (`SUPERMCP_AUTH_FRESH_WINDOW`).
The permission is checked first. A session that holds the permission but
is older than the window gets:

```json
{
  "title": "Forbidden",
  "status": 403,
  "detail": "reauth_required: sign in again to continue: this action needs a sign-in from the last 5 minutes",
  "errors": [{"location": "session", "message": "…", "value": "reauth_required"}]
}
```

The session itself stays valid for everything else.
`GET /api/v1/auth/session` returns `signIn`:
- `method`: `password`, `sso` or `saml`
- `canReauth`
- `authenticatedAt` and `freshUntil`
- `reauthUrl`, for single sign-on

The session becomes fresh again in one of two ways:

- **A password session** sends `POST /api/v1/auth/reauth` with
  `{"password": "…"}`. The session keeps its cookie and its id, and its
  authentication time becomes now. A wrong password is a `400` and counts
  toward the same lockout as a failed sign-in.
- **A single sign-on session** signs in through its provider again.
  Send the browser to `signIn.reauthUrl` with `&next=<path>` appended.
  The provider is asked to authenticate the person again: `prompt=login`
  and `max_age=0` for OpenID Connect, `ForceAuthn` for SAML. The answer
  is accepted only when all of these hold:
  - the provider's own authentication time is within the window
    (`auth_time` from the verified ID token, or `AuthnInstant`)
  - the person, workspace and provider match the session being replaced

  If so, a new session opens with that time and the old one ends.
  Otherwise nothing changes, and the browser lands on
  `/reauth?error=<reason>&next=<path>`. The reason is
  `reauth_not_recent`, `reauth_unconfirmed` or `reauth_mismatch`.

  A provider that never gives a time (GitHub, plain OAuth2) has
  `canReauth: false` and no `reauthUrl`. Its sessions cannot be made
  fresh, because a sign-in through it says nothing about when the person
  authenticated. For the same reason, a sign-in through it opens a
  session that is never fresh.

Setting a password from a single sign-on session is also subject to the
window. A password session instead proves itself with the current
password.

The OAuth consent page is served by the server, not the interface. A
stale session that reaches `GET /oauth/authorize` is redirected to
`/reauth?next=<the authorize URL>` and comes back once it confirms. A
consent form submitted with `allow` after the window has passed is
refused with `403`, and the person starts again from the client.

API keys, OAuth access tokens and service accounts
(`client_credentials`) are the only credentials not subject to the
window. No person signs them in who could be asked to sign in again.
They are named explicitly; any other kind of credential is held to the
window. Their scopes and the principal's permissions are all that apply.

The guarded operations:

| Area | Operations |
|---|---|
| API keys | `POST /api/v1/api-keys`, `POST /api/v1/api-keys/{id}/rotate`, `DELETE /api/v1/api-keys/{id}` (a SCIM token is an API key) |
| Service accounts | `POST /api/v1/service-accounts`, `POST …/{id}/rotate`, `POST …/{id}/disabled`, `DELETE …/{id}` |
| Connector credentials | `PUT /api/v1/connectors/{id}/credentials`, `POST /api/v1/connectors/{id}/oauth/authorize` |
| What server-bound keys reach | `POST /api/v1/servers`, `PATCH /api/v1/servers/{id}` when it sets `connectorIds` or `enabled: true` (not a rename, new instructions or turning it off), `POST /api/v1/servers/{id}/revisions/{revision}/restore`, `POST /api/v1/connectors/{id}/revisions/{revision}/restore` |
| OAuth clients | `GET /oauth/authorize` (redirects to `/reauth`), `POST /oauth/consent` with `decision=allow` |
| Approvals | `POST /api/v1/approvals/{id}/approve` (not reject or cancel) |
| Roles | `POST /api/v1/roles`, `PATCH /api/v1/roles/{id}`, `DELETE /api/v1/roles/{id}`, `POST /api/v1/roles/{id}/revisions/{revision}/restore` |
| Role holders | `POST /api/v1/roles/{id}/bindings`, `DELETE /api/v1/roles/{id}/bindings/{bindingId}`, `PATCH /api/v1/org/members/{userId}`, `DELETE /api/v1/org/members/{userId}`, `POST /api/v1/org/invites` |
| Single sign-on | `POST /api/v1/idps`, `PUT` and `DELETE /api/v1/idps/{id}`, `POST /api/v1/idps/{id}/revisions/{revision}/restore`, `POST /api/v1/saml-providers`, `PUT` and `DELETE /api/v1/saml-providers/{id}`, `POST /api/v1/saml-providers/{id}/rotate-key`, `POST /api/v1/saml-providers/{id}/revisions/{revision}/restore` |
| Security settings | `PUT /api/v1/org/password-policy`, `POST /api/v1/auth/password` from a single sign-on session |
| Data-loss and approval rules | `POST /api/v1/dlp/policies`, `PUT` and `DELETE /api/v1/dlp/policies/{id}`, `POST /api/v1/dlp/policies/{id}/revisions/{revision}/restore`, `POST /api/v1/dlp/detectors`, `PATCH` and `DELETE /api/v1/dlp/detectors/{id}`, `POST /api/v1/dlp/detectors/{id}/revisions/{revision}/restore`, `POST /api/v1/approval-policies`, `PUT` and `DELETE /api/v1/approval-policies/{id}`, `POST /api/v1/approval-policies/{id}/revisions/{revision}/restore` |
| Audit trail | `PUT /api/v1/audit/policy`, `PUT /api/v1/audit/retention`, `POST` and `DELETE /api/v1/audit/legal-hold`, `POST /api/v1/audit/exporters`, `DELETE /api/v1/audit/exporters/{id}` |

The master key and data keys have no HTTP endpoints. Rotating them is a
command (`supermcp keys`) run by the operator.

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
| Rotation | `POST /api/v1/api-keys/{id}/rotate` issues a replacement and gives the old key a grace period (24 hours by default, at most 7 days) rather than revoking it immediately. See below. |
| Revocation | Immediate. A revoked key is indistinguishable from an unknown one. |

#### Rotating a key

```
POST /api/v1/api-keys/{id}/rotate
{"graceSeconds": 3600}
```

`graceSeconds` is how long the old key keeps working: 0 stops it at
once, the maximum is 604800 (7 days), and leaving it out means 86400
(24 hours). The grace only ever brings the old key's expiry forward; a
key due to expire sooner keeps its earlier date.

The replacement has the old key's name, owner, scopes and server
binding, and the default 90-day expiry. The reply has the same shape as
creating a key, with the old key's id and its new expiry added. The
secret is shown this once:

```json
{
  "key": {"id": "…", "name": "…", "prefix": "…", "scopes": ["…"], "expiresAt": "…", "createdAt": "…"},
  "secret": "smk_…",
  "previousKeyId": "…",
  "previousExpiresAt": "2026-09-25T13:00:00Z"
}
```

Shortening the old key and creating the new one happen in one
transaction: if either fails, nothing changes. The permissions are the
same as for revoking: `apikeys:self:manage` rotates your own keys,
`apikeys:org:manage` any key in the workspace.

| Status | When |
|---|---|
| 404 | No such key, or it is not yours and you lack `apikeys:org:manage`. |
| 409 | The key is revoked, has expired, or has already been rotated (rotate its replacement instead). Of two rotations of the same key at once, one gets this. |
| 422 | `graceSeconds` is negative or over 604800. |

Each rotation is recorded as `apikey.rotate` against the old key, naming
the replacement's id, prefix, scopes and expiry, the old key's new
expiry, and the grace. Neither secret is in the event.

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

A token from the authorization code grant also says which sign-in it
came from:

- `sid`: the public id of the browser session that consented, the id
  the sessions list (`GET /api/v1/auth/sessions`) shows. It is random,
  not the server's own key for the session, so it grants nothing.
  Tokens from a refresh keep it; after a re-authentication (below) they
  name the new session.
- `amr`: how that session signed in, as RFC 8176 values. `pwd` for a
  password sign-in. For a single sign-on session, the registered RFC
  8176 values the provider reported, in its order: the ID token's `amr`
  for OpenID Connect, the method the authentication context class names
  for SAML (`pwd`, `sc` or `otp`). A provider's own values, such as
  Entra ID's `rsa`, are left out. `mfa` is added last when the session
  has a second factor on record: an OpenID Connect sign-in whose ID
  token met the provider's second-factor rule (see "Single sign-on
  providers"), or a SAML sign-in whose assertion names one. A provider
  that reports `mfa` without meeting the rule does not get it repeated.
  So `["pwd", "mfa"]` from an OpenID Connect provider with the default
  rule gives `["pwd", "mfa"]`, and `["pwd"]` gives `["pwd"]`. When
  nothing is known, `amr` is left out.
  Only `mfa` is our judgement. Every other value repeats what the
  provider said, as it said it; we check none of them.
  The value is fixed at consent and kept through refreshes. A
  re-authentication through a provider moves the client's refresh
  tokens to the new session and gives them that session's `amr`, so the
  next refresh describes the latest sign-in: if it had no second factor,
  tokens from then on do not say `mfa`, even though the consent came
  from a sign-in that had one. Access tokens issued before it name the
  replaced session and are refused.

A `client_credentials` token has no session and carries neither.

`/oauth/introspect` takes an API key (`X-API-Key` or `Authorization:
Bearer smk_...`) and returns `sid` and `amr` when the token has them. The
key must belong to the token's workspace and hold `tools:read` on the
server the token is for. A key scoped to MCP use passes with
`mcp:tools:read` or `mcp:tools:invoke`. For any other key, the answer is
`{"active": false}`, the same as for a token that is invalid.

Ending the session that consented ends what it granted. Signing out,
ending the session from the sessions list, a password change ending
the other sessions, and deactivating the member (from the API or SCIM
`active=false`) revoke the refresh tokens descended from that consent.
Its access tokens are refused at once, by the MCP endpoint and by
introspection, not when they expire. A re-authentication through a
single sign-on provider replaces the session: the refresh tokens move to
the new one, the old session's access tokens are refused, and a refresh
yields tokens naming the new session. A session that expires ends
nothing, since a refresh token is meant to outlive it; it stays on record
while a live refresh token names it, and a token whose session is not on
record is refused. A refresh that races the end of its session never
yields a usable token. Tokens issued before this release name no session
and end only with the client or the member.

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
5. Role bindings are loaded for the principal (cached per replica for
   up to 30 seconds, and dropped on every replica as soon as a role,
   binding or tool access rule in the workspace changes; see
   "Cache invalidation" in the operations guide).
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
Streamable HTTP, in the mode the server's `sessions` setting names (see
"Sessions" below). By default it is **stateless**: every request carries
everything needed to serve it and no session is held between requests.
In neither mode does the server offer a stream of its own, so a `GET` is
answered `405` with `Allow: POST, DELETE` immediately, rather than
hanging a client that probes with one.

Responses are server-sent events by default, or `application/json` when
`SUPERMCP_MCP_RESPONSE_MODE=json`. Request bodies are capped at 4 MiB.
On a stateless server, a client that disconnects cancels the upstream
call it caused.

### Sessions

A server's `sessions` is `stateless` (the default) or `stateful`, set
with `PATCH /api/v1/servers/{id}` or on the server screen. Any other
value is `422`. The change is recorded in the server's revision history
like any other, and a restore of a revision from before the setting
existed puts back `stateless`.

A **stateful** server keeps a session per client, as the Streamable HTTP
transport describes:

- The response to `initialize` carries `Mcp-Session-Id`, and every later
  request has to send it back.
- A request without one that is not an `initialize` is `400`.
- A session id this replica does not hold, or holds for another caller
  or another server, is `404` with
  `{"code":-32001,"message":"Session not found; initialize a new one"}`.
  That is the client's signal to initialise again.
- `DELETE` with the session id ends the session (`204`).
- A caller is one credential: a session opened with one API key or one
  OAuth client is unknown to another key or client of the same person.
- A new `initialize` from a caller, or a workspace, already holding as
  many sessions as it may, all of them busy, is `429`; from anyone when
  the replica is full and no session it may close is idle, `503`. Both
  carry `Retry-After: 1`.

Sessions live on the replica that opened them and are closed when idle
past `SUPERMCP_MCP_SESSION_IDLE`, when older than
`SUPERMCP_MCP_SESSION_MAX_AGE`, or when the replica shuts down; with
more than one replica, a client has to keep reaching the same one
(docs/operations.md, "Stateful MCP sessions"). A session does not carry
permissions: each request is authenticated and its surface worked out as
on a stateless server; `tools/list` on the session shows only what that
request may see, a call runs the tool as it is at that moment, and the
call is cancelled when its request ends.

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
description, input schema and annotations, exactly as its stored
definition declares them. Annotations the definition does not set are
derived from the transport and from whether the connector is read-only.

### tools/call

The name is re-checked against the surface before anything else. A name
outside it is refused with JSON-RPC code `-32600` and the message "tool
not available" — deliberately ambiguous, because a client must not
learn whether a tool exists in a workspace it cannot see. The two
tools for following up a held call are the exception, callable on every
server whether it lists them or not (see "Following up a held call").

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

### Calls held for approval

A call an approval policy reaches does not run. It comes back at once as
an error result whose text tells the model what happened and whose
structured content names the request:

```json
{"status":"approval_pending","approvalRequestId":"…","state":"pending","tool":"refund_payment",
 "policy":"Refunds","expiresAt":"…","retryWith":"_approval"}
```

Once someone else has approved it, the same tool called with
`"_approval": "<request id>"` runs the arguments that were approved, once.

On a **stateful** server (see "Sessions") whose client declared the
`elicitation` capability at `initialize`, the server first asks the
person behind the client about the call with `elicitation/create`, on the
stream of the call itself. The question names the tool and the request,
never the arguments or anything secret, and offers a form with a
`confirm` checkbox and an optional `note` of up to 500 characters:

- **accept with `confirm: true`** records the confirmation and the note
  on the request, as `acknowledgedAt` and `acknowledgement`, for the
  approver to read (`GET /api/v1/approvals/{id}` and the approvals
  screen, which show them). It approves nothing: the request stays
  pending, the person who asked still may not decide it, and the result
  says so and carries `"acknowledged": true`. A request is asked about
  once; the same call repeated is not asked again.
- **decline** withdraws the request, as `POST /api/v1/approvals/{id}/cancel`
  would, unless a confirmation reached it first; recorded on the audit
  trail as `approval.cancel` with `meta.via` `elicitation`. The result
  says it was withdrawn.
- **cancel** (the question dismissed), **accept without `confirm`**, or
  **no answer** within `SUPERMCP_MCP_ELICITATION_TIMEOUT` (45 s by
  default, ending at the latest five seconds before the request's own
  deadline), or before the replica starts shutting down, is no answer:
  the request stays pending and the result is exactly what it would have
  been without the question.

The note, like the reason given when a request is withdrawn, is the
requester's own text. It is stored with control and format characters
removed (bidirectional overrides, zero-width characters), line breaks
turned into spaces, and anything the built-in data-loss detectors
recognise masked, and the approvals screen shows it apart from its own
text, labelled as the requester's unverified words.

On a stateless server, with a client that did not declare the
capability, or when the endpoint answers with `application/json`
(`SUPERMCP_MCP_RESPONSE_MODE=json`, where the transport has no stream to
carry the question on), nothing is asked and a held call behaves as
described at the top of this section.

### Following up a held call

Every server has two tools of the instance's own, on both session modes:

| Tool | Input | What it does |
|---|---|---|
| `supermcp_approval_status` | `requestId` | Reads the request: `state`, `tool`, `decidedBy` and `decidedAt` once someone has answered, `reason`, `expiresAt`, and `acknowledgedAt` if the caller confirmed it from their client. Changes nothing. |
| `supermcp_approval_cancel` | `requestId`, optional `reason` (up to 2000 characters) | Withdraws the request if it is still pending, as `POST /api/v1/approvals/{id}/cancel` does, and answers with the same fields. A request already answered, lapsed or withdrawn is an error result that says what became of it. |

Both act only on requests the caller raised, and only while the caller
may still invoke the tool the request is for (`tools:invoke` on that
tool, which is what raising it needed; unlike the API routes they do not
need `approvals:request`, so an OAuth client holding only
`mcp:tools:invoke` can use them). Any other request id, whether it
exists or not, is an error result saying there is no such request among
the caller's calls. A withdrawal is on the audit trail as the API's is,
`approval.cancel` with the change and `meta.via` `mcp`, and a refused one
as a failure; reading the status is not recorded, as reading your own
requests over the API is not.

A server lists the two in `tools/list` only when an enabled rule that
asks for a person could reach it (one for the whole organisation, the
server, or one of its connectors or tools), so that a server where no
call is ever held does not show the model two tools it has no use for.
The listing follows a change of rules within 30 seconds, as the rest of
the tool list does. Listed or not, they can always be called: the
hidden-tool check lets them through. On a server that lists them, a
held call's result ends with a sentence naming them. An adapter tool
with either name is shadowed by them.

## Managing tools

A connector's tools can be added, edited and deleted through the admin
API, one at a time.

| Operation | Route | Permission |
|---|---|---|
| `connectors-tools` | `GET /api/v1/connectors/{id}/tools` | `tools:read` |
| `tools-get` | `GET /api/v1/tools/{id}` | `tools:read` |
| `tools-references` | `GET /api/v1/tools/{id}/references` | `tools:read` |
| `tools-create` | `POST /api/v1/connectors/{id}/tools` | `tools:update` and `connectors:update` |
| `tools-update` | `PUT /api/v1/tools/{id}` | `tools:update`, and see below |
| `tools-enable` | `PATCH /api/v1/tools/{id}` | `tools:update` |
| `tools-delete` | `DELETE /api/v1/tools/{id}` | `tools:update` and `connectors:update` |
| `tools-draft-dry-run` | `POST /api/v1/connectors/{id}/tools/dry-run` | `tools:update` and `tools:invoke` |
| `tools-revisions-restore` | `POST /api/v1/tools/{id}/revisions/{revision}/restore` | `revisions:rollback`, and see below |

Every tool route finds the tool's connector before it checks a
permission, so a binding scoped to the connector covers its tools. A
caller without access to a tool gets the same `403` whether or not the
tool exists.

### The definition

A tool's definition travels as a JSON string in `definition`, not as an
object. It is the same document as one entry of an adapter's `tools`
list (see `docs/adapters.md`), and its `name` is the tool's name.
`tools-get` returns it with the rest of the tool: `source`, `edited`,
`editedAt`, `editedBy` and `editedByName`, `version`, the connector's
`transport`, the `annotations` clients are served, and
`inferredAnnotations`, which are what the operation alone implies before
the definition's own hints are applied.

`source` is `catalog` for a tool installed from the catalogue, `import`
for one that came with an imported specification or a hand-made
connector, and `custom` for one created through `tools-create`. `edited`
is true once someone has changed the definition by hand.

`connectors-tools` returns the same fields as a list, without the
definition. `tools-enable` takes `{"enabled": true|false}`, records a
revision, and moves the version of every MCP server the connector is on,
as every tool write does, so a client's next `tools/list` sees the
change.

### Creating, editing and deleting

`tools-create` answers `201` with `{"tool": ..., "warnings": [...]}`. A
new tool is enabled unless the body says `"enabled": false`.

`tools-update` replaces the whole definition. `expectedVersion` is
required and must be the `version` that was read; without it the answer
is `422`, and with a stale one it is `409`. `enabled` may be left out to
keep the current value. A rename is refused while approval policies
match the tool by its current name, unless the body carries
`"acknowledgeReferences": true`: those policies stop matching once it
goes ahead.

`tools-delete` removes a `custom` tool. A catalogue or imported tool can
only be disabled, because a re-sync or a re-import would bring it back.
A delete is refused while any approval policy refers to the tool, by name
or by scope, unless the query carries `acknowledgeReferences=true`. The
role allow and deny rules and the data-loss policies that name the tool
go with it. `tools-references` lists all three before anyone asks.

Deleting a tool, or an edit that changes what a call does, cancels the
approval requests for it that are still pending or approved and not yet
run. An approval replays by tool, so otherwise a yes given to the old
definition would run the new one.

### Who may change what

Every write needs `tools:update`. On top of that:

- Creating or deleting a tool, and any edit that changes what a call
  does, needs `connectors:update`, because it is the connector's
  credential that the call carries. What a call does is the
  `operation`, `response`, `output`, `timeout`, `rateLimit`, `proxy` and
  the four annotation hints. An edit to the description, the input
  schema, the title or the name alone does not need it.
- A definition that serves a tool as not destructive when its operation
  implies it is — a `DELETE`, say, with `destructiveHint: false` —
  needs `tools:invoke:destructive`, unless the stored definition already
  did the same with the same operation and name. Otherwise an editor
  could turn a destructive tool into one anybody with `tools:invoke` may
  call. The audit event for such a write carries `meta.declassified`.

A catalogue install or an import records no revision for each tool. The
first change to such a tool records what it was before as revision 1, a
`create` with no actor, so the definition the catalogue shipped can
always be put back. A revision restore goes through the same checks as
an edit, and a restore that puts back an earlier name takes
`acknowledgeReferences` as a query parameter. A revision written before definitions were recorded
holds only whether the tool was enabled, so that is all it restores. A
deleted tool cannot be restored from its history.

### Checking a draft

`tools-draft-dry-run` takes an unsaved `definition`, the `toolId` being
edited (left out for a new tool) and the `arguments` a model would send.
It answers `200` with the problems it found in `issues`, the
`annotations` and `inferredAnnotations` the draft would resolve to, and,
when there are no errors, a `preview` of the request it would send. A
preview renders the connector's credentials, which is why it needs
`tools:invoke` as well. Every credential value and every value upstream
authentication prepared is replaced in the preview by
`<redacted:env.NAME>` or `<redacted:auth.NAME>`, wherever it appears:
the URL, any header, the body, the SQL and its arguments. Values shorter
than four characters are left alone. No preview is rendered for SOAP or
MCP-bridge connectors.

### What a definition is checked against

Each finding has a `rule`, a `severity` and, where it is about one part
of the definition, a dotted `field` such as `operation.path`. Errors
stop a save; warnings come back with the saved tool.

| Rule | Severity | Meaning |
|---|---|---|
| `json` | error | The draft is not valid JSON. Draft dry run only; a save answers `422`. |
| `definition-required` | error | No definition was sent. |
| `tool-name-format` | error | The name is not lower-case snake_case. |
| `tool-name-unique` | error | Another tool on this connector has the name. |
| `input-required`, `input-object`, `input-required-unknown`, `schema-subset` | error | As in an adapter. |
| `placeholder-syntax`, `placeholder-unknown`, `placeholder-namespace` | error | As in an adapter. |
| `operation-method`, `operation-kind`, `operation-document`, `operation-statement`, `operation-tool`, `operation-static`, `operation-body-encoding` | error | As in an adapter. |
| `operation-host` | error | On an HTTP or SOAP connector, an `operation.path` that is an absolute URL, or that starts with a placeholder filtered `raw`, points at a host that is neither the base URL's host, a host the connector's other tools already use, nor the host this tool had before. It would send the connector's credential somewhere new. |
| `jmespath-parses` | error | The response transform does not compile. |
| `transform-length` | error | The response transform is longer than 4000 characters. |
| `description-min-60`, `operation-body-get`, `sql-readonly` | warning | As in an adapter. |
| `env-unknown` | warning | An `{{env.X}}` that is not a credential of this connector. It renders empty until one is set. |
| `tool-name-shared-server` | warning | Another connector on the same MCP server has a tool of this name. A server serves the first and drops the rest. |
| `preview-unsupported` | warning | The connector is SOAP or an MCP bridge, which have no preview. |

A save whose definition has errors is `422`, with one entry in `errors`
per error: `location` is `body.definition.<field>`, `message` says what
is wrong, and `value` is the rule. The exception is a definition whose
only error is `tool-name-unique`: nothing is wrong with it except what
else exists, so it is a `409`.

### Conflicts

A tool write that conflicts is `409`, and `errors[].value` carries a
code to match on. The message is written for people and may change.

| Code | Means |
|---|---|
| `version_conflict` | The tool changed since `expectedVersion` was read. Read it again. |
| `name_taken` | Another tool on the connector has the name. |
| `not_deletable` | The tool is not `custom`. Disable it instead. |
| `references_unacknowledged` | Approval policies refer to the tool. The response lists them, one further entry each at `references.approvalPolicies`, with the policy's name as `message` and its id as `value`. A rename lists the policies that match by name; a delete lists all of them. Send `acknowledgeReferences` to go ahead. |

## Connectors and servers: concurrent edits

Connectors and MCP servers carry a `version`, as tools do. These writes
take `expectedVersion` in the body, the `version` that was read:

| Operation | Route |
|---|---|
| `connectors-update` | `PATCH /api/v1/connectors/{id}` (name, instructions, `readOnly`, `enabled`) |
| `connectors-credentials` | `PUT /api/v1/connectors/{id}/credentials` |
| `connectors-revisions-restore` | `POST /api/v1/connectors/{id}/revisions/{revision}/restore` |
| `servers-update` | `PATCH /api/v1/servers/{id}` (name, instructions, `enabled`, `sessions`, `connectorIds`) |
| `servers-revisions-restore` | `POST /api/v1/servers/{id}/revisions/{revision}/restore` |

With a stale one the answer is `409`, with the same body a tool edit
gets: `errors[].value` is `version_conflict` at `body.expectedVersion`,
and a further entry at `version` carries the version stored now as its
`value` (a `tools-update` conflict carries it too). Read the connector
or server again and send the change against that. The version is
compared under the row's lock, in the transaction that writes, so two
writes against the same version cannot both go through.

For this release `expectedVersion` is optional on these routes, and a
write without it is not checked. A later release makes it required, as
it is on `tools-update`; send it now. A restore takes it in an optional
body, `{"expectedVersion": N}`.

A connector's version moves on every change to it, including a change
to one of its tools, its credentials or a catalogue re-sync. The server
raises it too when an upstream rotates the connector's refresh token and
when the connector's OAuth sign-in completes. A server's version moves
when one of its connectors changes, because the version is what the
served tool list is cached under. A write read before any of those is
refused. A write that goes through moves the version by one.
`connectors-resync` checks the same version, through the same lock, but
answers a mismatch with its own code, `resync_stale`.

## Data-loss prevention

A data-loss policy screens what a tool call carries: the arguments on
the way out, the result on the way back, or both. It runs a set of
detectors and either records what they find (`allow`), masks it
(`mask`), or refuses the call (`refuse`). One policy applies per scope
(the organisation, a connector, or a tool), the narrowest winning.

| Route | Needs |
|---|---|
| `GET /api/v1/dlp/policies`, `GET /api/v1/dlp/policies/{id}` | `connectors:read` |
| `POST /api/v1/dlp/policies`, `PUT` and `DELETE /api/v1/dlp/policies/{id}` | `dlp:manage`, recent sign-in |
| `POST /api/v1/dlp/preview` | `dlp:manage`; the `SUPERMCP_RATELIMIT_DLP_TEST` budget |
| `GET /api/v1/dlp/detectors`, `GET /api/v1/dlp/detectors/{id}` | `connectors:read` |
| `POST /api/v1/dlp/detectors`, `PATCH` and `DELETE /api/v1/dlp/detectors/{id}` | `dlp:manage`, recent sign-in |
| `POST /api/v1/dlp/detectors/test` | `dlp:manage`; the `SUPERMCP_RATELIMIT_DLP_TEST` budget |

### Detectors

`GET /api/v1/dlp/detectors` lists the built-in detectors under
`detectors` (name, kind, what each matches and what it deliberately
does not) and the organisation's own under `custom`. The list shows a
custom detector's `pattern` only to holders of `dlp:manage`, and its
samples to nobody: it carries `mustMatchCount` and `mustNotMatchCount`
instead. `GET /api/v1/dlp/detectors/{id}` shows a holder of `dlp:manage`
the samples too, for an editor; anyone else sees neither pattern nor
samples. A policy's
`detectors` names the ones it runs: a built-in by its name
(`payment_card`), a custom detector as `custom:<name>`
(`custom:contract_id`, which is the custom detector's `detector` field).
An empty list runs every built-in and no custom detector; a custom
detector runs only where a policy names it. A policy naming a custom
detector the organisation does not have is `400`. A custom detector that
is switched off is skipped by the policies that name it; a policy whose
only detectors are switched off scans nothing, rather than falling back
to every built-in.

### Custom detectors

A custom detector is a regular expression for an identifier only the
organisation knows: a customer number, a contract id.

| Field | |
|---|---|
| `name` | 2 to 63 characters: lower-case letters, digits, `-` and `_`, starting with a letter or digit. Unique in the organisation. Policies refer to it by name, so it cannot change after the detector is created. |
| `description` | Up to 500 characters. |
| `pattern` | [RE2 syntax](https://github.com/google/re2/wiki/Syntax), as Go's `regexp` reads it. |
| `flags` | `""`, or `"i"` to ignore case. |
| `mustMatch`, `mustNotMatch` | Up to 20 samples each, up to 1024 bytes each. |
| `enabled` | Defaults to `true`. |
| `version` | Starts at 1 and moves by one on every change. |

A pattern is refused with `422` when it is shorter than 3 bytes or
longer than 512; when it does not compile (RE2 has no lookarounds and no
backreferences, which is also why its cost is linear in the text and a
pattern cannot backtrack catastrophically); when it can match an empty
string (`CN-\d*|`, `(?:CN)?`, a pattern of anchors alone); or when it
compiles to more than 256 instructions (large repetition counts such as
`[a-z]{1,650}Q`; the message says how many it compiled to).

Linear is still text times program. So the custom detectors one policy
names share a cost budget: the sum of their program sizes times the
bytes the policy reads (`maxBytes`, 64 KiB when zero) may be at most
16 Mi instruction-bytes. That is 256 instructions at 64 KiB, which is
about 60 ms on a quiet machine at the slowest shape measured and about
200 ms on a loaded one; a contract-id pattern such as `\bCN-\d{6}\b` is
13 instructions, so a policy at the default window can name about
nineteen. A policy that exceeds it is `400` when saved, with the sizes
in the message; an edit or a restore of a detector that would push a
policy naming it over is `422` at `body.pattern`, naming the policy.
Lower `maxBytes` to name more.

A screen runs under the call's own deadline, or one second when that is
later or absent. A scan that reaches it refuses the call, whatever the
policy's action, with the reason in the refusal and on the audit trail
(`meta.error` for the arguments, `meta.dlpRefusal` for a result): a
value nobody finished reading may carry what the policy is for. The
preview is held to the same second and answers `422` when it reaches
it. A
policy naming a stored detector that cannot be compiled (a row written
by hand, say) refuses every call it screens, and the server logs the
detector once per cache load; every other policy screens as before. Each sample in `mustMatch` must
contain a match and none in `mustNotMatch` may; these are checked on
every save, including an edit that changes only the pattern. The `422`
names what failed in `errors[].location`: `body.pattern`, `body.flags`,
`body.name`, or the sample by position, such as `body.mustMatch[1]`. The
message names a sample by its position and never quotes it. An
organisation holds at most 50 custom detectors.

Samples are stored as written in the detector's row and nowhere else:
the revision history and the audit trail's diffs keep
`mustMatchCount` and `mustNotMatchCount`, not the samples, nor a hash of
them (a six-digit id is a million guesses from any unkeyed hash of it).
Use made-up values anyway.

A custom detector scans within the same byte budget as the built-ins
(the policy's `maxBytes`, 64 KiB by default). Its findings name it
(`detector` is `custom:<name>`, `rule` is `pattern`, `confidence` is
`high`) and carry the field path and a count, never the text it
matched. A mask replaces a match with `<redacted:custom:<name>>`, and a
refusal names the detector.

- `POST /api/v1/dlp/detectors` creates one (`201`); a name the
  organisation already uses is `409` with `name_taken` at `body.name`.
- `PATCH /api/v1/dlp/detectors/{id}` changes the fields it carries and
  leaves the rest. `expectedVersion` is required; a stale one is `409`
  with `version_conflict` at `body.expectedVersion` and the version
  stored now at `version`, as a tool edit's is. A `name` other than the
  current one is `422`. A write that deadlocks with a concurrent policy
  write (Postgres aborts one of the two) is `409` with
  `concurrent_change`; nothing was written, and it can be sent again.
- `DELETE /api/v1/dlp/detectors/{id}` is `409` while policies name the
  detector: `in_use` at `query.force`, then one entry per policy at
  `references.dlpPolicies`, with its name as `message` and its id as
  `value`. With `?force=true` the detector is removed from those policies
  in the same transaction, each change recorded in the policy's history
  and audited as `dlp.policy.update` with `meta.cause`
  `dlp.detector.delete` and `meta.detectorId`; a policy left naming no
  detector is also switched off.
- `POST /api/v1/dlp/detectors/test` takes `{pattern, flags, samples}`
  (up to 40 samples) and answers, per sample, `matched` and the byte
  offsets of each match (`start` inclusive, `end` exclusive, at most 20,
  with `more` when there were more). It applies the rules a save applies
  to the pattern and writes nothing; the samples are never quoted back.
  A body over 64 KiB is `413` before it is read.

A string in which one detector matches more than 100 times is treated
as one match, masked or refused whole, with `rule` `too_many_matches`:
a value that dense with matches is the thing itself, and a span per
match is what would cost the memory. This holds for the built-ins too.

Changes are audited as `dlp.detector.create`, `dlp.detector.update` and
`dlp.detector.delete`. Each replica caches an organisation's compiled
detectors beside its policies; a change reaches every replica on commit
through the same notification a policy change sends
(`docs/operations.md`, "Cache invalidation").

## Audit search

`GET /api/v1/audit` (`audit:read`) and `GET /api/v1/audit/export`
(`audit:export`) take the same filters: `category`, `action`, `actorId`,
`targetId`, `outcome`, `from`, `to`, and `q`, a free-text search. They
combine: an event is listed only if it passes every filter given. The
list pages by `afterSeq` with a search as without one, and a workspace
only ever finds its own events.

`q` is read as Postgres
[web search syntax](https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-PARSING-QUERIES)
(`websearch_to_tsquery`):

| Written | Finds events that |
|---|---|
| `connector okta` | carry both words |
| `"quarterly review"` | carry the words next to each other, in that order |
| `saml or okta` | carry either |
| `connector -denied` | carry `connector` and not `denied` |

Matching is by whole word and ignores case; there is no prefix match, so
`conn` does not find `connector`. Nothing is stemmed and no word is
ignored (the `simple` configuration), because the trail is mostly ids,
action names and slugs. A name with dots or an `@` matches written whole
or by its parts: `connector.created` and `connector` both find a
`connector.created` event, and `ada@example.com` and `ada` both find her.

What is searched:

- the action;
- who acted: `actorId` and `actorDisplay` (a person's email is there);
- what was acted on: `targetKind`, `targetId` and `targetDisplay`;
- the string values in `meta`, at any depth. Not its keys, numbers or
  booleans.

What is deliberately not: `diff` and `payload`, which can hold what a
tool was sent and returned and are governed by the payload policy; the
caller's IP and user agent; request and session ids.

One `meta` string is kept whatever the payload policy says, and so is
searched: a failed tool call's `meta.error`, which says why it failed.
Before it is recorded (and on the tool-call row, which keeps the same
text) a URL in it is cut to scheme, host and path, a password in a URL
or connection string and a query parameter named like a secret are
replaced with `***`, and what the `masked` policy removes from payloads
(card numbers, email addresses, IBANs, US social security numbers,
API-key shaped tokens) is replaced with `<redacted>`. A plain word the
caller sent that the upstream quoted back in its error can still be
there.

The first 100,000 characters of an event's text are searched: its own
fields first, then `meta.target`, `server`, `connector`, `tool` and
`reason`, then the rest of `meta`. An event whose `meta` is longer is
still listed, but a word past that point does not find it.

`q` longer than 200 characters is `422`. A `q` that is empty or only
spaces is no search at all. A `q` with no word in it, such as `!!!` or
`-`, matches nothing, not everything: an empty list, not the whole trail.

A page of the list, search included, has ten seconds. One that takes
longer is `503`, with `detail` saying so; a time range (`from`, `to`) or
more specific words bring it back within bounds.

An export sends at most 100,000 events and runs for at most ten
minutes. One cut short by either ends with a line that is not an event:

```json
{"truncated": true, "afterSeq": 81234, "reason": "the export reached its limit of 100,000 events"}
```

Export again with the same filters and `afterSeq` set to that number to
take the next part. An export that ends without that line is complete.

An export records `audit.exported` with the `category`, `action` and `q`
it was asked for. So a search is only as private as the trail: a secret
pasted into `q` to see where it leaked is written into the trail, where
every reader of it can see it, the moment that search is exported. Search
for part of it, or look for it outside the application.

## Audit retention

`GET /api/v1/audit/retention` (`audit:read`) reads the current
workspace's window; `PUT` with `{"days": N}` (`audit:policy:manage`,
the permission that also sets the payload policy) changes it. Both answer:

| Field | Means |
|---|---|
| `days` | Events older than this lose their content. They stay in the chain. |
| `configured` | `false` while the workspace is on the default. |
| `defaultDays`, `minDays`, `maxDays` | 365, 90 and 36 500. |

A `days` below `minDays` or above `maxDays` is `422`, with the bound in
`detail`; nothing is stored. Each change is recorded as
`audit.retention.set` with the window before and after, and a refused
one as the same action with outcome `failure`. The hourly sweep reads
the new value on its next run.

## Usage analytics

`GET /api/v1/analytics/usage` (`connectors:read`, the permission the
tool-call list asks for) counts the current workspace's tool calls over a
window. It reads the rows the tool-call list reads and nothing else;
Prometheus has no workspace label and is not consulted.

| Parameter | Means |
|---|---|
| `from`, `to` | The window, RFC 3339, `from` inclusive and `to` exclusive. `to` defaults to now, `from` to seven days before `to`. |
| `bucket` | `hour` or `day`, cut in UTC. Defaults to `hour` for a window of two days or less, `day` otherwise. |
| `by` | `tool` (default), `connector` or `server`: what the top list is broken down by. |
| `limit` | How many entries the top list holds, 1 to 50, default 10. |

A window longer than 90 days, or one whose `from` is not before its `to`,
is `422` with the reason in `detail`. `by=server` also needs
`servers:read`, the permission the server list asks for; without it the
request is `403`.

Each request runs aggregates over up to 90 days of calls, so the route
has limits of its own. It draws on the `SUPERMCP_RATELIMIT_ANALYTICS`
budget (default `30/1m`) instead of the general one. Each replica runs at
most two of a workspace's analytics queries at a time and answers a third
with `429` rather than queueing it. An answer is reused for 60 seconds for
the same workspace and the same parameters, so a window that ends at "now"
to the millisecond is never reused; the screen rounds `to` to the minute.

The answer has `totals` for the whole window, `series` with one entry per
bucket (empty buckets included, with zero calls), and `top`, the busiest
entries by call count over the whole window. Each of these carries
`calls`; `errors`, the calls whose status was not `success` (so `error`,
`timeout` and `denied`); `p50Ms` and `p95Ms`, the median and 95th
percentile of the call's duration; and `upstreamP50Ms` and
`upstreamP95Ms`, the same for the time spent waiting on the upstream.
The percentiles are left out when there is nothing to take them over. A
`top` entry also has `id` and `name`: a tool's current name, or the name
its latest call recorded if it has been deleted. Calls that went through
no MCP server are one entry with an empty `id` when `by=server`, and calls
that recorded no tool id are one entry with an empty `id` when `by=tool`.

## Members

The people in the current workspace and what an administrator can do
about them.

| Method | Path | Permission | Audit action |
|---|---|---|---|
| `GET` | `/api/v1/org/members` | `org:read` | none |
| `PATCH` | `/api/v1/org/members/{userId}` with `{"status": "deactivated"}` or `{"status": "active"}` | `org:members:manage` | `member.deactivate`, `member.reactivate` |
| `PATCH` | `/api/v1/org/members/{userId}` with `{"roleId": "..."}` | `org:members:manage` | `member.role.set` |
| `DELETE` | `/api/v1/org/members/{userId}` | `org:members:manage` | `member.remove` |

Each member carries `userId`, `email`, `name`, `status` (`active` or
`deactivated`), `source` (`scim` when an identity provider provisions
them through SCIM, `sso` when they sign in through single sign-on, else
`password`), `roles` (every unexpired binding they hold here, with its
`roleId`, `roleName`, `bindingId`, `source` and `scopeKind`),
`lastSignInAt`, `joinedAt`, `isSelf` and `scimManaged`.

A `PATCH` changes one thing: send `status` or `roleId`, not both (`400`).

- **Deactivate** keeps the membership and its role bindings but switches
  them off, and in the same transaction revokes the member's sessions
  (in every workspace), their API keys in this workspace and their
  refresh tokens. Their next request is unauthenticated. They can no
  longer switch into the workspace, and the evaluator ignores the
  bindings of a deactivated member, so nothing cached keeps working.
  **Reactivate** turns the membership back on; the member signs in again.
- **Set role** replaces the member's manual workspace-wide bindings with
  one for `roleId`. Bindings an identity provider made, and bindings
  scoped to a server, connector or tool, are left alone, so this works
  for single sign-on and SCIM members too. An unknown role, or another
  workspace's own role, is `404`. Making someone an owner takes an owner
  (`403` otherwise).
- **Remove** deletes the member's role bindings here and the membership,
  and revokes their credentials as deactivation does. The account itself
  stays: it may belong to other workspaces, and the audit trail names it.

The audit event's target is the user, named by email, with the member
before and after (or, for a removal, before) as its diff. A refused
change is recorded under the same action with outcome `failure`.

Refusals are `409` with a stable code in `errors[0].value`:

| Code | Refused because |
|---|---|
| `self` | The change is aimed at the caller. Ask another administrator. |
| `last_owner` | It would leave the workspace with no active member holding the owner role workspace-wide. Applies to deactivate, remove and a role change. |
| `scim_managed` | The member is provisioned through SCIM. Deactivate or remove them in the identity provider; their role can still be changed here. |

A `userId` that is not a member of the current workspace, including one
in another workspace, is `404`.

## Invites

An invite brings a person into the current workspace with one role. The
server sends no email. Creating an invite returns a link once, and the
administrator sends it to the person. Invites work when
`SUPERMCP_OPEN_REGISTRATION` is off. They create an account only for the
invited address, and only in the inviting workspace.

| Method | Path | Permission | Audit |
|---|---|---|---|
| `GET` | `/api/v1/org/invites` | `org:members:manage` | none |
| `POST` | `/api/v1/org/invites` | `org:members:manage` | `invite.create` |
| `DELETE` | `/api/v1/org/invites/{id}` | `org:members:manage` | `invite.revoke` |
| `POST` | `/api/v1/invites/lookup` | none | none |
| `POST` | `/api/v1/invites/accept` | none, or a session | `account.register`, `member.join` |

**Creating.** Send `{"email", "roleId", "expiresInDays"}`.
`expiresInDays` is optional. It defaults to 7 and can be 1 to 30. The
`201` response contains `invite` and `url`, which is
`<SUPERMCP_PUBLIC_URL>/invite/<token>`. The token is 32 random bytes.
The server stores only its SHA-256 digest, so the link cannot be read
back later. If it is lost, revoke the invite and create another. The
token and the link never appear in list responses or the audit trail.
The `invite.create` diff contains the invite exactly as the list returns
it.

Refusals:

| Status | `errors[].value` | Means |
|---|---|---|
| 400 | | The address is not an email address. |
| 403 | | The role grants `*` (for example `owner`), and the caller does not hold `*`. |
| 404 | | The workspace has no role with that id. |
| 409 | `invite_exists` | The address already has an open invite. Revoke it first. An expired invite that was never revoked is revoked automatically. |
| 409 | `already_member` | The person is already a member, active or deactivated. |
| 409 | `invite_limit` | The workspace already has 100 pending invites. |

**Listing** returns the newest 500 invites. Each one has a `status`:
`pending`, `accepted`, `revoked` or `expired`. `invitedBy` is the id of
the user who created the invite. `invitedByName` is that user's name, or
their address if they have no name. It is omitted after they leave the
workspace.

**Revoking** works on any invite that has not been accepted or revoked,
including an expired one. It answers `204`. An invite that cannot be
revoked, or that belongs to another workspace, is `404`.

**Looking up and accepting.** The page at `/invite/<token>` posts the
token in a JSON body, `{"token": "..."}`. The token never goes in an API
path, so it stays out of the access-log lines for these calls.
`lookup` returns `orgName`, `email`, `roleName`, `expiresAt` and
`registrationRequired`, which is `true` when the address has no account.
When it is `true`, the response also includes `passwordPolicy`, the
workspace's password rules in the same shape as
`GET /api/v1/org/password-policy`. The person holding the link has no
session, so they cannot call that endpoint. An unknown, expired, revoked or accepted token always gets the same
`404`. Each `404` counts against the caller's address, like a failed
sign-in, and repeated misses lock it out with `429`. Both endpoints
share the `SUPERMCP_RATELIMIT_INVITE` budget.

How `accept` behaves depends on whether the caller has a session:

- **No session.** Send `password` and optionally `name`. The password
  must meet the workspace's policy. The server creates an account for
  the invited address, makes it a member with the invited role, and
  returns a new session cookie, the same way `register` does. If an
  account already has that address, the reply is `409` with the error
  value `account_exists` at `body.password`. The person signs in, with a
  password or single sign-on, and opens the link again. Accounts are
  never merged on an unauthenticated request.
- **A session.** Send only the token. The signed-in account's address
  must match the invite, or the reply is `403`. Sending a password is
  `400`. The account joins the workspace, and the session switches to
  it.

An invite can be used once. When two people accept at the same moment,
one succeeds and the other gets `404`. A new account is recorded as
`account.register` with `meta.via = "invite"`. Every acceptance is
recorded as `member.join` in the workspace, with the new member as the
actor and the role in `meta`.

## Revisions

Connectors, tools, MCP servers, roles, data-loss policies and
detectors, approval policies and sign-in providers keep a history. Every create, update and
delete writes a revision in the same transaction as the change: the
entity as it stood afterwards (for a delete, as it stood before), the
diff, who made it and when. A delete keeps the history. An entity that
predates its kind's history has its state recorded as revision 1, with
no actor, just before its first recorded change.

Each kind has the same three routes under its own path:

| Kind (`kind` in a revision) | Path | Read with | Restore also needs |
|---|---|---|---|
| `connector` | `/api/v1/connectors/{id}` | `connectors:read` | |
| `tool` | `/api/v1/tools/{id}` | `connectors:read` | see "Managing tools" |
| `server` | `/api/v1/servers/{id}` | `servers:read` | |
| `role` | `/api/v1/roles/{id}` | `roles:read` | |
| `dlp_policy` | `/api/v1/dlp/policies/{id}` | `connectors:read` | `dlp:manage` |
| `dlp_detector` | `/api/v1/dlp/detectors/{id}` | `connectors:read` | `dlp:manage` |
| `approval_policy` | `/api/v1/approval-policies/{id}` | `approvals:decide` | `org:settings:manage` |
| `identity_provider` | `/api/v1/idps/{id}` | `idp:manage` | `idp:manage` |
| `saml_provider` | `/api/v1/saml-providers/{id}` | `idp:manage` | `idp:manage` |

- `GET <path>/revisions` lists them newest first, without snapshots.
  `before` and `limit` page through; `nextBefore` is zero at the start of
  the history.
- `GET <path>/revisions/{revision}` reads one, with its `snapshot`.
- `POST <path>/revisions/{revision}/restore` puts that version back. It
  needs `revisions:rollback` and the permission in the last column, and
  a browser session must be within the fresh-auth window. It answers with
  the entity as it now stands.

A restore goes through the path an edit takes, so it is checked like an
edit, recorded as a further revision (the history of a mistake survives
its correction) and audited twice: the ordinary change event (for
example `dlp.policy.update`) and `<kind>.revision.restore` with the
revision number in `meta.revision`. The change event's diff is taken
from the entity as it stood under the row lock, before and after, and for
a provider it is the history's snapshot, so it shows the issuer, the
endpoints and (for SAML) the certificates trusted. A refused restore is
recorded as the same action with outcome `failure`.

What each kind puts back:

- **Data-loss policy.** Every setting, scope included. The change reaches
  every replica's policy cache on commit, as an edit does, so the next
  tool call anywhere is screened by the restored rule. A deleted policy is
  recreated under its old id, recorded as a `create`. A scope that has
  since gone (the connector or tool was deleted, which also deletes its
  policies without a revision) is `400`, as is a scope that another rule
  now holds.
- **Custom data-loss detector.** Every setting but the name, which is how
  policies refer to it and never changes, and the samples, which the
  history does not hold. A detector that exists keeps the samples it has
  now, and the answer says so with `samplesKept: true`; the restored
  pattern is checked against them and against the cost budget of every
  policy naming it, so a version that would no longer pass is `422`. A
  deleted detector is recreated under its old id and name with no
  samples (`samplesKept: false`); the policies a forced delete took it
  out of stay as they are, and each has its own history to restore from.
- **Approval policy.** Every setting. Rules are read on every tool call,
  not cached, so the next call is governed by the restored rule. A deleted
  rule is recreated under its old id. Requests it raised before the delete
  stay detached from it (the delete cleared their `policyId`) and keep its
  name as it was.
- **OIDC or OAuth 2.0 provider.** Everything but the client secret,
  including the second-factor rule (a revision recorded before the rule
  existed keeps the one the provider has now). The
  history never holds the secret, sealed or otherwise: one that an older
  version used may have been revoked at the provider since, and a copy in
  the history would be a place rotation does not reach. The secret stored
  when the restore runs is kept, and the answer says so with
  `clientSecretKept: true`. The stored secret is only ever sent where it
  was configured to go: a restore, or a `PUT /api/v1/idps/{id}`, that
  changes the issuer or sets an endpoint on a host the provider does not
  use now is `422` unless the request carries a new client secret (on a
  restore, an optional body `{"clientSecret": "…"}`, after which
  `clientSecretKept` is `false`). A deleted provider cannot be restored
  (`404`): its secret went with it.
- **SAML provider.** Everything but our signing key pair, including the
  identity provider's entity id, sign-in URL and certificates, which come
  from the snapshot rather than from fetching the metadata again. The key
  pair stays as it is, because the private key is not in the history and
  the identity provider trusts the certificate in use now; the answer says
  so with `signingKeyKept: true`. A version that names no identity
  provider certificate is refused with `400`. A rotation is recorded as a revision, so
  it shows in the history. A deleted provider cannot be restored (`404`).

A snapshot and a diff digest a top-level field whose name looks like a
credential (`secret`, `token`, `password` and similar), as the audit
trail does. That is why a provider's snapshot keeps its URLs under
`endpoints`.

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
reason the evaluator gave.

Every response, on every route (the admin API, SCIM, MCP, OAuth, the
health checks), carries an `X-Request-Id` header. The server chooses
the id; one a client sends is not reused. A `500` says nothing about
its cause, because the cause is often a database or upstream error that
names a host, a connection string or a query. On the admin API, and for
any request that panics, the body is always this shape, with no
`errors`:

```json
{
  "title": "Internal Server Error",
  "status": 500,
  "detail": "something went wrong; the request id is 5PZ4Q2B7YHMMJ3XKSV6CT3NE4Q"
}
```

The other surfaces carry the same sentence in their own error shape:
SCIM in `detail` of its error schema, the MCP endpoint in the JSON-RPC
error's `message`, and the OAuth endpoints as `error: "server_error"`
with the sentence in `error_description`. A request that runs past the
60-second limit answers `504` with an empty body.

The id in the sentence is the one in `X-Request-Id`. Quote it when
reporting the failure: the server logs the cause once with the same id
in `req_id` (`request failed`, `request panicked`, `scim request
failed`, `mcp request failed` or `oauth request failed`). The audit
trail records such a failure the same way: `meta.error` (or
`meta.reason`, for sign-in events) is the generic message and
`meta.requestId` the id. A failure the API answers itself (any `4xx`,
or a `503`) keeps its message in the response, and the audit event
records a stable code in `meta.error` (the code in `errors[].value`
where the response has one, such as `last_owner`, otherwise the status
in words, such as `not_found`), with the message, cut to 200
characters, in `meta.message`. Changes whose refusals quote what was
sent (importing, installing or updating a connector, creating or
updating a tool, a data-loss or approval policy, or an identity
provider) record the code only. Failed tool calls are the exception:
their audit event keeps the upstream's error text, after credentials
and anything the payload policy masks are removed from it, because that
is how an administrator learns why their connector failed.

`/readyz` answers `database unavailable` or `schema not ready` and
nothing more; the pod's log says why.

| Status | Means |
|---|---|
| 400 | The request is malformed, or a value violates a policy (a weak password, a reused password, an unknown scope). |
| 401 | No credential, or one that did not verify. |
| 403 | Authenticated, but the permission is not held — or no workspace is selected, or the account is disabled, or registration is closed, or the session signed in too long ago for the operation (`errors[].value` is `reauth_required`; see "Recent sign-in"). |
| 404 | No such object *in your workspace*. Objects in other workspaces are not distinguishable from objects that do not exist. |
| 409 | A record that already exists (a role binding, a tool name, anything else held unique), removing the last owner of a workspace, or a tool write that conflicts (see "Managing tools"). |
| 422 | The body is well formed but its content is not acceptable: a tool definition with errors, or a required field missing. |
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

## Single sign-on providers

`GET /api/v1/idps` lists the workspace's OpenID Connect and OAuth 2.0
providers, `POST /api/v1/idps` adds one and `PUT /api/v1/idps/{id}`
replaces one's configuration; all need `idp:manage`. The fields are
those of `IdpInput` in the OpenAPI document: `preset` (`entra`,
`google`, `okta`, `auth0`, `github` or `generic`), `name`, `issuer`,
`clientId`, `clientSecret` (write-only; left out of a `PUT`, the stored
one is kept), `scopes`, `allowedDomains`, `jitProvisioning`,
`defaultRoleId`, `groupsClaim`, `enabled`, the endpoints a `generic`
provider without a discovery document needs, and `mfa`.

### The second-factor rule

We issue no second factor of our own. Whether a single sign-on session
has one, which is what the `mfa` value in an access token's `amr`
says, comes from what the identity provider said, and `mfa` says which
of its answers count:

```json
"mfa": {"amr": ["mfa", "otp", "hwk", "sc"], "acr": []}
```

- `amr` lists RFC 8176 authentication method references. A sign-in
  counts when the ID token's `amr` claim names any of them. `pwd` is
  refused: a password is the first factor.
- `acr` lists authentication context class references. A sign-in counts
  when the ID token's `acr` claim is one of them.
- Both are compared with the verified ID token only, never with the
  user endpoint's answer, which is not signed. Values are compared
  exactly, case included. Each list holds at most 32 values of at most
  256 characters.
- Both lists empty is no rule, and then no sign-in through the provider
  counts as having a second factor.
- `PATCH /api/v1/idps/{id}/mfa` with the rule as its body
  (`{"amr": [...], "acr": [...]}`) changes the rule and nothing else,
  so it cannot undo a change to the rest of the provider made since you
  read it. It needs what a `PUT` needs (`idp:manage` and a recent
  sign-in), is recorded in the provider's history and on the audit
  trail as `idp.update`, and answers `404` for a provider that is not
  there.
- Left out of a `POST`, an OpenID Connect provider gets the default,
  `amr` `["mfa", "otp", "hwk", "sc"]`. `swk` is not in it: a key held in
  software and used alone is one factor. Left out of a `PUT`, the stored
  rule is kept. A GitHub provider issues no ID token, so its rule is
  always empty and a `mfa` that names anything is refused with `400`.
- The rule applies to a re-authentication as to a first sign-in: the
  session that replaces the stale one has a second factor only if the
  new ID token met the rule.

What providers send differs, and a provider's configuration decides
what it sends, so read a real ID token from yours (the `session.create`
audit event records the `amr` and `acr` each sign-in carried) before
you rely on a rule:

| Provider | What to count |
|---|---|
| Entra ID | `amr` contains `mfa` when the sign-in satisfied multi-factor authentication, beside values of its own, such as `rsa` and `ngcmfa`, that the default leaves alone. Which token versions carry `amr` depends on the app registration, so check a decoded ID token from your tenant; a token without `amr` never counts under the default rule. |
| Okta | `amr` names the factors (`pwd`, `mfa`, `otp`, `sms`, `hwk`, `swk`, ...). With the Identity Engine, `acr` can say the assurance level: `urn:okta:loa:2fa:any` for two factors, `phr` for phishing-resistant and `phrh` for phishing-resistant hardware. Do not count `urn:okta:loa:2fa:any:ifpossible`, which a single factor can satisfy. |
| Auth0 | `amr` contains `mfa` when a second factor was used. The default rule covers it. |
| Google | Its ID tokens carry neither `amr` nor `acr`, so no sign-in through Google counts as having a second factor here, whatever the Google Workspace enforces. Use SAML if you need that. |

Providers that report `sms` or `tel`, which the default leaves out, can
have them added.

A change to the rule applies to the next sign-in; sessions already open
keep what was recorded when they signed in. The rule is part of the
provider's history, and a restore puts it back, except from a revision
recorded before the rule existed, whose restore keeps the rule the
provider has now.

## SCIM

Mounted at `/scim/v2` with the usual `Users` and `Groups` resources and
`GET`, `POST`, `PUT`, `PATCH`, `DELETE` on each, plus
`ServiceProviderConfig`, `ResourceTypes` and `Schemas`.

Authentication is an ordinary credential — in practice an API key held
by the identity provider — and every route requires the `scim:manage`
permission. As noted above, the key must also carry the `mcp:org` scope,
or the scope ceiling refuses it.

Errors use the SCIM error schema (`urn:ietf:params:scim:api:messages:2.0:Error`).
A `500`'s `detail` is the same generic message with the request id as
the admin API's, and the cause is in the log as `scim request failed`.

Setting a user `active: false`, through `PUT` or through a `PATCH` on
the `active` attribute, and a `DELETE` of the user, mark the membership
deactivated and revoke the person's API keys and refresh tokens in that
workspace and their sessions in every workspace: a person who belongs to
several workspaces is signed out of all of them and signs in again to
reach the others. A deactivated account stops working immediately rather
than at the next token expiry.

SCIM does not assign roles. Group membership from an identity provider
maps to roles through single sign-on instead: bind a role to a principal
of kind `idp_group` whose id is the group name, and every sign-in
through that provider reconciles the person's provider-sourced bindings
to match their groups. Bindings an administrator made by hand are left
alone — the provider owns what it granted and nothing else.

## Versioning

The admin API is at `/api/v1`. The schema policy is expand-only across
one minor version: `scripts/check-migrations.sh`, run in CI, refuses a
migration whose Up section drops, renames, retypes or makes a column
`NOT NULL` unless it carries a `-- supermcp:breaking` line and
`docs/UPGRADING.md` names it.
