# Writing an adapter

An adapter is one YAML file that describes an upstream system and the
tools it offers. Installing an adapter creates a connector in a
workspace; the connector's tools are what an AI client sees over MCP.

255 adapters ship compiled into the binary. This document is about
writing another one, whether to contribute it or to keep it in your own
tree.

## Where the files go

```
adapters/<region>/<slug>/adapter.yaml
adapters/<region>/<slug>/cassettes/<tool_name>.yaml
```

The directory name must equal `metadata.slug`, and the region directory
must equal `metadata.region`. The validator checks both, because a file
that disagrees with its path is found by one tool and not by another.

Every adapter file starts with a schema comment, so an editor with the
YAML language server validates as you type:

```yaml
# yaml-language-server: $schema=https://supermcp.dev/schema/adapter/v2.json
```

The running instance serves the same schema at
`/schema/adapter/v2.json`, and it is embedded in the binary, so it is
always the schema this build enforces.

## The document

```yaml
apiVersion: supermcp.dev/v2
kind: Adapter
metadata: { ... }
credentials: { ... }      # optional
transport: { ... }
auth: { ... }
healthcheck: { ... }      # optional but warned about when absent
instructions: |           # optional but warned about when short
tools: [ ... ]
```

### metadata

| Field | Required | Meaning |
|---|---|---|
| `slug` | yes | Lower-case kebab-case. Must equal the directory name and be unique across the catalogue. |
| `name` | yes | What a person reads in the catalogue. |
| `description` | yes | One paragraph. Shown in the catalogue listing and searched by the `q` filter. |
| `region` | yes | One of `be br ch de dk es fr gb in intl it jp ng nl se`. Must equal the region directory. |
| `category` | yes | One of a closed set of 42: `accounting`, `analytics`, `banking`, `cms`, `crm`, `data`, `database`, `documents`, `e-commerce`, `e-signature`, `email`, `enrichment`, `entertainment`, `erp`, `finance`, `food`, `forms`, `government`, `healthcare`, `hr`, `infrastructure`, `itsm`, `knowledge`, `logistics`, `maps`, `marketing-automation`, `messaging`, `monitoring`, `operations`, `payments`, `productivity`, `project-management`, `publishing`, `real-estate`, `scheduling`, `social`, `sports`, `storage`, `support`, `time-tracking`, `transport`, `travel`. |
| `icon` | yes | Icon identifier or URL. A plain `http://` URL raises a warning. |
| `docsUrl` | yes | The vendor's own API documentation. |
| `priority` | no | Ordering hint for the catalogue. |
| `featured` | no | Catalogue flag. |
| `selfHostOnly` | no | Catalogue flag. |
| `lint.allow` | no | A list of validator rule ids whose *warnings* are suppressed for this adapter. It cannot suppress an error. |

### credentials

One declaration site for everything the adapter needs an operator to
supply. Names are `UPPER_SNAKE_CASE`.

```yaml
credentials:
  PANDADOC_API_KEY:
    required: true
    secret: true
    description: An API key from Settings → Integrations → API.
```

| Field | Default | Meaning |
|---|---|---|
| `required` | `false` | The install is refused unless a value is supplied. |
| `secret` | `false` | Whether the value is treated as a secret. Every credential value is encrypted at rest regardless; this flag is what the interface and the API report about it. |
| `usage` | `template` | `template` means the adapter references it as `{{env.NAME}}`. `manual` means the operator sets it but the adapter's own templates do not use it. |
| `description` | empty | Shown to whoever is installing. |

The validator enforces both directions of the relationship. A
`{{env.X}}` that is not declared is an **error**: an undeclared
credential is a value going on the wire that nothing asked the operator
for and nothing records. A declared credential that is never referenced
is a **warning**, with `usage: manual` as the way to say it is
deliberate.

### transport

```yaml
transport:
  type: http
  baseUrl: https://api.example.com/v2
  headers:
    Accept: application/json
  timeout: 30s
```

| Field | Applies to | Meaning |
|---|---|---|
| `type` | all | `http`, `graphql`, `database`, `soap` or `mcp`. |
| `baseUrl` | `http`, `graphql`, `soap`, `mcp` | Required. Each tool's `path` is appended to it. |
| `dsn`, `driver` | `database` | Required. `driver` is one of `postgres`, `mysql`, `mssql`, `oracle`, `sqlite`, `mongodb`. Setting either on a non-database transport is an error. |
| `headers` | all | Sent on every request. Values may contain placeholders. |
| `timeout` | all | A Go duration string such as `30s`. Caps every tool on this connector. |
| `rateLimit` | all | `{ rps, burst }`. |
| `proxy` | all | Route through the configured outbound proxy. |

The schema accepts `soap` and `mcp`, and the validator checks them, but
**no engine ships for either**. Only `http`, `graphql` and `database`
can execute a call. An adapter using `soap` or `mcp` validates and then
fails at call time with an unsupported-transport error.

### auth

A discriminated union on `type`. Setting a field belonging to another
type is an error, so a half-converted adapter is caught rather than
silently ignoring half its configuration.

| Type | Required fields | Notes |
|---|---|---|
| `none` | — | |
| `apiKey` | `in` (`header`, `query` or `cookie`), `name`, `value` | The common case. |
| `bearer` | `token` | `prefix` and `header` override `Bearer` and `Authorization`. |
| `basic` | `username` or `password` | Both empty is an error; one empty is not, because "API key as username, empty password" is a real pattern. |
| `query` | `params` (non-empty) | Credentials as query parameters. |
| `oauth2` | `grant`, `tokenUrl`, `clientId` | `grant` is `client_credentials`, `refresh_token` or `authorization_code`. `refresh_token` also needs `refreshToken`; `authorization_code` also needs `authorizationUrl`. `clientAuth` is `basic` or `body`. |
| `login` | `request.url`, `tokenSource`, `inject` | For upstreams with a bespoke sign-in call. `tokenSource.from` is `body` (needs `jsonPath`) or `setCookie` (needs `cookieName`). `preprocess` (bcrypt with a fetched salt) is accepted by the schema and the validator; no implementation ships, and a login that declares it fails. |
| `hmac` | `secret`, `stringToSign`, `signatureHeader` | `algorithm` is `sha256` (default), `sha1` or `sha512`. `encoding` is `hex` or `base64`. |
| `database` | `username` or `password` | Credentials for a database transport. `domain` for NTLM. |
| `oauth1`, `wsSecurity`, `mtls` | see the schema | **Accepted by the schema and the validator; no implementation ships.** A call using one of these fails. |

`auth.optional: true` says the adapter sends unauthenticated requests
when no credential is set. There is a consistency rule: an adapter with
an auth type other than `none`, at least one declared credential, and
none of them required, must set `optional: true` — otherwise it claims
to authenticate and has nothing to authenticate with.

`inject` says where an obtained token goes on each request, and is
shared by `oauth2`, `login` and `hmac`:

```yaml
inject:
  header: Authorization
  prefix: Bearer
  # or: template: 'id={{auth.token}}'
  # or: cookie: session
```

### healthcheck

Either a tool to call, or a raw HTTP path:

```yaml
healthcheck:
  tool: fortnox_get_company_settings
  http:
    method: GET
    path: /settings/company
```

`healthcheck.tool` must name a tool this adapter defines. An adapter
with no healthcheck raises a warning, suppressible with
`lint.allow: [healthcheck-present]`.

### instructions

A block scalar that becomes the MCP server instructions for a connector
built from this adapter. It is where the operational knowledge goes:
how to obtain a credential, which rate limits the vendor enforces, which
fields are surprising, what is out of scope. Fewer than 800 characters
raises a warning.

### tools

```yaml
tools:
  - name: nominatim_search
    description: Forward geocode a free-text address to coordinates and a structured address.
    input:
      type: object
      properties:
        q: { type: string, description: "Free-text query." }
        limit: { type: integer, default: 10 }
      required: [q]
    annotations:
      readOnlyHint: true
    timeout: 20s
    operation:
      method: GET
      path: /search
      query:
        q: '{{params.q}}'
        limit: '{{params.limit}}'
        format: json
    response:
      transform:
        jmespath: '[].{name: display_name, lat: lat, lon: lon}'
      cache: 24h
```

| Field | Meaning |
|---|---|
| `name` | Lower-case snake_case, unique within the adapter. It *should* start with the slug with hyphens replaced by underscores (`nominatim_`); not doing so is a warning, because tool names collide across a catalogue of thousands. `supermcp_approval_status` and `supermcp_approval_cancel` are the instance's own tools, present on every server (docs/api.md, "Following up a held call"); an adapter tool with either name is never called. |
| `description` | What the model reads to decide whether to call it. Fewer than 60 characters is a warning. |
| `input` | A JSON Schema object. Required. |
| `output` | A JSON Schema object. When present, the result is also returned as MCP structured content. |
| `annotations` | `title`, `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`. Unset hints are derived at runtime from the transport and whether the connector is read-only. |
| `timeout` | Caps this tool. It is used only when it is shorter than the connector's timeout. |
| `rateLimit`, `proxy` | Per-tool overrides. |
| `operation` | A union keyed by `transport.type`. See below. |
| `response` | `transform.jmespath`, `cache` (a duration), `exposeHeaders`, `maxBytes`, `fallbackToRaw`. |

The input schema is a **subset** of JSON Schema. These keywords are
errors: `$ref`, `oneOf`, `anyOf`, `allOf`, `not`, `if`, `then`, `else`,
`patternProperties`, `dependencies`, `$defs`, `definitions`. The subset
exists because the schema is handed to a model and round-tripped through
the database on every call; a `$ref` that resolves in one place and not
another is a call that fails for reasons no one can see. `input.type`
must be `object`, and every name in `required` must be a declared
property.

#### operation by transport

**http** and **soap**: `method` (one of `GET POST PUT PATCH DELETE HEAD
OPTIONS`), `path` (may be empty when the base URL is the resource),
`query`, `headers`, `body`. A body on a `GET` or `HEAD` raises a
warning. `body.encoding` is `json` (default), `form`, `multipart` or
`raw`.

**graphql**: `kind` is `query` or `mutation`, `document` is the
operation text, `variables` is a mapping.

**database**: `kind` is `sql`, `schema` or `static`. An `sql` operation
needs a `statement`. A statement that does not begin with `SELECT`,
`WITH`, `SHOW`, `EXPLAIN` or `DESCRIBE`, on a tool not marked
`destructiveHint: true`, raises a warning — the tool is being described
to the model as safe when it is not.

**mcp**: `tool` names the upstream tool, `argsMap` maps arguments.

**any**: `kind: static` returns `value` without calling anything. It is
how an adapter ships a reference table or a constant. It works on every
transport: the call is answered before any engine runs, so nothing is
sent upstream and no credential is decrypted. The response transform and
the data-loss rules still apply to the value.

## Placeholder syntax

One syntax, resolved in one place, used by the engines, the validator
and the command line alike.

```
{{namespace.path}}
{{namespace.path | filter}}
{{namespace.path | filter:argument | filter}}
```

### Namespaces

| Namespace | Holds | Available where |
|---|---|---|
| `params.*` | The tool call's arguments, typed. A dotted path walks objects and arrays (`params.filter.from`, `params.ids.0`). | Anywhere in a tool's `operation`. |
| `env.*` | The connector's credentials. | Anywhere, including `transport` and `auth`. |
| `caller.*` | Who is calling: `email`, `sub`, `org`, `server`, `authMethod`. Any other name is an error. | Anywhere. |
| `auth.*` | Values the upstream auth flow produced, such as `token`. | `auth` blocks and, for `login`, the declared `credentials` keys. |
| `req.*` | Facts about the request being signed: `method`, `url`, `path`, `body`, `timestamp`. | HMAC and login signing strings only. |

`{{ "{{" }}` renders a literal `{{`.

### Typed versus interpolated

A string that is **exactly one placeholder** yields the referenced value
with its type intact: a number stays a number, an object stays an
object. When the value is unset, the key is dropped from the request
rather than sent empty.

```yaml
query:
  limit: '{{params.limit}}'     # absent limit → no limit= parameter at all
```

Any other string is interpolated into text. In a URL path, values are
escaped per segment unless `| raw` is given. A missing reference in a
path or in a strict context — SQL text, a GraphQL document, a signing
string — is an error rather than an empty string.

### Filters

| Filter | Effect |
|---|---|
| `default:<json>` | Supplies a value when the reference is unset. The argument is JSON, so `default:0` and `default:"none"` differ. |
| `raw` | Suppresses escaping. |
| `json` | Serialises the value as JSON. |
| `urlencode` | Percent-encodes. |
| `base64` | Base64-encodes. |
| `join:","` | Joins an array. |
| `upper`, `lower` | Case. |

Anything else is a parse error naming the filter.

## A worked example

A read-only HTTP adapter with one credential, one tool and a response
transform. Saved as `adapters/intl/acme-invoices/adapter.yaml`:

```yaml
# yaml-language-server: $schema=https://supermcp.dev/schema/adapter/v2.json
apiVersion: supermcp.dev/v2
kind: Adapter
metadata:
  slug: acme-invoices
  name: Acme Invoices
  description: >-
    Acme's invoicing API: list and read invoices, with customer and line
    detail. REST, API key in a header, amounts in minor units.
  region: intl
  category: accounting
  icon: acme
  docsUrl: https://developer.acme.example/invoices
credentials:
  ACME_API_KEY:
    required: true
    secret: true
    description: Settings → Developers → API keys. Needs the invoices:read scope.
transport:
  type: http
  baseUrl: https://api.acme.example/v1
  headers:
    Accept: application/json
  timeout: 30s
auth:
  type: apiKey
  in: header
  name: Authorization
  value: Bearer {{env.ACME_API_KEY}}
healthcheck:
  tool: acme_invoices_list
  params:
    limit: 1
instructions: |-
  **Setup.** Create an API key under Settings → Developers with the
  `invoices:read` scope and set `ACME_API_KEY`. Keys are not scoped to a
  subsidiary; the key sees every company on the account.

  **Amounts are in minor units.** `total: 129900` is 1 299,00 in the
  invoice's own currency, which is in `currency`. Do not divide by 100
  without reading `currency` first: JPY has no minor unit.

  **Paging** is cursor based. The response carries `next_cursor`; pass
  it back as `cursor`. There is no total count, so "how many invoices
  are there" cannot be answered without walking the whole list.

  **Dates** are ISO 8601 in UTC. `issued_at` is when the invoice was
  raised, `due_at` is when payment is due, and a paid invoice also has
  `paid_at`. Filtering is on `issued_at` only.

  **Rate limit** is 100 requests per minute per key, answered with 429
  and a `Retry-After` header. Pace bulk work.

  **Out of scope here.** Creating, amending and voiding invoices are
  deliberately not exposed: this adapter is read-only so that it can be
  installed without a change-approval conversation.
tools:
  - name: acme_invoices_list
    description: >-
      List invoices newest first, optionally narrowed to a customer, a
      status or an issue-date range. Returns a cursor for the next page.
    input:
      type: object
      properties:
        customer_id:
          type: string
          description: Restrict to one customer's invoices.
        status:
          type: string
          enum: [draft, open, paid, void]
          description: Restrict to one status.
        issued_from:
          type: string
          description: Earliest issue date, ISO 8601 (2026-01-01).
        limit:
          type: integer
          default: 25
          description: Rows per page, 1 to 100.
        cursor:
          type: string
          description: The next_cursor from a previous call.
    annotations:
      readOnlyHint: true
      idempotentHint: true
    operation:
      method: GET
      path: /invoices
      query:
        customer_id: '{{params.customer_id}}'
        status: '{{params.status}}'
        issued_from: '{{params.issued_from}}'
        limit: '{{params.limit}}'
        cursor: '{{params.cursor}}'
    response:
      transform:
        jmespath: '{invoices: data[].{id: id, number: number, customer: customer.name, total: total, currency: currency, status: status, issued: issued_at, due: due_at}, next: next_cursor}'
      cache: 60s
```

Every `query` value is a whole-string placeholder, so an argument the
caller omitted produces no query parameter at all. `limit` has a schema
default, which the executor fills in before the template is resolved, so
a call with no `limit` still sends `limit=25`.

Validate it:

```bash
supermcp adapter validate --strict adapters/intl/acme-invoices
```

## What the validator enforces, and why

`supermcp adapter validate [--strict] [--format text|json] [paths...]`
checks the JSON Schema and then a set of named rules. Errors always
fail. Warnings fail only under `--strict`, which is what CI runs.

| Rule | Severity | Why |
|---|---|---|
| `slug-format`, `slug-dir`, `region-enum`, `region-dir`, `category-enum` | error | A file that disagrees with its path is found by one tool and missed by another. The region and category sets are closed so the catalogue filters mean something. |
| `slug-unique-catalog` | error | Two adapters with one slug cannot both be installed by name. |
| `metadata-required` | error | `name`, `description`, `icon` and `docsUrl` are what a person decides from. |
| `credential-name`, `credential-usage` | error | Credential names become environment-variable names. |
| `env-declared` | error | A `{{env.X}}` nobody declared is a value going on the wire that no one was asked for. |
| `env-unused` | warning | A declared credential nothing references is usually a conversion mistake. `usage: manual` says it is not. |
| `transport-baseurl`, `transport-dsn`, `transport-driver`, `transport-fields`, `transport-type` | error | A transport missing its destination cannot be called; a database field on an HTTP transport means the document was edited from the wrong template. |
| `auth-*` | error | Each auth type has fields it cannot work without, and fields that belong to another type. A field set on the wrong type is silently ignored at runtime, which is the worst outcome. |
| `auth-optional-consistency` | error | An adapter that claims to authenticate and has no required credential must say that unauthenticated calls are intended. |
| `healthcheck-empty`, `healthcheck-tool` | error | A healthcheck that names a tool that does not exist never runs. |
| `healthcheck-present` | warning | Without one there is no cheap way to tell whether a connector's credentials still work. |
| `tools-empty`, `tool-name-format`, `tool-name-unique` | error | Tool names are the model's whole vocabulary. |
| `tool-name-prefix` | warning | Unprefixed names collide across the catalogue. |
| `tool-name-unique-catalog` | warning | Sandbox and production variants of one API share names deliberately, and a server never mounts both. |
| `description-min-60` | warning | A model choosing between forty tools has only the descriptions. |
| `instructions-min-800` | warning | The instructions are where the operational knowledge lives. |
| `input-required`, `input-object`, `input-required-unknown` | error | A tool with no input schema, or one requiring a property it does not declare, cannot be called correctly. |
| `schema-subset` | error | See the subset list above. |
| `placeholder-syntax`, `placeholder-unknown`, `placeholder-namespace` | error | An unbalanced `{{`, an unknown namespace, or a `{{params.x}}` for an `x` the tool does not declare, is a request that is wrong at run time and detectable now. |
| `operation-method`, `operation-kind`, `operation-document`, `operation-statement`, `operation-tool`, `operation-static`, `operation-body-encoding` | error | The operation must be executable by the engine its transport selects. |
| `operation-body-get` | warning | Allowed, because some upstreams require it. |
| `jmespath-parses` | error | A transform that does not compile turns every successful call into a failure. |
| `sql-readonly` | warning | A statement that is not a read, on a tool the model has been told is safe, is the one mistake in this format with a blast radius. |
| `icon-https` | warning | |

The output is `file: severity: [rule] message`. `--format json` gives
the same findings as an array, for CI annotation.

Generate the catalogue index after changing anything:

```bash
supermcp adapter index -out adapters/index.gen.json
```

CI fails if the checked-in index does not match the adapters. `make
adapters` regenerates the converted corpus, validates it, rebuilds the
index and replays every cassette in one step.

## Record and replay

The validator proves an adapter is well formed. A cassette proves it
still works: that the request this build produces is the request that
was recorded, that the response still decodes, and that the JMESPath
still selects something from what the upstream actually returns.

Cassettes live in `cassettes/` beside the adapter, one file per tool.
One file per adapter would be rewritten wholesale whenever one tool was
re-recorded, so two people refreshing two tools would conflict and a
reviewer could not see which upstream had changed.

### Recording

Recording calls the real upstream with real credentials, so it refuses
to run without `--live`:

```bash
export ACME_API_KEY=...
supermcp adapter record --adapter acme-invoices --live
```

By default it records every tool whose arguments it can work out, in
this order of preference: arguments you passed, the arguments the
existing cassette was recorded with (so refreshing needs no arguments at
all), the healthcheck's arguments, or nothing when the tool requires
nothing. A tool that needs arguments and has none of these is skipped
with a message naming what it needs.

One tool with explicit arguments:

```bash
supermcp adapter record --adapter acme-invoices \
  --tool acme_invoices_list \
  --params '{"status":"paid","limit":2}' --live
```

Other flags: `--root` (default `adapters`), `--timeout` (default 30s),
`--max-body` (default 256 KiB — a cassette is committed and read by
people).

### How credentials are kept out

Three mechanisms, and the third is a check on the first two.

1. **Substitution.** Every credential value that had a value when the
   recording ran is replaced, wherever it appears in the request or the
   response, by a marker `SUPERMCP_CREDENTIAL_<NAME>`. The marker is
   upper-case ASCII and underscores, so it survives URL, form and JSON
   encoding unchanged and a replayed request still matches. Values of
   three characters or fewer are not substituted: they would match
   innocent text everywhere and are not secrets.
2. **Dropped headers.** Headers that carry a credential whole —
   `Authorization`, `Cookie`, `Set-Cookie` and the like — are never
   written to a file at all.
3. **Refusal.** `Save` refuses to write a file in which a credential
   value survived either step.

The recorder wraps the engine's HTTP client, so it sees the request
exactly as the engine sends it: rendered, authenticated and signed. The
authenticator itself is given the live client rather than the recorder —
a token endpoint's answer is a credential, and nothing that is not the
tool's own exchange belongs in a cassette.

Response headers are dropped except `Content-Type`, which decoding
depends on, and anything the tool lists in `response.exposeHeaders`. A
`Date` or a rate-limit counter would make every re-recording a diff
that tells a reviewer nothing.

A credential that was *unset* when the recording ran stays unset on
replay. Its absence shaped the request, and giving it a value later
would change the request.

### Replaying

```bash
supermcp adapter test                          # every adapter that has cassettes
supermcp adapter test --adapter acme-invoices  # one
```

The player holds no transport and therefore cannot reach the network
however it is wired. Each credential the recording had is set to its own
marker, so the request built here matches the recorded one without a
secret ever existing on the machine running the test. Auth schemes that
would fetch a token are skipped during replay, because the headers they
set are exactly the ones a cassette drops.

For each recorded exchange the replay checks that the status matches,
that the body still decodes, and — this is the assertion a
request-parity harness cannot make — that the tool's JMESPath still
selects something from the body the upstream actually returned. A
mismatch names the field that disagrees and what it disagrees with,
rather than reporting "no match".

Binary responses are not recorded.

### When to re-record

When the upstream changes its response shape, when you change a tool's
operation or transform, and on a schedule if you want to know that the
vendor has not quietly changed something. Re-recording needs no
arguments: the existing cassette supplies the ones it was recorded with.

49 cassettes ship, covering the adapters that need no credential.
Adapters that do need one are not covered offline in this release.

## After install: editing a tool in place

A connector's tools can be edited once it is installed, from the
connector screen or through the API (`docs/api.md`, "Managing tools").
An edit changes that one connector in that one workspace; the adapter
file and every other install of it are untouched. A tool can also be
added to a connector by hand, and only such a tool can be deleted.
Tools that came from the adapter can be disabled instead.

An edited tool is marked (`tools.edited_at`, with who edited it), so a
catalogue re-sync, when one exists, can leave it alone rather than
overwrite someone's change with the adapter's version.

The editor checks a definition with the same per-tool rules as the
validator above, plus a few that need the connector. One matters for
authors: on an HTTP connector, an `operation.path` that is an absolute
URL, or that starts with a placeholder filtered `raw`, must point at the
base URL's host or a host the connector's tools already use
(`operation-host`). A tool that sends requests to a second host is
fine in an adapter; an edit may not add a new one, because the request
carries the connector's credential.

## Converting from the v1 format

```bash
supermcp adapter convert -in <v1 dir> -out adapters -report report.json
```

The converter emits deterministic YAML, rewrites the five v1 placeholder
syntaxes into the one described above, and infers OAuth2 grants. An
unrecognised key in the v1 `authConfig` is reported as a **blocker** and
the adapter is not written, rather than being silently dropped. The
report lists every finding at `info`, `review` and `blocker` level;
`-fail-on-blocker` (on by default) makes the command exit non-zero when
any adapter was blocked.
