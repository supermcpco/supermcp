# Access review

Who can do what, in a form a reviewer can sign.

```
supermcp compliance access-review [-org <id|slug>] [-dormant-days 90] [-format text|json|csv] [-out file]
```

It reads the database and writes nothing. It defaults to every
workspace, because a reviewer asked to attest to access has to be shown
all of it, and a report that covered one workspace by default would be a
report that quietly omitted the others.

Two other reports sit beside it and are documented here too:
`crypto-report` and `config-snapshot`.

## What a principal's entry says

Four kinds of principal appear.

| Kind | What it is | Where its permissions come from |
|---|---|---|
| `user` | A person who is a member of the workspace | Their own role bindings |
| `service_account` | A non-human principal with client credentials | Its own role bindings |
| `idp_group` | A provisioned group a binding can name | Everybody the provider puts in it |
| `api_key` | A credential | The principal it acts as, narrowed by its scopes |

Each entry carries the principal's status, when it gained access to this
workspace, when it was last used and what that use was, every binding it
holds with the scope and expiry of each, and the permission set it adds
up to right now.

The effective set is computed the way `authz.Evaluate` computes it: an
expired binding grants nothing, a binding scoped to one server, connector
or tool does not widen the workspace, and the wildcard expands to the
whole closed set of 35 permissions. A credential carrying any scope and
not `mcp:org` comes down to reading and invoking tools, whatever its
owner holds.

This is deliberately *not* `authz.Evaluator.EffectivePermissions`, which
serves the session bootstrap and the admin screens. That method does not
filter expired bindings, so a person whose only grant expired last week
still sees the permissions on screen that the evaluator would refuse. The
review agrees with the decision rather than with the screen; where the
two disagree, the decision is what happens.

## Findings

A finding is never a failure on its own. Every one of these is lawful in
some instance and wrong in most, which is why the report raises them and
does not judge them.

| Code | What it means | What a reviewer does |
|---|---|---|
| `privileged-binding-never-expires` | The binding carries a permission that changes who can do what, what is recorded, what leaves the instance, or that destroys something — and it never expires | Justify it, or put an expiry on it |
| `privileged-credential` | An API key reaches a privileged permission through the principal it acts as | Narrow the key's scopes, or accept it |
| `expired-binding` | The binding grants nothing and is still on the record | Remove it, so the record says what is true |
| `no-binding` | A member or service account holds nothing at all | Usually an account somebody forgot to remove |
| `dormant` | Nothing has used it within the window | Ask whether it is still needed |
| `never-used` | It was created before the window and has never been used | The same question, more sharply |
| `disabled-principal-still-bound` | The account is disabled or deactivated and still holds bindings | The grants come back with the account |
| `secret-never-rotated` | No rotation of this service account's secret appears in the audit stream | Rotate it, or record why not |
| `credential-never-expires` | An API key with no expiry | It stays valid until somebody revokes it |
| `binding-for-a-principal-that-is-not-there` | A binding naming a principal this workspace does not have | The residue of a deletion that did not finish |

The privileged set is: `*`, `org:delete`, `org:members:manage`,
`org:settings:manage`, `org:billing:manage`, `roles:manage`,
`apikeys:org:manage`, `serviceaccounts:manage`, `idp:manage`,
`scim:manage`, `audit:export`, `audit:policy:manage`,
`approvals:decide`, `dlp:manage`, `revisions:rollback`,
`secrets:rotate`, `tools:invoke:destructive`,
`connectors:auth:update`, `connectors:delete`, `servers:delete`.

## Formats

`text` is grouped by workspace and then by principal, written with fixed
indentation rather than aligned columns: aligned columns look better and
diff worse, because one long address changes the width of every line in
the block.

`json` is the whole structure, for a pipeline.

`csv` is one row per principal and binding, which is the shape a reviewer
signs: one line to look at, one decision to record beside it. A principal
holding no binding still gets a row, because "this person has no access"
is a thing a review has to state rather than omit. The header is fixed
and columns are only ever added at the end, so a spreadsheet built on one
quarter's export still opens the next one.

## What this report cannot see

- A group binding reaches whoever the identity provider puts in that
  group. The report lists the group's members as SCIM last provisioned
  them, which is this instance's copy and not the provider's.
- Last use is the newest of a session, an API key's last use, a service
  account's last use and a tool call. A principal that only ever read
  through the admin API with a session it kept alive leaves a session
  time and nothing more specific.
- `secret-never-rotated` is read from the audit stream, which retention
  cuts. It means no rotation is recorded in the window this instance
  still holds, not that none ever happened.
- Nothing here is an attestation. There is no sign-off workflow, no
  record of who reviewed what, and no history of previous reviews. The
  CSV is the artefact a reviewer signs, and keeping the signed copy is
  the operator's.
- Nothing prevents one person holding every role. Separation of duties is
  expressible here and is not enforced.

## `supermcp compliance crypto-report`

```
supermcp compliance crypto-report [-format text|json] [-out file]
```

Every data key, its scope, its status, the master key that wraps it, its
age and whether it opens; the token signing keys and where each is in its
rotation; the sealed columns and how many rows each holds; and what this
instance does not encrypt at all.

The master keys are optional. With `ENCRYPTION_KEK` or
`SUPERMCP_KEK_PROVIDER` set as the gateway has them, each data key is
opened with the master key its own row names — never with every key in
turn — and the report says whether it opened. Without them the keys are
still listed and the report says it did not check, which is a weaker
claim honestly made rather than a command that refuses. `supermcp keys
verify` is the check that leaves by the error path; this is the report.

The sealed columns are found in the schema — a `bytea` column whose name
ends in `_enc` — rather than listed in the report's source. A list would
go stale the first time a feature sealed a new column, and it would go
stale silently. A column the schema has and the report has no description
for is printed with that said plainly.

The section that says what is **not** encrypted is the half an assessor
is owed, and it is not abbreviated: the database as a whole, tool-call
arguments and results in the clear in `tool_invocations`, audit diffs and
payloads in the clear in `audit_events`, connector transport and auth
configuration, and the traffic either side of the gateway. Where a count
makes the statement concrete, the count is there.

## `supermcp compliance config-snapshot`

```
supermcp compliance config-snapshot [-format text|json] [-out file]
```

The settings that decide behaviour, so an assessor can be shown the shape
of an instance without being given it.

Three sections: the effective settings this process resolved after
defaults; the environment an operator actually set; and the settings held
in the database, per instance and per workspace. Beside them are the
populations — workspaces, accounts, connectors, tools, events — because
an assessor reads a gateway with two connectors differently from one with
four hundred.

Secrets become digests. A connection string keeps its scheme, host,
database and parameters and loses only its password, because whether the
connection is encrypted is part of the configuration and the password is
not. A digest is not a safe way to publish a value that could be guessed
from a short list, so only key material, the passwords inside connection
strings and values whose setting name says they are secret are digested;
everything else is printed as it is.

A `SUPERMCP_` variable this binary does not read is reported as set and
having no effect. That is the most expensive kind of misconfiguration:
a setting that looks applied and is not.

The snapshot describes the process that ran the command. A gateway
replica started with a different environment is a different
configuration, and nothing here would show it.
