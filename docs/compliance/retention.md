# Retention

What this system keeps, for how long, what removes it, and which of it a
customer can change.

Read `data-flow.md` first for what each store holds.

## Summary

| Store | Default lifetime | What removes it |
|---|---|---|
| `audit_events` content | 365 days per workspace | The hourly retention sweep, which removes the content and leaves the row in the chain |
| `audit_events` rows | The longest window any workspace on the instance still asks for | The same sweep, as one contiguous cut across the whole stream; whole months past it are dropped as partitions |
| `tool_invocations`; what it keeps of a call is what the audit payload policy allows, which by default is the shape of the arguments and none of their values | **Indefinite** | Nothing. There is no sweep for this table. |
| `revisions` | Indefinite, deliberately | Deleting the workspace |
| `sessions` | Unusable after 12 hours idle or 30 days absolute | Deleted hourly, seven days after they became unusable |
| `oauth_codes`, `oauth_sessions`, `oauth_refresh_tokens` | Unusable after 5 minutes, 15 minutes and 30 days | Deleted hourly, a day after a code expires and a week after a refresh token does |
| `connector_auth_requests` | Unusable after its expiry | Each new consent request deletes those more than an hour past expiry |
| `sso_requests` | Single use, short expiry | Nothing deletes the rows |
| `login_lockouts` | One row per email address and per client address | Nothing. Counters are reset, rows are not removed. |
| `password_history` | The policy's depth, 5 by default | Trimmed on every password change |
| Blob results (`tool_blobs`, or Redis) | 15 minutes | Redis expiry, or a sweep every five minutes that deletes expired rows |
| Cached tool results | The adapter's declared duration, clamped to 24 hours | Expiry, or eviction |
| Rate-limit counters | The budget's window | Expiry |
| Data keys, master key references | Indefinite | Nothing, by design: a retired key must still open an old backup |

Everything keyed to a workspace is removed when the workspace row is
deleted, by foreign-key cascade. `audit_events` is the exception: its
`organization_id` carries no foreign key, so events survive the deletion
of the workspace they describe.

## The audit stream

This is the only store with a real retention mechanism, and it works in
two steps because one sequence is shared by every workspace on the
instance and a hole in it cannot be bridged.

### Step one: scrub

Each hour, for each workspace, events older than that workspace's window
have their `diff` and `payload` columns set to null and are marked
`scrubbed_at`. The row stays where it is in the chain.

This works because the chain hash covers a *digest* of the content
rather than the content itself. The digest stays, so the links either
side of the row are unaffected. `supermcp audit verify` then proves the
row's place in the sequence but reports that it could not check what the
row contained, and counts those rows separately rather than reporting the
chain as unqualified valid.

An event belonging to no workspace — an instance-level event — is never
scrubbed, because no workspace owns a window for it.

### Step two: cut

Rows are deleted only by a single contiguous cut across the whole
stream, at the longest window any workspace still asks for. The sweep
finds the newest row older than that window, records a `retention_cut`
anchor holding that row's hash, and deletes everything at or below it.

`audit_events` is partitioned by calendar month (UTC), so the cut does
not have to delete a whole month row by row. A month that ended before
the window and holds nothing above the cut is dropped as a partition; the
month the cut runs into loses its rows at or below the cut one by one.
Both happen in the same transaction as the anchor, so what goes is still
exactly the prefix at or below it, and a month holding a row under legal
hold is never dropped (the hold stops the cut below it). A hold placed
on an event below the cut while the cut is running makes it refuse, as
does an event written into a month it is dropping; so does not getting
the table for a moment to drop a month. In each case nothing is cut that
hour and the next sweep tries again. Months are created three ahead by an hourly
job; an event for a month that has no partition is kept in a default
partition and cut row by row.

Verification bridges the gap with that anchor: the first surviving row
records a predecessor that is no longer there, and the anchor says what
that predecessor hashed to. Without it, deleting the oldest rows would
be undetectable — the row that became the first would claim a
predecessor nobody could check. `supermcp audit verify` reports the cut
it started after (`retentionCut` in its JSON). A month dropped any other
way than by the sweep has no anchor and is reported as removed rows.

Deleting one workspace's rows out of the middle of the sequence is
therefore **not offered**. It would leave a hole no anchor can bridge.
A workspace whose own window is shorter than the instance-wide cut is
served by the scrub, which removes the content and keeps the link.

### Legal hold

A row marked `legal_hold` is never scrubbed, and a held row below the
cut stops the cut where it sits rather than being skipped, which would
tear the chain.

To place a hold on the calling workspace's events in a time window,
call `POST /api/v1/audit/legal-hold`, which needs `audit:export`. To
release it, call `DELETE` with the same body. Both are recorded in the
stream. A hold covers the events that exist when it is placed, so call
it again to cover events written since. No command places a hold on
instance-level events. For those, run an `UPDATE` against the database,
as described in `incident-response.md`.

## What a customer can change

| Setting | Where | Range |
|---|---|---|
| How long the audit trail is kept | `audit.retention_days` in the workspace's settings | Set with `PUT /api/v1/audit/retention` or on the audit screen (needs `audit:policy:manage`). Default 365 days; the API refuses anything outside 90 to 36 500. A value stored before the API existed is still raised to 90 or clamped to 36 500 when read. A missing or malformed value is read as the default, because too much history costs storage and too little costs an investigation that can no longer be run. |
| How much of a tool call the audit trail keeps | `PUT /api/v1/audit/policy`, or the audit screen | `none`, `metadata` (default), `masked`, `full`. Needs `audit:policy:manage`. The change is itself recorded, with the old and new values. |

Both are per workspace. A change to the payload policy takes effect
within 30 seconds; it applies to calls made after it, and does not reach
back and remove what earlier calls stored.

Nothing else is configurable. Session lifetimes, key lifetimes, blob and
cache lifetimes and the prune behaviour are fixed in the code.

## What is not deleted, and what that means

Four gaps are worth stating plainly because they will otherwise be found
by whoever is asked to answer a retention questionnaire.

**`tool_invocations` grows without bound.** Every tool call adds a row,
and nothing removes it. What the row holds is governed by the audit
payload policy — set it to `none` and the row carries no arguments and
no result — but an operator who needs a bound on how long the rows
themselves persist has to delete from this table. It carries
`(organization_id, created_at DESC)` and `(tool_id, created_at DESC)`
indexes, so a delete by age is cheap:

```sql
DELETE FROM tool_invocations WHERE created_at < now() - interval '90 days';
```

That statement has to run as the maintenance role: the application role
can insert into this table but a delete has no row-level-security path
that would reach another workspace's rows anyway.

**Spent OAuth material and dead sessions are removed hourly**, on the
same leader-elected sweep as the rest of the maintenance, with a grace
period so that "your session was ended at 14:02" is still answerable for
a week afterwards. A session row holds the digest of the cookie's
secret, not the secret, so what survives the grace period is the time,
the IP address and the user agent, not anything that could be replayed.

**Audit events outlive their workspace.** Deleting a workspace cascades
through every other table but not this one, which is the correct
behaviour for an audit trail and is worth saying out loud to anyone
asking about erasure.

## Backups

This software takes no backups. Postgres backups, their retention, their
encryption and their disposal are the operator's, and a backup is
unreadable without the master key. See `shared-responsibility.md`, and
follow `dr-runbook.md` to restore.

A restored backup must be verified before it is trusted:

```bash
supermcp audit verify     # the chain is intact end to end
supermcp keys verify      # every data key opens with the keys this process holds
```

## Erasure

There is no subject-erasure command. What the code makes possible, and
what a future release would use, is that the chain hash covers the
actor's id but not their display name, so a display name can be
pseudonymised without breaking verification, and the scrub already
removes an event's content while keeping its place. Neither is exposed
today.

In practice, erasing a person from this system means: delete the user
row, which cascades through memberships, sessions, identities,
provisioning records and password history; and decide separately what to
do about their name and address in `audit_events`, `revisions` and
`tool_invocations`.
