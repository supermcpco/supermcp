# Disaster recovery

How to bring an instance back after its database is lost, what it takes, and what
a restore cannot bring back. Read it before you need it, and rehearse it with the
steps under "Rehearsal".

**supermcp takes no backups.** It has no backup command, and neither the chart nor
Compose ships a job that schedules one. Back up Postgres with your own tooling:
`pg_dump` on a schedule you run, or your managed service's snapshots and
point-in-time recovery. This runbook restores from those backups.

## What you must already have

The restore fails without any one of these, so check them now:

- **A Postgres backup** that restores the whole database from one consistent
  snapshot. This runbook uses a custom-format `pg_dump`.
- **The master key the backup was sealed under, held outside the cluster.** With
  `local`, that is the base64 value of `ENCRYPTION_KEK` at the time of the backup,
  plus every older key its data keys may still be wrapped by. With `awskms`, it is
  access to the same KMS key in the same region, and the value of
  `SUPERMCP_KMS_DEPLOYMENT` if you set one. For a restore into another region,
  the key must be a multi-Region key with a replica there. "The master key a
  restore needs" below says why each part matters.
- **The configuration.** Keep a current `supermcp compliance config-snapshot`
  (secrets appear only as digests) so you can rebuild the same settings.
- **The audit spool volume, if you run `audit.onUnavailable: spool`.** It is a
  PersistentVolumeClaim. A backup of Postgres does not include it.

## What you can promise

| | What decides it |
|---|---|
| Recovery point for everything in Postgres | Your backup alone. A nightly `pg_dump` loses up to a day; continuous WAL archiving loses minutes. Connectors, credentials, members, keys and the audit trail are all in Postgres, so they all go back to the same moment. |
| Recovery point for the audit trail | Also your backup, with two exceptions that can do better. The spool keeps events written while the database was unreachable, if its volume survives. An audit destination (webhook, syslog, Splunk, OTLP) holds a copy of everything it accepted, which is usually less than a minute behind. |
| Recovery point for Redis | Nothing to recover; see "Losing Redis". |
| Recovery time | The time to restore Postgres, plus the checks below, plus a few seconds for a pod to pass `/readyz`. `keys verify` makes one unwrap per data key (a KMS request each with `awskms`). `audit verify` reads every event, so its time grows with the size of the trail. The rehearsal measures both on your data. |

You cannot promise any of these:

- Audit events that never reached the database during an outage, unless the spool
  was on. With the default `degrade`, a batch the database refuses is logged
  (`audit append failed`, with a count) and lost. The trail itself shows only a
  quiet period.
- Revocations made after the backup was taken. "What a restore undoes" covers this.
- A restore into another AWS region under `awskms` with a single-Region key. The
  key exists in one region only. A multi-Region key works; see "The master key a
  restore needs".

## Restoring from a dump

Run the `supermcp` commands with the pods' environment (`DATABASE_URL`,
`SUPERMCP_MAINT_DATABASE_URL`, the master key settings) from a host that can
reach Postgres, using the binary from the release archive. Once a replica is up,
`kubectl exec deploy/<release> -- /supermcp ...` works too; the image has no
shell. With Compose, use `docker compose exec supermcp /supermcp ...`.

1. **Stop serving.** Run `kubectl scale deploy/<release> --replicas=0`. If
   `autoscaling.enabled` is true, the HPA does not scale a Deployment up from zero,
   so you will scale it back by hand in step 8. With Compose, run
   `docker compose stop supermcp`. Nothing then writes to a half-restored
   database or replays spooled events before you decide about them.
2. **Keep the spool files**, if the spool is on. See "The audit spool".
3. **Prepare an empty database.** `pg_dump` does not carry roles, because roles
   belong to the Postgres cluster rather than to one database. On a new cluster,
   create two roles before you restore. The first is the user that owned the
   schema, under the same name and with the attributes it had. That is the user in
   `SUPERMCP_MAINT_DATABASE_URL`, or in `DATABASE_URL` if that is unset, and the
   chart expects it to have `BYPASSRLS`. The second is the role the migrations
   made. To find the owner's name, run
   `pg_restore -f - supermcp.dump | grep -m1 'OWNER TO'`.

   ```sql
   CREATE ROLE <owner> LOGIN BYPASSRLS PASSWORD '<new password>';
   CREATE ROLE supermcp_app NOLOGIN NOBYPASSRLS NOINHERIT;
   GRANT supermcp_app TO <owner>;  -- and to the user in DATABASE_URL, if different
   CREATE DATABASE supermcp OWNER <owner>;
   ```

   Without the owner, the restore stops at the first `OWNER TO`. Without the
   membership, every pod fails at boot with `SET ROLE supermcp_app`.
4. **Restore** as the owner or as a superuser, into the new database:

   ```bash
   pg_restore --exit-on-error --single-transaction --dbname="$MAINT_URL" supermcp.dump
   ```

5. **Check the keys:** `supermcp keys verify`. It must end with `every data key
   opens`. A key listed with `this process holds no key with that reference` needs
   a master key you have not supplied; one listed with `message authentication
   failed` was given the wrong key under the right reference. Fix either (next
   section) before going on: a replica with the wrong key still passes `/readyz`,
   then fails every stored credential and every OAuth token, because the token
   signing keys are sealed too.
6. **Check the audit trail:** `supermcp audit verify -format json > verify.json`.
   Keep the file, because it records the restored head (`lastSeq`). See "The audit
   trail after a restore".
7. **Check the schema:** `supermcp migrate -status`. If the dump predates your
   current version, it shows a lower version than the binary expects. Pods stay
   unready until the migrations run, and step 8 runs them.
8. **Serve again.** If the database moved, update the Secret named by
   `database.existingSecret` first. Then run `helm upgrade <release>
   charts/supermcp --reuse-values`. That runs the migration Job before the new
   pods, and it sets the replica count back to `replicaCount`. With autoscaling,
   run `kubectl scale deploy/<release> --replicas=<minReplicas>` after the Job
   completes. With Compose, run `docker compose start supermcp`, which migrates on
   start.
9. **Watch the replicas come back.** A pod is ready once `/readyz` sees the
   database at the right schema. Nothing else needs restoring. Each replica's
   cache-invalidation listener connects on `SUPERMCP_MAINT_DATABASE_URL`, and
   `supermcp_cache_listener_connected` goes to 1; if it stays 0, see
   `docs/operations.md`, "Cache invalidation". There is no lasting leader: each
   background sweep takes a Postgres advisory lock for one run, so the first
   export runs within a minute, the first checkpoint within ten, retention within
   the hour.
10. **Deal with what the restore undid.** See the next sections.

## The master key a restore needs

Each data key row names the master key that wraps it in `data_keys.kek_ref`, and
only a key with exactly that reference opens it. `SELECT DISTINCT kek_ref FROM
data_keys` lists what a dump needs.

- **`local` through `ENCRYPTION_KEK`** has the reference `local:env:ENCRYPTION_KEK`.
  The chart and Compose always load the key this way. Set `ENCRYPTION_KEK` to the
  value that was active when the dump was taken.
- **`local` through `ENCRYPTION_KEK_FILE`** has the reference
  `local:file:<path>`. The same key at another path is a different reference.
- **`awskms`** has the reference `awskms:<region>/<key id>`, or `awskms:<ARN>` when
  `SUPERMCP_KMS_KEY_ID` is an ARN. In the same region, use the same spelling of
  the key. Unwrapping also checks the encryption context, which includes
  `SUPERMCP_KMS_DEPLOYMENT`: set it as it was, or leave it unset if it was. KMS
  refuses to decrypt if an alias now points at a different key from the one that
  wrapped the data keys, or if the key is disabled or pending deletion.

**A restore into another region** works only with a multi-Region key. Its replicas
share the key id (`mrk-` and the same characters) and the key material, in the
same account, and each can decrypt what the others encrypted. A single-Region key
cannot be used outside its region, and nothing supermcp can do changes that. For
the restore:

- Create a replica of the key in the new region before you need it, and grant the
  new region's pods `kms:Encrypt` and `kms:Decrypt` on it.
- Set `SUPERMCP_KMS_REGION` to the new region, and name the replica the way the old
  setting named the key: the same `mrk-` key id, the replica's ARN (which differs
  only in the region), or the same alias name. An alias is not replicated, so
  create it in the new region and point it at the replica.
- Keep `SUPERMCP_KMS_DEPLOYMENT` exactly as it was: the same value, or unset if it
  was unset. It is part of what every data key was wrapped with.

A data key whose reference names another region is then opened with the key
configured here, when the two differ in the region alone. `keys verify` checks
them the same way. New data keys are wrapped under the new region's reference.
`keys rotate-kek` moves the old ones onto it too, which is optional.

**A dump taken before a master key rotation** carries data keys wrapped by the key
you rotated away from. Name that key in `SUPERMCP_KEK_PREVIOUS`, which may decrypt
and never seals. A bare base64 value takes the reference
`local:env:ENCRYPTION_KEK`. For any other reference, write `<reference>|<base64>`.
Then run `supermcp keys rotate-kek`, `keys verify` again, and remove the old key.
`SUPERMCP_KEK_PREVIOUS` accepts only local keys: data keys wrapped by a KMS key
other than the configured one (or its replica in another region) open only by
pointing the instance at that key. That includes a key an alias pointed at before
it was moved.

Keep every master key for as long as you keep a backup sealed under it. Data keys
retired by `keys rotate-dek` are never deleted, so an old dump still needs the key
that wrapped them.

## What a restore undoes

Everything done after the backup is gone. Find it in an audit destination or a
spool file, and do it again:

- **Revocations come back to life.** Sessions ended, API keys revoked, members
  deactivated or removed, SCIM deactivations and rejected OAuth clients all revert.
  Search the destination for `session.revoke`, `apikey.revoke`,
  `member.deactivate`, `member.remove`, `scim.user.deactivate`,
  `oauth.client.reject`, `service_account.delete` and `signing_key.rotate` with
  `revoked: true` after the backup time, and repeat each one. A revoked signing
  key is back in the key set until you run `keys rotate-signing -revoke` again.
  Also ask each identity provider to push its SCIM state again.
- **New credentials vanish.** API keys created, rotated or re-issued after the
  backup are unknown and get 401. Service account secrets rotated after the backup
  revert to the old secret. Tell their owners.
- **Upstream tokens may be stale.** A connector whose vendor rotates refresh tokens
  may hold one the vendor has already replaced. Its calls fail until someone
  re-authorises it.
- **Key rotations after the backup revert** (see the section above).

## The audit spool

With `audit.onUnavailable: spool`, a replica that cannot write an event puts it in
`SUPERMCP_AUDIT_SPOOL_DIR` as an NDJSON segment. Each line holds `at` and `event`.
When the database takes events again, the replica replays the segments in order
before anything newer. A replica that starts and finds segments logs `the audit
spool holds events from an earlier run` and replays them.
`supermcp_audit_spool_depth` falls to zero when it is done.

- **The database came back by itself.** Do nothing, and keep the claim until the
  depth is zero.
- **The database was restored.** Copy the segments off the volume before any
  replica starts (step 2). The image has no shell, so mount the claim in a
  throwaway pod that has one and copy the `*.ndjson` files out. Then decide:
  - **Replay them into the restored trail.** This is the usual choice. It is the
    only record of the outage window. Start the replicas and they replay the files.
    A replayed event is stamped when it reaches the chain, and carries
    `meta.spooled: true` and `meta.occurredAt` with the real time.
  - **Keep them out.** Do this when you restored to a point before something you
    do not trust. Move the files off the volume before starting replicas. Keep the
    copies with the incident record, because they are then the only copy.
- The chart's claim is `ReadWriteMany` and shared by every replica, so two replicas
  can adopt the same segment. An event that appears twice with identical content
  was replayed twice. A replay interrupted between the write and the file's removal
  duplicates the same way. The chain is still intact.

## The audit trail after a restore

`audit verify` walks the chain to its head, with the signed checkpoints written
every ten minutes and the anchors that bridge retention cuts.

- **`the chain is intact`** proves the restored trail is unbroken up to its head.
  It cannot prove that nothing came after the head. The events between the backup
  and the failure are simply absent. Their only copies are in your audit
  destinations and in spool files.
- **`a checkpoint was signed at row N, but the stream ends at row M; rows were
  removed from the head`** means `audit_anchors` and `audit_events` came from
  different snapshots, or rows were deleted. A whole-database `pg_dump` cannot
  cause it. Do not serve from that database; restore both tables together.
- **Any other break** names a row. Treat it as tampering until shown otherwise; see
  `incident-response.md`.

The event sequence is restored with the dump, so new events reuse sequence
numbers after `lastSeq`. Each destination resumes from the cursor it had at backup
time, so it may first receive some events again with their original hashes. Then
it receives new events whose sequence numbers it already saw from the lost timeline.
Give each destination's owner the restore time and `lastSeq` from `verify.json`.
Events above that number, stamped before the restore, are the lost timeline.

## Losing Redis

Redis holds rate-limit counters, cached tool results and result blobs that live
15 minutes. Pods start without it, and a new, empty Redis at the same address is
a complete recovery.

- **Rate limits** fall back to per-replica budgets: the instance's budget divided
  by `SUPERMCP_EXPECTED_REPLICAS`, which the chart sets to `replicaCount`, not the
  HPA's current count. `SupermcpRateLimiterDegraded` fires, and the limiter
  returns to Redis by itself once Redis answers.
- **Cached tool results** are kept per replica meanwhile.
- **Result blobs** go to Postgres instead. One that was only in Redis answers 404.

## Rehearsal

Prove the runbook on a scratch host in under an hour, and find out whether the
escrowed key and the backup really open before an outage asks.

1. **Take a dump** of a staging instance, or of production if your data-handling
   rules allow it on the scratch host:
   `pg_dump --format=custom --file=supermcp.dump "$MAINT_URL"`.
2. **Start a scratch Postgres 17:**
   `docker run -d --name dr -e POSTGRES_PASSWORD=scratch -p 127.0.0.1:55432:5432 postgres:17`.
   Create the roles and the database as in step 3, using the password `scratch`,
   then restore through the container:
   `docker exec -i dr pg_restore -U postgres --exit-on-error --single-transaction --dbname=supermcp < supermcp.dump`.
3. **Fetch the master key from the escrow**, not from the cluster, and export it.
   This is the step that proves the escrow works.
4. **Point the binary at the scratch database.** Set `DATABASE_URL` and
   `SUPERMCP_MAINT_DATABASE_URL` to
   `postgres://<owner>:scratch@127.0.0.1:55432/supermcp?sslmode=disable`. Then time
   `supermcp keys verify`, `supermcp audit verify` and `supermcp migrate -status`.
   Also run `keys verify` once with a wrong key, so you know what a failure looks
   like: every data key is listed with `message authentication failed`.
5. **Turn off outbound work before serving.** The dump carries production's audit
   destinations, and a scratch replica would deliver to them. Run
   `UPDATE audit_exporters SET enabled = false;`, then start the binary with
   `SUPERMCP_PUBLIC_URL=http://localhost:8080 supermcp serve`, check that
   `curl -fsS localhost:8080/readyz` answers, and sign in with an account you know.
   Do not call tools. Their connectors point at real upstreams.
6. **Write down** how long the restore and the two verifications took. Those times
   are your recovery time on this data. Then destroy the container and the copy of
   the dump.

## Checklist

- [ ] Replicas at zero; spool files copied off the volume
- [ ] Schema owner and `supermcp_app` created and granted; dump restored in one transaction
- [ ] Master key set as it was at backup time; older keys in `SUPERMCP_KEK_PREVIOUS`
- [ ] `supermcp keys verify` ends with `every data key opens`
- [ ] `supermcp audit verify -format json` intact; `lastSeq` recorded
- [ ] `helm upgrade --reuse-values` (migration Job, then pods); replicas ready
- [ ] `supermcp_cache_listener_connected` is 1 on every replica
- [ ] Spool replayed, or kept out and recorded
- [ ] Revocations and rotations after the backup repeated; owners of lost keys told
- [ ] Audit destinations told the restore time and `lastSeq`
