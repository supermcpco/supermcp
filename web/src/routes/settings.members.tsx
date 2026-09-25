import { useId, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  invitesCreateMutation,
  invitesListOptions,
  invitesListQueryKey,
  invitesRevokeMutation,
  listRolesOptions,
  membersListOptions,
  membersListQueryKey,
  membersRemoveMutation,
  membersUpdateMutation,
} from "../api/@tanstack/react-query.gen";
import type { InviteDto, MemberDto, RoleDto } from "../api/types.gen";
import { useSession } from "../lib/session";
import { Badge, Loading, SignInFirst } from "../lib/ui";
import { status } from "../lib/errors";
import {
  defaultExpiryDays,
  expiryDays,
  maxExpiryDays,
  memberError,
  notReady,
  relativeTime,
  sourceLabel,
} from "../lib/members";

export const Route = createFileRoute("/settings/members")({
  component: Members,
});

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

/** A change to one member waiting for the administrator to confirm it. */
type Pending =
  | { userId: string; kind: "role"; roleId: string }
  | { userId: string; kind: "deactivate" | "reactivate" | "remove" };

function Members() {
  const { signedIn, can, loading } = useSession();
  const canRead = can("org:read");
  const canManage = can("org:members:manage");
  const qc = useQueryClient();

  const members = useQuery({ ...membersListOptions(), enabled: signedIn && canRead, retry: false });
  const roles = useQuery({ ...listRolesOptions(), enabled: signedIn && canManage, retry: false });

  const [pending, setPending] = useState<Pending | null>(null);
  const [rowError, setRowError] = useState<{ userId: string; text: string } | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: membersListQueryKey() });
  const settle = {
    onSuccess: async () => {
      setPending(null);
      setRowError(null);
      await refresh();
    },
  };
  const update = useMutation({
    ...membersUpdateMutation(),
    ...settle,
    onError: (e, v) => setRowError({ userId: v.path.userId, text: memberError(e) }),
  });
  const remove = useMutation({
    ...membersRemoveMutation(),
    ...settle,
    onError: (e, v) => setRowError({ userId: v.path.userId, text: memberError(e) }),
  });

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;
  if (!canRead) return <Text>You do not have permission to see the members of this workspace.</Text>;

  // A role that carries everything can only be handed out by somebody who
  // holds everything; the server refuses anybody else, so the screen does
  // not offer it.
  const assignable = (roles.data?.roles ?? []).filter((r) => can("*") || !r.permissions.includes("*"));
  const list = members.data?.members ?? [];

  const confirm = (p: Pending) => {
    if (p.kind === "role") update.mutate({ path: { userId: p.userId }, body: { roleId: p.roleId } });
    else if (p.kind === "remove") remove.mutate({ path: { userId: p.userId } });
    else
      update.mutate({
        path: { userId: p.userId },
        body: { status: p.kind === "deactivate" ? "deactivated" : "active" },
      });
  };

  return (
    <div className="grid gap-8">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Members
        </Text>
        <Text>
          Everybody who can sign in to this workspace, what they hold and how they sign in. Deactivating someone ends
          their sessions and API keys at once; removing them also takes away every role they hold here.
        </Text>
        {!canManage && (
          <Text variant="secondary">You can see the members; changing them needs the permission to manage members.</Text>
        )}
      </div>

      <section className="grid gap-3" aria-labelledby="members-heading">
        <Text as="h2" variant="heading3" id="members-heading">
          People
        </Text>
        {members.isPending && <Loading />}
        {members.error && (
          <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
            <Text>{status(members.error) === 501 ? notReady : memberError(members.error)}</Text>
          </div>
        )}
        {members.isSuccess && list.length === 0 && <Text variant="secondary">Nobody is a member yet.</Text>}
        {list.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <caption className="sr-only">Members of this workspace</caption>
              <thead>
                <tr className="border-b border-kumo-line">
                  {["Name", "Email", "Status", "Roles", "Last sign-in", "Signs in with"].map((h) => (
                    <th key={h} scope="col" className="py-2 pr-4">
                      <Text as="span" variant="secondary">
                        {h}
                      </Text>
                    </th>
                  ))}
                  {canManage && (
                    <th scope="col" className="py-2">
                      <Text as="span" variant="secondary">
                        Actions
                      </Text>
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {list.map((m) => (
                  <MemberRow
                    key={m.userId}
                    member={m}
                    canManage={canManage}
                    roles={assignable}
                    pending={pending?.userId === m.userId ? pending : null}
                    error={rowError?.userId === m.userId ? rowError.text : null}
                    busy={update.isPending || remove.isPending}
                    onAsk={(p) => {
                      setRowError(null);
                      setPending(p);
                    }}
                    onConfirm={confirm}
                    onCancel={() => {
                      setPending(null);
                      setRowError(null);
                    }}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {canManage && <InviteSection roles={assignable} rolesLoading={roles.isPending} />}
    </div>
  );
}

function displayName(m: MemberDto) {
  return m.name || m.email;
}

function MemberRow({
  member: m,
  canManage,
  roles,
  pending,
  error,
  busy,
  onAsk,
  onConfirm,
  onCancel,
}: {
  member: MemberDto;
  canManage: boolean;
  roles: RoleDto[];
  pending: Pending | null;
  error: string | null;
  busy: boolean;
  onAsk: (p: Pending) => void;
  onConfirm: (p: Pending) => void;
  onCancel: () => void;
}) {
  const who = displayName(m);
  const orgRoles = m.roles.filter((r) => r.scopeKind === "org");
  // The select shows the member's one organisation-wide role. Somebody
  // holding several (or none) starts on the prompt, and picking a role
  // replaces the manually granted ones.
  const current = orgRoles.length === 1 ? orgRoles[0].roleId : "";
  const lifecycleLocked = m.isSelf || m.scimManaged;
  const noteId = `member-note-${m.userId}`;
  const note = m.isSelf
    ? "This is you. Another administrator has to change your membership."
    : m.scimManaged
      ? "Managed by your identity provider: deactivate or remove them there. The role can still be changed here."
      : null;
  const active = m.status === "active";
  const columns = canManage ? 7 : 6;

  return (
    <>
      <tr className="border-b border-kumo-line align-top">
        <td className="py-2 pr-4">
          <Text as="span" bold>
            {m.name || "—"}
          </Text>
          {m.isSelf && (
            <Text as="span" variant="secondary">
              {" "}
              (you)
            </Text>
          )}
        </td>
        <td className="py-2 pr-4">
          <Text as="span">{m.email}</Text>
        </td>
        <td className="py-2 pr-4">
          <Badge>{active ? "active" : "deactivated"}</Badge>
        </td>
        <td className="py-2 pr-4">
          <ul className="flex flex-wrap gap-1" aria-label={`Roles of ${who}`}>
            {m.roles.map((r) => (
              <li key={r.bindingId}>
                <Badge>
                  {r.roleName}
                  {r.scopeKind !== "org" ? ` · one ${r.scopeKind}` : ""}
                </Badge>
              </li>
            ))}
            {m.roles.length === 0 && (
              <li>
                <Text as="span" variant="secondary">
                  None
                </Text>
              </li>
            )}
          </ul>
        </td>
        <td className="py-2 pr-4 whitespace-nowrap">
          {m.lastSignInAt ? (
            <time dateTime={m.lastSignInAt} title={new Date(m.lastSignInAt).toLocaleString()}>
              <Text as="span" variant="secondary">
                {relativeTime(m.lastSignInAt)}
              </Text>
            </time>
          ) : (
            <Text as="span" variant="secondary">
              Never
            </Text>
          )}
        </td>
        <td className="py-2 pr-4">
          <Badge>{sourceLabel(m.source)}</Badge>
        </td>
        {canManage && (
          <td className="py-2">
            <div className="flex flex-wrap items-center gap-2">
              <select
                aria-label={`Role for ${who}`}
                className={selectClass}
                value={pending?.kind === "role" ? pending.roleId : current}
                disabled={m.isSelf || busy}
                aria-describedby={note ? noteId : undefined}
                onChange={(e) => {
                  const roleId = e.currentTarget.value;
                  if (roleId && roleId !== current) onAsk({ userId: m.userId, kind: "role", roleId });
                  else onCancel();
                }}
              >
                {current === "" && <option value="">{orgRoles.length > 1 ? "Several roles" : "Choose a role"}</option>}
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
              <Button
                disabled={lifecycleLocked || busy}
                aria-describedby={note ? noteId : undefined}
                onClick={() => onAsk({ userId: m.userId, kind: active ? "deactivate" : "reactivate" })}
              >
                {active ? "Deactivate" : "Reactivate"}
                <span className="sr-only"> {who}</span>
              </Button>
              <Button
                disabled={lifecycleLocked || busy}
                aria-describedby={note ? noteId : undefined}
                onClick={() => onAsk({ userId: m.userId, kind: "remove" })}
              >
                Remove<span className="sr-only"> {who}</span>
              </Button>
            </div>
            {note && (
              <p id={noteId} className="pt-1">
                <Text as="span" variant="secondary">
                  {note}
                </Text>
              </p>
            )}
          </td>
        )}
      </tr>
      {canManage && (pending || error) && (
        <tr className="border-b border-kumo-line">
          <td colSpan={columns} className="py-3">
            <div className="grid gap-3 rounded-md px-4 py-3 ring ring-kumo-line">
              {error && (
                <div role="alert">
                  <Text>{error}</Text>
                </div>
              )}
              {pending && (
                <>
                  <Text>{question(pending, who, roles)}</Text>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="primary" disabled={busy} onClick={() => onConfirm(pending)}>
                      {confirmLabel(pending, who)}
                    </Button>
                    <Button onClick={onCancel}>Cancel</Button>
                  </div>
                </>
              )}
              {!pending && error && (
                <div>
                  <Button onClick={onCancel}>Dismiss</Button>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function question(p: Pending, who: string, roles: RoleDto[]) {
  switch (p.kind) {
    case "role": {
      const name = roles.find((r) => r.id === p.roleId)?.name ?? p.roleId;
      return `Make ${who} a ${name}? This replaces the organisation-wide roles granted to them here; roles from your identity provider stay.`;
    }
    case "deactivate":
      return `Deactivate ${who}? Their sessions and API keys stop working at once, and they cannot sign in to this workspace until reactivated.`;
    case "reactivate":
      return `Reactivate ${who}? They can sign in again with the roles they hold.`;
    case "remove":
      return `Remove ${who} from this workspace? Every role they hold here is taken away and their sessions and API keys stop working. The audit trail keeps what they did.`;
  }
}

function confirmLabel(p: Pending, who: string) {
  switch (p.kind) {
    case "role":
      return `Change ${who}'s role`;
    case "deactivate":
      return `Yes, deactivate ${who}`;
    case "reactivate":
      return `Yes, reactivate ${who}`;
    case "remove":
      return `Remove ${who} for good`;
  }
}

/**
 * Inviting someone: the server hands back a link once, and this screen
 * shows it once. Nothing is emailed; the administrator sends it.
 */
function InviteSection({ roles, rolesLoading }: { roles: RoleDto[]; rolesLoading: boolean }) {
  const qc = useQueryClient();
  const ids = useId();
  const invites = useQuery({ ...invitesListOptions(), retry: false });

  const [email, setEmail] = useState("");
  const [roleId, setRoleId] = useState("");
  const [days, setDays] = useState(String(defaultExpiryDays));
  const [link, setLink] = useState<{ url: string; email: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: invitesListQueryKey() });
  const create = useMutation({
    ...invitesCreateMutation(),
    onSuccess: async (res) => {
      setLink({ url: res.url, email: res.invite.email });
      setCopied(false);
      setEmail("");
      setDays(String(defaultExpiryDays));
      setError(null);
      await refresh();
    },
    onError: (e) => setError(memberError(e)),
  });
  const revoke = useMutation({
    ...invitesRevokeMutation(),
    onSuccess: async () => {
      setError(null);
      await refresh();
    },
    onError: (e) => setError(memberError(e)),
  });

  const list = sortInvites(invites.data?.invites ?? []);

  return (
    <section className="grid gap-3" aria-labelledby="invite-heading">
      <Text as="h2" variant="heading3" id="invite-heading">
        Invite someone
      </Text>
      <Text variant="secondary">
        You get a link to send them. It works once, for that email address only, and no email is sent.
      </Text>

      {link && (
        <div className="grid gap-1.5 rounded-lg px-5 py-4 ring ring-kumo-line" role="alert">
          <Text as="h3" variant="heading3">
            Copy the invitation link for {link.email} now
          </Text>
          <Text variant="secondary">This link is shown once. Send it to the person yourself; no email is sent.</Text>
          <code className="overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]" data-testid="invite-url">
            {link.url}
          </code>
          <div className="flex items-center gap-2">
            <Button
              onClick={() =>
                void navigator.clipboard.writeText(link.url).then(
                  () => setCopied(true),
                  () => setCopied(false),
                )
              }
            >
              Copy
            </Button>
            <Button
              onClick={() => {
                setLink(null);
                setCopied(false);
              }}
            >
              Done
            </Button>
            <span aria-live="polite">
              <Text as="span" variant="secondary">
                {copied ? "Copied." : ""}
              </Text>
            </span>
          </div>
        </div>
      )}

      <form
        className="flex flex-wrap items-end gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
        aria-labelledby="invite-heading"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          create.mutate({ body: { email: email.trim(), roleId, expiresInDays: expiryDays(days) } });
        }}
      >
        <label className="grid flex-1 gap-1.5">
          <Text as="span">Email</Text>
          <Input
            type="email"
            required
            autoComplete="off"
            value={email}
            onChange={(e) => setEmail(e.currentTarget.value)}
            placeholder="ada@example.com"
          />
        </label>
        {/* Labelled by id rather than by wrapping: a wrapped control's
            value becomes part of its name, and "Role Choose a role" helps
            nobody. */}
        <div className="grid gap-1.5">
          <label htmlFor={`${ids}-role`}>
            <Text as="span">Role</Text>
          </label>
          <select
            id={`${ids}-role`}
            className={selectClass}
            required
            value={roleId}
            onChange={(e) => setRoleId(e.currentTarget.value)}
          >
            <option value="">{rolesLoading ? "Loading roles…" : "Choose a role"}</option>
            {roles.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
        </div>
        <div className="grid gap-1.5">
          <label htmlFor={`${ids}-days`}>
            <Text as="span">Link works for (days)</Text>
          </label>
          <Input
            id={`${ids}-days`}
            type="number"
            min={1}
            max={maxExpiryDays}
            required
            value={days}
            onChange={(e) => setDays(e.currentTarget.value)}
          />
        </div>
        <Button type="submit" variant="primary" disabled={create.isPending || !email.trim() || !roleId}>
          {create.isPending ? "Creating…" : "Create invitation link"}
        </Button>
      </form>

      {error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
        </div>
      )}

      <Text as="h3" variant="heading3">
        Invitations
      </Text>
      {invites.isPending && <Loading />}
      {invites.error && (
        <Text variant="secondary">
          {status(invites.error) === 501 ? notReady : memberError(invites.error)}
        </Text>
      )}
      {invites.isSuccess && list.length === 0 && <Text variant="secondary">No invitations yet.</Text>}
      <ul className="grid gap-2" aria-label="Invitations">
        {list.map((inv) => (
          <li
            key={inv.id}
            className="flex flex-wrap items-center justify-between gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
          >
            <div className="grid gap-1">
              <div className="flex flex-wrap items-center gap-2">
                <Text as="span" bold>
                  {inv.email}
                </Text>
                <Badge>{inv.status}</Badge>
              </div>
              <Text as="span" variant="secondary">
                {inv.roleName} · {inviteWhen(inv)}
              </Text>
            </div>
            {inv.status === "pending" && (
              <Button disabled={revoke.isPending} onClick={() => revoke.mutate({ path: { id: inv.id } })}>
                Revoke<span className="sr-only"> the invitation for {inv.email}</span>
              </Button>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Open invitations first, then the rest newest first. */
function sortInvites(list: InviteDto[]) {
  return [...list].sort((a, b) => {
    const open = Number(b.status === "pending") - Number(a.status === "pending");
    return open || b.createdAt.localeCompare(a.createdAt);
  });
}

function inviteWhen(inv: InviteDto) {
  switch (inv.status) {
    case "pending":
      return `expires ${relativeTime(inv.expiresAt)}`;
    case "accepted":
      return `accepted ${relativeTime(inv.acceptedAt)}`;
    case "revoked":
      return `revoked ${relativeTime(inv.revokedAt)}`;
    case "expired":
      return `expired ${relativeTime(inv.expiresAt)}`;
  }
}
