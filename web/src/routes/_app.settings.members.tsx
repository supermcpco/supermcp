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
  orgUpdateMutation,
  sessionQueryKey,
} from "../api/@tanstack/react-query.gen";
import type { InviteDto, MemberDto, RoleDto } from "../api/types.gen";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";
import { asSentence, details, message, status } from "../lib/errors";
import { toast } from "../components/shell/toast";
import { EmptyState, FormDialog, HeaderWithAction } from "../components/form-dialog";
import { Help, HeadingWithHelp } from "../components/help";
import { WithTooltip } from "../components/tooltip";
import {
  defaultExpiryDays,
  expiryDays,
  maxExpiryDays,
  invitedBy,
  memberError,
  notReady,
  relativeTime,
  sourceLabel,
} from "../lib/members";
import { LabelledInput } from "../components/labelled-input";
import { LabelledSelect } from "../components/select";

export const Route = createFileRoute("/_app/settings/members")({
  component: Members,
});

/** A change to one member waiting for the administrator to confirm it. */
type Pending =
  | { userId: string; kind: "role"; roleId: string }
  | { userId: string; kind: "deactivate" | "reactivate" | "remove" };

function Members() {
  const { signedIn, can } = useSession();
  const canRead = can("org:read");
  const canManage = can("org:members:manage");
  const qc = useQueryClient();

  const members = useQuery({ ...membersListOptions(), enabled: signedIn && canRead, retry: false });
  const roles = useQuery({ ...listRolesOptions(), enabled: signedIn && canManage, retry: false });

  const [pending, setPending] = useState<Pending | null>(null);
  const [rowError, setRowError] = useState<{ userId: string; text: string } | null>(null);
  const [inviting, setInviting] = useState(false);
  const [link, setLink] = useState<{ url: string; email: string } | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: membersListQueryKey() });
  const settle = async () => {
    setPending(null);
    setRowError(null);
    await refresh();
  };
  const who = (userId: string) => {
    const m = members.data?.members?.find((x) => x.userId === userId);
    return m ? displayName(m) : "The member";
  };
  const update = useMutation({
    ...membersUpdateMutation(),
    onSuccess: async (_, v) => {
      if (v.body.roleId) {
        const role = roles.data?.roles?.find((r) => r.id === v.body.roleId)?.name ?? "the new role";
        toast(`${who(v.path.userId)} now holds ${role}`);
      } else toast(`${who(v.path.userId)} ${v.body.status === "deactivated" ? "deactivated" : "reactivated"}`);
      await settle();
    },
    onError: (e, v) => setRowError({ userId: v.path.userId, text: memberError(e) }),
  });
  const remove = useMutation({
    ...membersRemoveMutation(),
    onSuccess: async (_, v) => {
      toast(`${who(v.path.userId)} removed from the workspace`);
      await settle();
    },
    onError: (e, v) => setRowError({ userId: v.path.userId, text: memberError(e) }),
  });

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

  const invite = canManage ? (
    <Button variant="primary" onClick={() => setInviting(true)}>
      Invite someone
    </Button>
  ) : null;

  return (
    <div className="grid gap-8">
      <HeaderWithAction action={invite}>
        <HeadingWithHelp
          heading={
            <Text as="h2" variant="heading">
              Members
            </Text>
          }
          help={
            <Help about="members">
              <Text>Deactivating someone ends their sessions and API keys at once, and they cannot sign in again until reactivated.</Text>
              <Text>Removing them also takes away every role they hold here. The audit trail keeps what they did.</Text>
            </Help>
          }
        />
        <Text>Everybody who can sign in to this workspace, and what they hold.</Text>
        {!canManage && (
          <Text variant="secondary">You can see the members; changing them needs the permission to manage members.</Text>
        )}
      </HeaderWithAction>

      {link && <InviteLink link={link} onDone={() => setLink(null)} />}

      <Workspace />

      <section className="grid gap-3" aria-labelledby="members-heading">
        <Text as="h3" variant="heading" id="members-heading">
          People
        </Text>
        {members.isPending && <Loading />}
        {members.error && (
          <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
            <Text>{status(members.error) === 501 ? notReady : memberError(members.error)}</Text>
          </div>
        )}
        {members.isSuccess && list.length === 0 && <EmptyState>Nobody is a member yet.</EmptyState>}
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

      {canManage && (
        <>
          <InviteDialog
            open={inviting}
            onOpenChange={setInviting}
            roles={assignable}
            rolesLoading={roles.isPending}
            onCreated={(created) => {
              setLink(created);
              setInviting(false);
            }}
          />
          <Invitations />
        </>
      )}
    </div>
  );
}

/**
 * The workspace's name, which everybody in it sees in the sidebar, and its
 * slug, which links and exports name it by and so never changes. Renaming
 * needs org:update; everybody else just reads it.
 */
function Workspace() {
  const { session, can } = useSession();
  const qc = useQueryClient();
  const org = session?.organization;
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const rename = useMutation({
    ...orgUpdateMutation(),
    onSuccess: async () => {
      toast("Workspace renamed");
      setOpen(false);
      setError(null);
      // Nothing on the server caches the name; asking for the session
      // again puts the new one in the sidebar.
      await qc.invalidateQueries({ queryKey: sessionQueryKey() });
    },
    onError: (e) => {
      const field = details(e).find((d) => d.location === "body.name")?.message;
      setError(asSentence(field || message(e)));
    },
  });

  if (!org) return null;
  const canRename = can("org:update");

  return (
    // Held with its card to the forms' width, so the Rename button sits by
    // the name it changes rather than at the far edge of a wide screen.
    <section className="grid max-w-3xl gap-3" aria-labelledby="workspace-heading">
      <HeaderWithAction
        action={
          canRename ? (
            <Button
              onClick={() => {
                setName(org.name);
                setError(null);
                setOpen(true);
              }}
            >
              Rename workspace
            </Button>
          ) : null
        }
      >
        <Text as="h3" variant="heading" id="workspace-heading">
          Workspace
        </Text>
      </HeaderWithAction>
      <dl className="grid gap-x-6 gap-y-1 rounded-lg px-5 py-4 ring ring-kumo-line sm:grid-cols-[max-content_1fr]">
        <dt>
          <Text as="span" variant="secondary">
            Name
          </Text>
        </dt>
        <dd>
          <Text as="span" bold>
            {org.name}
          </Text>
        </dd>
        <dt>
          <Text as="span" variant="secondary">
            Slug
          </Text>
        </dt>
        <dd className="grid gap-0.5">
          <code className="font-mono text-[0.9em]">{org.slug}</code>
          <Text as="span" variant="secondary">
            Links and exports name the workspace by its slug, so it stays the same when the name changes.
          </Text>
        </dd>
      </dl>
      {canRename && (
        <FormDialog
          open={open}
          onOpenChange={(next) => {
            setOpen(next);
            setError(null);
          }}
          size="base"
          title="Rename workspace"
          description="Everybody in the workspace sees the new name. The slug stays the same."
          submitLabel={rename.isPending ? "Renaming…" : "Rename workspace"}
          pending={rename.isPending}
          canSubmit={name.trim() !== org.name}
          error={error}
          onSubmit={() => {
            setError(null);
            rename.mutate({ body: { name } });
          }}
        >
          <LabelledInput
            label="Name"
            required
            autoComplete="off"
            value={name}
            onChange={(e) => {
              setName(e.currentTarget.value);
              setError(null);
            }}
          />
        </FormDialog>
      )}
    </section>
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
              <LabelledSelect
                label={`Role for ${who}`}
                hideLabel
                className="contents"
                value={pending?.kind === "role" ? pending.roleId : current}
                disabled={m.isSelf || busy}
                describedBy={note ? noteId : undefined}
                onChange={(roleId) => {
                  if (roleId && roleId !== current) onAsk({ userId: m.userId, kind: "role", roleId });
                  else onCancel();
                }}
                options={[
                  ...(current === "" ? [{ value: "", label: orgRoles.length > 1 ? "Several roles" : "Choose a role" }] : []),
                  ...roles.map((r) => ({ value: r.id, label: r.name })),
                ]}
              />
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
 * Inviting someone: the server hands back a link once, and the screen
 * shows it once, in the banner above the list after this dialog has
 * closed. Nothing is emailed; the administrator sends it.
 */
function InviteDialog({
  open,
  onOpenChange,
  roles,
  rolesLoading,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  roles: RoleDto[];
  rolesLoading: boolean;
  onCreated: (link: { url: string; email: string }) => void;
}) {
  const qc = useQueryClient();
  const ids = useId();

  const [email, setEmail] = useState("");
  const [roleId, setRoleId] = useState("");
  const [days, setDays] = useState(String(defaultExpiryDays));
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    ...invitesCreateMutation(),
    onSuccess: async (res) => {
      toast(`Invitation for ${res.invite.email} created`);
      onCreated({ url: res.url, email: res.invite.email });
      setEmail("");
      setDays(String(defaultExpiryDays));
      setError(null);
      await qc.invalidateQueries({ queryKey: invitesListQueryKey() });
    },
    onError: (e) => setError(memberError(e)),
  });

  return (
    <FormDialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        setError(null);
      }}
      title="Invite someone"
      description="You get a link to send them. It works once, for that email address only, and no email is sent."
      submitLabel={create.isPending ? "Creating…" : "Create invitation link"}
      pending={create.isPending}
      canSubmit={email.trim() !== "" && roleId !== ""}
      error={error}
      onSubmit={() => {
        setError(null);
        create.mutate({ body: { email: email.trim(), roleId, expiresInDays: expiryDays(days) } });
      }}
    >
      <LabelledInput
        label="Email"
        type="email"
        required
        autoComplete="off"
        value={email}
        onChange={(e) => setEmail(e.currentTarget.value)}
        placeholder="ada@example.com"
      />
      <LabelledSelect
        label="Role"
        required
        triggerClassName="w-full"
        value={roleId}
        onChange={setRoleId}
        options={[
          { value: "", label: rolesLoading ? "Loading roles…" : "Choose a role" },
          ...roles.map((r) => ({ value: r.id, label: r.name })),
        ]}
      />
      <div className="grid gap-1.5">
        <label htmlFor={`${ids}-days`} id={`${ids}-days-label`}>
          <Text as="span">Link works for (days)</Text>
        </label>
        <Input
          id={`${ids}-days`}
          aria-labelledby={`${ids}-days-label`}
          type="number"
          min={1}
          max={maxExpiryDays}
          required
          value={days}
          onChange={(e) => setDays(e.currentTarget.value)}
        />
      </div>
    </FormDialog>
  );
}

/** The link an invitation was created with, shown this once. */
function InviteLink({ link, onDone }: { link: { url: string; email: string }; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="grid gap-1.5 rounded-lg px-5 py-4 ring ring-kumo-line" role="alert">
      <Text as="h3" variant="heading">
        Copy the invitation link for {link.email} now
      </Text>
      <Text variant="secondary">This link is shown once. Send it to the person yourself; no email is sent.</Text>
      <code className="overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]">{link.url}</code>
      <div className="flex items-center gap-2">
        <WithTooltip tip="Copy the invitation link to the clipboard">
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
        </WithTooltip>
        <Button onClick={onDone}>Done</Button>
        <span aria-live="polite">
          <Text as="span" variant="secondary">
            {copied ? "Copied." : ""}
          </Text>
        </span>
      </div>
    </div>
  );
}

/** Every invitation, and the way to take back one that is still open. */
function Invitations() {
  const qc = useQueryClient();
  const invites = useQuery({ ...invitesListOptions(), retry: false });
  const [error, setError] = useState<string | null>(null);

  const revoke = useMutation({
    ...invitesRevokeMutation(),
    onSuccess: async (_, v) => {
      const email = invites.data?.invites?.find((i) => i.id === v.path.id)?.email;
      toast(email ? `Invitation for ${email} revoked` : "Invitation revoked");
      setError(null);
      await qc.invalidateQueries({ queryKey: invitesListQueryKey() });
    },
    onError: (e) => setError(memberError(e)),
  });

  const list = sortInvites(invites.data?.invites ?? []);

  return (
    <section className="grid gap-3" aria-labelledby="invitations-heading">
      <Text as="h3" variant="heading" id="invitations-heading">
        Invitations
      </Text>
      {error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
        </div>
      )}
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
                {[inv.roleName, inviteWhen(inv), invitedBy(inv.invitedByName)].filter(Boolean).join(" · ")}
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
