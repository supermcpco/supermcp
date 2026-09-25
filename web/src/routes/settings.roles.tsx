import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  createRoleBindingMutation,
  deleteRoleBindingMutation,
  deleteRoleMutation,
  listPermissionsOptions,
  listRoleBindingsOptions,
  listRoleBindingsQueryKey,
  listRolesOptions,
  listRolesQueryKey,
  listServiceAccountsOptions,
  rolesRevisionsListOptions,
  rolesRevisionsListQueryKey,
  rolesRevisionsRestoreMutation,
} from "../api/@tanstack/react-query.gen";
import type { BindingDto, RoleDto } from "../api";
import { useSession } from "../lib/session";
import { Badge, Loading, SignInFirst } from "../lib/ui";
import { message } from "../lib/errors";
import { RoleEditor, type Holder } from "../components/role-editor";
import { RevisionList } from "../components/revisions";

export const Route = createFileRoute("/settings/roles")({
  component: Roles,
});

/** How many lines of "what it allows" a collapsed role shows. */
const summaryLength = 4;

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

function Roles() {
  const { signedIn, can, loading } = useSession();
  const canRead = can("roles:read");
  const canManage = can("roles:manage");
  const canRestore = can("revisions:rollback");
  const qc = useQueryClient();

  const roles = useQuery({ ...listRolesOptions(), enabled: signedIn && canRead, retry: false });
  const permissions = useQuery({ ...listPermissionsOptions(), enabled: signedIn && canRead, retry: false });
  const accounts = useQuery({
    ...listServiceAccountsOptions(),
    enabled: signedIn && canManage && can("serviceaccounts:manage"),
    retry: false,
  });

  const roleList = useMemo(() => roles.data?.roles ?? [], [roles.data]);
  // Every role's holders are loaded together: the list is short, and it is
  // what lets the grant form offer people by name instead of asking for an
  // identifier nobody knows by heart.
  const holderQueries = useQueries({
    queries: roleList.map((r) => ({
      ...listRoleBindingsOptions({ path: { id: r.id } }),
      enabled: signedIn && canRead,
      retry: false,
    })),
  });

  const allows = useMemo(() => {
    const byId = new Map<string, string>();
    for (const group of permissions.data?.groups ?? []) {
      for (const p of group.permissions) byId.set(p.id, p.description);
    }
    return byId;
  }, [permissions.data]);

  const people = useMemo(() => {
    const byId = new Map<string, string>();
    for (const q of holderQueries) {
      for (const b of q.data?.bindings ?? []) {
        if (b.principalKind === "user") byId.set(b.principalId, b.display || b.principalId);
      }
    }
    return [...byId].map(([id, display]) => ({ id, display }));
  }, [holderQueries]);

  // Whoever the preview can be worked out for: the people who already
  // hold something, and the service accounts. Between them they cover
  // the case that matters, which is somebody who would end up holding
  // two roles at once.
  const previewHolders = useMemo<Holder[]>(
    () => [
      ...people.map((p): Holder => ({ kind: "user", id: p.id, display: p.display })),
      ...(accounts.data?.accounts ?? []).map((a): Holder => ({ kind: "service_account", id: a.id, display: a.name })),
    ],
    [people, accounts.data],
  );

  const [open, setOpen] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [history, setHistory] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [kind, setKind] = useState<"user" | "service_account">("user");
  const [principal, setPrincipal] = useState("");
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: listRolesQueryKey() });
    await Promise.all(
      roleList.map((r) => qc.invalidateQueries({ queryKey: listRoleBindingsQueryKey({ path: { id: r.id } }) })),
    );
  };

  const grant = useMutation({
    ...createRoleBindingMutation(),
    onSuccess: async () => {
      setPrincipal("");
      setError(null);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });
  const revoke = useMutation({
    ...deleteRoleBindingMutation(),
    onSuccess: async () => {
      setError(null);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });
  const remove = useMutation({
    ...deleteRoleMutation(),
    onSuccess: async () => {
      setConfirming(null);
      setError(null);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;
  if (!canRead) return <Text>You do not have permission to see the roles in this workspace.</Text>;

  const toggle = (id: string) => {
    setOpen((current) => (current === id ? null : id));
    setPrincipal("");
    setError(null);
  };

  // A change to a role is a new version in its history, so the history
  // read before the save is out of date the moment the save lands. Left
  // alone it would be served from the cache, and an open history panel
  // would go on showing the role as it was.
  const afterSave = async (id?: string) => {
    setEditing(null);
    await Promise.all([
      refresh(),
      id ? qc.invalidateQueries({ queryKey: rolesRevisionsListQueryKey({ path: { id } }) }) : undefined,
    ]);
  };

  return (
    <div className="grid gap-8">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Roles
        </Text>
        <Text>
          A role is a named set of things somebody is allowed to do. Give a person or a service account a role and they
          can do everything it lists, anywhere in this workspace.
        </Text>
        <Text variant="secondary">
          The roles that came with the product are the same everywhere and cannot be changed. Build one of your own for
          anything else, and the screen will tell you what somebody holding it could do before you save it.
        </Text>
      </div>

      {error && !open && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
        </div>
      )}

      {canManage && editing !== "new" && (
        <div>
          <Button variant="primary" onClick={() => setEditing("new")}>
            Build a role
          </Button>
        </div>
      )}

      {canManage && editing === "new" && (
        <RoleEditor
          groups={permissions.data?.groups ?? []}
          holders={previewHolders}
          onSaved={() => afterSave()}
          onCancel={() => setEditing(null)}
        />
      )}

      <ul className="grid gap-2">
        {roleList.map((role, index) => {
          const expanded = open === role.id;
          const descriptions = role.permissions.map((p) => allows.get(p) ?? p);
          const shown = expanded ? descriptions : descriptions.slice(0, summaryLength);
          const bindings = holderQueries[index]?.data?.bindings ?? [];
          return (
            <li key={role.id} className="grid gap-4 rounded-lg px-5 py-4 ring ring-kumo-line">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="grid gap-1">
                  <div className="flex items-center gap-2">
                    <Text as="span" bold>
                      {role.name}
                    </Text>
                    {role.builtIn && <Badge>built in</Badge>}
                  </div>
                  {role.description && <Text as="span">{role.description}</Text>}
                  <Text as="span" variant="secondary">
                    {holders(role.holders)}
                  </Text>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => toggle(role.id)} aria-expanded={expanded}>
                    {expanded ? "Hide holders" : "Who holds it"}
                  </Button>
                  {!role.builtIn && canManage && editing !== role.id && (
                    <Button onClick={() => setEditing(role.id)}>Change what it allows</Button>
                  )}
                  {!role.builtIn && (
                    <Button
                      onClick={() => setHistory((current) => (current === role.id ? null : role.id))}
                      aria-expanded={history === role.id}
                    >
                      {history === role.id ? "Hide history" : "History"}
                    </Button>
                  )}
                  {!role.builtIn && canManage && confirming !== role.id && (
                    <Button onClick={() => setConfirming(role.id)}>Delete</Button>
                  )}
                  {!role.builtIn && canManage && confirming === role.id && (
                    <>
                      <Button
                        variant="primary"
                        disabled={remove.isPending}
                        onClick={() => remove.mutate({ path: { id: role.id } })}
                      >
                        Delete {role.name} for good
                      </Button>
                      <Button onClick={() => setConfirming(null)}>Keep it</Button>
                    </>
                  )}
                </div>
              </div>

              <div className="grid gap-1">
                <Text as="span" variant="secondary">
                  What it allows
                </Text>
                <ul className="grid list-disc gap-1 pl-5">
                  {shown.map((line) => (
                    <li key={line}>
                      <Text as="span">{line}</Text>
                    </li>
                  ))}
                </ul>
                {!expanded && descriptions.length > summaryLength && (
                  <Text variant="secondary">and {descriptions.length - summaryLength} more</Text>
                )}
              </div>

              {canManage && editing === role.id && (
                <RoleEditor
                  role={role}
                  groups={permissions.data?.groups ?? []}
                  holders={previewHolders}
                  onSaved={() => afterSave(role.id)}
                  onCancel={() => setEditing(null)}
                />
              )}

              {history === role.id && <RoleHistory role={role} canRestore={canRestore} onRestored={refresh} />}

              {expanded && (
                <div className="grid gap-3 border-t border-kumo-line pt-4">
                  {/* Beside the buttons it belongs to: this page is long,
                      and a refusal at the top is a refusal nobody reads. */}
                  {error && (
                    <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
                      <Text>{error}</Text>
                    </div>
                  )}
                  <ul className="grid gap-2">
                    {bindings.map((b) => (
                      <li key={b.id} className="flex flex-wrap items-center justify-between gap-3">
                        <div className="grid gap-0.5">
                          <Text as="span">{b.display || b.principalId}</Text>
                          <Text as="span" variant="secondary">
                            {holderKind(b)}
                            {scope(b)}
                            {b.source === "sso" ? " · from your identity provider" : ""}
                          </Text>
                        </div>
                        {canManage && (
                          <Button
                            onClick={() => revoke.mutate({ path: { id: role.id, bindingId: b.id } })}
                            disabled={revoke.isPending}
                          >
                            Take away
                          </Button>
                        )}
                      </li>
                    ))}
                    {bindings.length === 0 && (
                      <li>
                        <Text variant="secondary">Nobody holds this role.</Text>
                      </li>
                    )}
                  </ul>

                  {canManage && (
                    <form
                      className="flex flex-wrap items-end gap-3"
                      onSubmit={(e) => {
                        e.preventDefault();
                        grant.mutate({
                          path: { id: role.id },
                          body: { principalKind: kind, principalId: principal, scopeKind: "org" },
                        });
                      }}
                    >
                      <label className="grid gap-1.5">
                        <Text as="span">Give it to</Text>
                        <select
                          className={selectClass}
                          value={kind}
                          onChange={(e) => {
                            setKind(e.target.value === "service_account" ? "service_account" : "user");
                            setPrincipal("");
                          }}
                        >
                          <option value="user">A person</option>
                          <option value="service_account">A service account</option>
                        </select>
                      </label>
                      {kind === "service_account" ? (
                        <label className="grid flex-1 gap-1.5">
                          <Text as="span">Service account</Text>
                          <select className={selectClass} value={principal} onChange={(e) => setPrincipal(e.target.value)}>
                            <option value="">Choose one</option>
                            {accounts.data?.accounts?.map((a) => (
                              <option key={a.id} value={a.id}>
                                {a.name}
                              </option>
                            ))}
                          </select>
                        </label>
                      ) : (
                        <label className="grid flex-1 gap-1.5">
                          <Text as="span">Person</Text>
                          <Input
                            list={`people-${role.id}`}
                            value={principal}
                            onChange={(e) => setPrincipal(e.target.value)}
                            placeholder="Name or user id"
                          />
                          <datalist id={`people-${role.id}`}>
                            {people.map((p) => (
                              <option key={p.id} value={p.id}>
                                {p.display}
                              </option>
                            ))}
                          </datalist>
                        </label>
                      )}
                      <Button type="submit" variant="primary" disabled={grant.isPending || !principal}>
                        Give this role
                      </Button>
                    </form>
                  )}
                </div>
              )}
            </li>
          );
        })}
        {roles.isSuccess && roleList.length === 0 && (
          <li>
            <Text variant="secondary">No roles yet.</Text>
          </li>
        )}
      </ul>
    </div>
  );
}

/**
 * Every change to one role, and the version it can be put back to.
 *
 * A role is recorded the way a connector is: the revision is written in
 * the same transaction as the change, so a workspace can answer who
 * widened a role and when, not only that somebody did.
 */
function RoleHistory({ role, canRestore, onRestored }: { role: RoleDto; canRestore: boolean; onRestored: () => Promise<void> }) {
  const qc = useQueryClient();
  const revisions = useQuery({ ...rolesRevisionsListOptions({ path: { id: role.id } }), retry: false });
  const restore = useMutation({
    ...rolesRevisionsRestoreMutation(),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: rolesRevisionsListQueryKey({ path: { id: role.id } }) });
      await onRestored();
    },
  });

  return (
    <div className="grid gap-3 border-t border-kumo-line pt-4">
      <Text as="span" variant="secondary">
        Every change to this role, newest first. Restoring an earlier version is recorded as a further change rather
        than a rewind.
      </Text>
      {restore.error && (
        <div role="alert">
          <Text>{message(restore.error)}</Text>
        </div>
      )}
      {/* "Nothing has changed yet" is a claim, and a screen that makes it
          before the answer has arrived is telling the reader something it
          does not know. */}
      {revisions.isPending ? (
        <Loading />
      ) : (
        <RevisionList
          revisions={revisions.data?.revisions ?? []}
          canRestore={canRestore}
          restoring={restore.isPending}
          onRestore={(revision) => restore.mutate({ path: { id: role.id, revision } })}
          empty="Nothing has changed about this role yet."
        />
      )}
    </div>
  );
}

function holders(count: number) {
  if (count === 0) return "Nobody holds this role";
  return count === 1 ? "1 holder" : `${count} holders`;
}

function holderKind(b: BindingDto) {
  if (b.principalKind === "service_account") return "Service account";
  if (b.principalKind === "idp_group") return "Everyone in this group";
  return "Person";
}

function scope(b: BindingDto) {
  if (b.scopeKind === "org") return "";
  return ` · only on the ${b.scopeKind} ${b.scopeDisplay || b.scopeId}`;
}
