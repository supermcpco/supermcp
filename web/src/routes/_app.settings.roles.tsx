import { Fragment, useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
import { CaretDown, CaretRight } from "@phosphor-icons/react";
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
import { Badge, Loading } from "../lib/ui";
import { message } from "../lib/errors";
import { RoleEditor, type Holder } from "../components/role-editor";
import { HistoryPanel } from "../components/revisions";
import { toast } from "../components/shell/toast";
import { HeaderWithAction } from "../components/form-dialog";
import { ConfirmDialog } from "../components/confirm-dialog";
import { Help, HeadingWithHelp } from "../components/help";
import { LabelledInput } from "../components/labelled-input";
import { LabelledSelect } from "../components/select";

export const Route = createFileRoute("/_app/settings/roles")({
  component: Roles,
});

const columns = ["Role", "Kind", "Holders", "Permissions", "Actions"] as const;

/** Which role the editor dialog is open on: a new one, or an existing custom one. */
type Editing = { key: number; role?: RoleDto };

function Roles() {
  const { signedIn, can } = useSession();
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

  // What each row has unfolded: its permissions, its holders, its history.
  const [unfolded, setUnfolded] = useState<ReadonlySet<string>>(new Set());
  const [holdersOf, setHoldersOf] = useState<string | null>(null);
  const [history, setHistory] = useState<string | null>(null);
  // The editor is keyed afresh on every opening, so it starts from the
  // role as it is now; the key is kept while it closes, so it fades out.
  const [editing, setEditing] = useState<Editing>({ key: 0 });
  const [editorOpen, setEditorOpen] = useState(false);
  const [deleting, setDeleting] = useState<RoleDto | null>(null);
  const [asking, setAsking] = useState(false);
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
    onSuccess: async (b, vars) => {
      const role = roleList.find((r) => r.id === vars.path.id)?.name ?? "the role";
      toast(`${b.display || "The holder"} now holds ${role}`);
      setPrincipal("");
      setError(null);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });
  const revoke = useMutation({
    ...deleteRoleBindingMutation(),
    onSuccess: async (_, vars) => {
      const index = roleList.findIndex((r) => r.id === vars.path.id);
      const binding = holderQueries[index]?.data?.bindings?.find((x) => x.id === vars.path.bindingId);
      const role = roleList[index]?.name ?? "the role";
      toast(`${binding?.display || "The holder"} no longer holds ${role}`);
      setError(null);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });
  const remove = useMutation({
    ...deleteRoleMutation(),
    onSuccess: async (_, vars) => {
      const role = roleList.find((r) => r.id === vars.path.id)?.name;
      toast(role ? `Role ${role} deleted` : "Role deleted");
      setAsking(false);
      await refresh();
    },
  });

  if (!canRead) return <Text>You do not have permission to see the roles in this workspace.</Text>;

  const unfold = (id: string) =>
    setUnfolded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const toggleHolders = (id: string) => {
    setHoldersOf((current) => (current === id ? null : id));
    setPrincipal("");
    setError(null);
  };
  const openEditor = (role?: RoleDto) => {
    setEditing((current) => ({ key: current.key + 1, role }));
    setEditorOpen(true);
  };

  // A change to a role is a new version in its history, so the history
  // read before the save is out of date the moment the save lands. Left
  // alone it would be served from the cache, and an open history panel
  // would go on showing the role as it was.
  const afterSave = async (id?: string) => {
    setEditorOpen(false);
    await Promise.all([
      refresh(),
      id ? qc.invalidateQueries({ queryKey: rolesRevisionsListQueryKey({ path: { id } }) }) : undefined,
    ]);
  };

  const build = canManage ? (
    <Button variant="primary" onClick={() => openEditor()}>
      Build a role
    </Button>
  ) : null;

  return (
    <div className="grid gap-6">
      <HeaderWithAction action={build}>
        <HeadingWithHelp
          heading={
            <Text as="h2" variant="heading">
              Roles
            </Text>
          }
          help={
            <Help about="roles">
              <Text>
                A role is a named set of things somebody is allowed to do. Give a person or a service account a role
                and they can do everything it lists, anywhere in this workspace.
              </Text>
              <Text>
                The roles that came with the product are the same everywhere and cannot be changed. Build one of your
                own for anything else, and the editor tells you what somebody holding it could do before you save it.
              </Text>
            </Help>
          }
        />
        <Text>What each role allows, and who holds it.</Text>
      </HeaderWithAction>

      {roles.isPending && <Loading />}
      {roles.error && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{message(roles.error)}</Text>
        </div>
      )}

      {roleList.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <caption className="sr-only">Roles in this workspace</caption>
            <thead>
              <tr className="border-b border-kumo-line">
                {columns.map((h) => (
                  <th key={h} scope="col" className="py-2 pr-4">
                    <Text as="span" variant="secondary">
                      {h}
                    </Text>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {roleList.map((role, index) => {
                const open = unfolded.has(role.id);
                const holding = holdersOf === role.id;
                const showingHistory = history === role.id;
                const details = `role-${role.id}-details`;
                const bindings = holderQueries[index]?.data?.bindings ?? [];
                const custom = !role.builtIn;
                return (
                  <Fragment key={role.id}>
                    <tr className="border-b border-kumo-line align-top">
                      <td className="py-2 pr-4">
                        <button
                          type="button"
                          className="flex items-center gap-1.5 rounded text-left font-semibold focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
                          aria-expanded={open}
                          aria-controls={open ? details : undefined}
                          onClick={() => unfold(role.id)}
                        >
                          <span className="h-lh flex items-center">
                            {open ? <CaretDown size={14} aria-hidden /> : <CaretRight size={14} aria-hidden />}
                          </span>
                          {role.name}
                        </button>
                        {role.description && (
                          <Text as="span" variant="secondary">
                            {role.description}
                          </Text>
                        )}
                      </td>
                      <td className="py-2 pr-4">
                        <Badge>{custom ? "custom" : "built in"}</Badge>
                      </td>
                      <td className="py-2 pr-4">
                        <Text as="span">{role.holders}</Text>
                      </td>
                      <td className="py-2 pr-4">
                        <Text as="span">{role.permissions.length}</Text>
                      </td>
                      <td className="py-2">
                        <div className="flex flex-wrap gap-2">
                          <Button
                            size="sm"
                            onClick={() => toggleHolders(role.id)}
                            aria-expanded={holding}
                            aria-label={`${holding ? "Hide who holds" : "Who holds"} ${role.name}`}
                          >
                            {holding ? "Hide holders" : "Who holds it"}
                          </Button>
                          {custom && canManage && (
                            <Button size="sm" onClick={() => openEditor(role)} aria-label={`Change what ${role.name} allows`}>
                              Change
                            </Button>
                          )}
                          {custom && (
                            <Button
                              size="sm"
                              onClick={() => setHistory((current) => (current === role.id ? null : role.id))}
                              aria-expanded={showingHistory}
                              aria-label={`${showingHistory ? "Hide the history of" : "History of"} ${role.name}`}
                            >
                              {showingHistory ? "Hide history" : "History"}
                            </Button>
                          )}
                          {custom && canManage && (
                            <Button
                              size="sm"
                              variant="secondary-destructive"
                              onClick={() => {
                                remove.reset();
                                setDeleting(role);
                                setAsking(true);
                              }}
                              aria-label={`Delete ${role.name}`}
                            >
                              Delete
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {(open || holding || showingHistory) && (
                      <tr className="border-b border-kumo-line">
                        <td colSpan={columns.length} className="py-3 pl-6">
                          <div className="grid gap-4">
                          {open && (
                            <section id={details} aria-label={`Permissions of ${role.name}`} className="grid gap-1">
                              <Text as="span" variant="secondary">
                                What it allows
                              </Text>
                              <ul className="grid list-disc gap-1 pl-5">
                                {role.permissions.map((p) => (
                                  <li key={p}>
                                    <Text as="span">{allows.get(p) ?? p}</Text>
                                  </li>
                                ))}
                              </ul>
                            </section>
                          )}
                          {holding && (
                            <section aria-label={`Holders of ${role.name}`} className="grid gap-3">
                              {/* Beside the buttons it belongs to: a refusal at
                                  the top of a long table is one nobody reads. */}
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
                                  <LabelledSelect
                                    label="Give it to"
                                    value={kind}
                                    onChange={(v) => {
                                      setKind(v === "service_account" ? "service_account" : "user");
                                      setPrincipal("");
                                    }}
                                    options={[
                                      { value: "user", label: "A person" },
                                      { value: "service_account", label: "A service account" },
                                    ]}
                                  />
                                  {kind === "service_account" ? (
                                    <LabelledSelect
                                      label="Service account"
                                      className="grid flex-1 gap-1.5"
                                      triggerClassName="w-full"
                                      value={principal}
                                      onChange={setPrincipal}
                                      options={[
                                        { value: "", label: "Choose one" },
                                        ...(accounts.data?.accounts ?? []).map((a) => ({ value: a.id, label: a.name })),
                                      ]}
                                    />
                                  ) : (
                                    <LabelledInput
                                      labelClassName="grid flex-1 gap-1.5"
                                      label="Person"
                                      list={`people-${role.id}`}
                                      value={principal}
                                      onChange={(e) => setPrincipal(e.target.value)}
                                      placeholder="Name or user id"
                                    >
                                      <datalist id={`people-${role.id}`}>
                                        {people.map((p) => (
                                          <option key={p.id} value={p.id}>
                                            {p.display}
                                          </option>
                                        ))}
                                      </datalist>
                                    </LabelledInput>
                                  )}
                                  <Button type="submit" variant="primary" disabled={grant.isPending || !principal}>
                                    Give this role
                                  </Button>
                                </form>
                              )}
                            </section>
                          )}
                          {showingHistory && <RoleHistory role={role} canRestore={canRestore} onRestored={refresh} />}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {roles.isSuccess && roleList.length === 0 && <Text variant="secondary">No roles yet.</Text>}

      {canManage && (
        <RoleEditor
          key={editing.key}
          open={editorOpen}
          onOpenChange={setEditorOpen}
          role={editing.role}
          groups={permissions.data?.groups ?? []}
          holders={previewHolders}
          onSaved={() => afterSave(editing.role?.id)}
        />
      )}

      {canManage && (
        <ConfirmDialog
          open={asking}
          onOpenChange={setAsking}
          resourceType="Role"
          resourceName={deleting?.name ?? ""}
          confirmLabel="Delete role"
          pending={remove.isPending}
          error={remove.error ? message(remove.error) : null}
          onConfirm={() => deleting && remove.mutate({ path: { id: deleting.id } })}
        />
      )}
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
    onSuccess: async (_, vars) => {
      toast(`Role ${role.name} restored to version ${vars.path.revision}`);
      await qc.invalidateQueries({ queryKey: rolesRevisionsListQueryKey({ path: { id: role.id } }) });
      await onRestored();
    },
  });

  return (
    <HistoryPanel
      label={`History of ${role.name}`}
      intro="Every change to this role, newest first. Restoring an earlier version is recorded as a further change rather than a rewind."
      loading={revisions.isPending}
      revisions={revisions.data?.revisions ?? []}
      error={restore.error ? message(restore.error) : revisions.error ? message(revisions.error) : null}
      canRestore={canRestore}
      restoring={restore.isPending}
      onRestore={(revision) => restore.mutate({ path: { id: role.id, revision } })}
      empty="Nothing has changed about this role yet."
    />
  );
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
