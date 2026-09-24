import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import { previewRole, type PermissionGroupDto, type RoleDto } from "../api";
import { createRoleMutation, updateRoleMutation } from "../api/@tanstack/react-query.gen";
import { message } from "../lib/errors";

/** Somebody the preview can be worked out for. */
export interface Holder {
  kind: "user" | "service_account";
  id: string;
  display: string;
}

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

/**
 * Builds a role out of the things this workspace can allow, and says what
 * somebody holding it could actually do.
 *
 * The preview is the point of the screen. A list of ticked boxes is not
 * an answer to "what could they do?": the answer also depends on the
 * other roles that person already holds and on the tool rules that take
 * a tool away again. All of that is worked out by the server, by the
 * same evaluator that decides a real request, so the screen cannot drift
 * away from what the system actually does.
 */
export function RoleEditor({
  role,
  groups,
  holders,
  onSaved,
  onCancel,
}: {
  role?: RoleDto;
  groups: PermissionGroupDto[];
  holders: Holder[];
  onSaved: () => Promise<void> | void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(role?.name ?? "");
  const [description, setDescription] = useState(role?.description ?? "");
  const [chosen, setChosen] = useState<string[]>(role?.permissions ?? []);
  const [holder, setHolder] = useState("");
  const [error, setError] = useState<string | null>(null);

  const picked = useMemo(() => new Set(chosen), [chosen]);
  const asHolder = holders.find((h) => `${h.kind}:${h.id}` === holder);

  // Creating and changing are two calls with two shapes, so they are two
  // mutations rather than one with a branch inside it.
  const saved = async () => {
    setError(null);
    await onSaved();
  };
  const failed = (e: unknown) => setError(message(e));
  const create = useMutation({ ...createRoleMutation(), onSuccess: saved, onError: failed });
  const update = useMutation({ ...updateRoleMutation(), onSuccess: saved, onError: failed });
  const saving = create.isPending || update.isPending;

  const preview = useQuery({
    queryKey: ["role-preview", [...chosen].sort(), role?.id ?? "", holder],
    enabled: chosen.length > 0,
    retry: false,
    queryFn: async () => {
      const { data } = await previewRole({
        body: {
          permissions: chosen,
          roleId: role?.id,
          principalKind: asHolder?.kind,
          principalId: asHolder?.id,
        },
        throwOnError: true,
      });
      return data;
    },
  });

  const toggle = (id: string) =>
    setChosen((current) => (current.includes(id) ? current.filter((p) => p !== id) : [...current, id]));

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const body = { name: name.trim(), description: description.trim(), permissions: chosen };
    if (role) {
      update.mutate({ path: { id: role.id }, body });
      return;
    }
    create.mutate({ body });
  };

  return (
    <form className="grid gap-5 rounded-lg bg-kumo-tint px-5 py-4 ring ring-kumo-line" onSubmit={submit}>
      <Text as="h2" variant="heading3">
        {role ? `Change what ${role.name} allows` : "Build a role"}
      </Text>

      {error && (
        <div role="alert" className="rounded-md bg-kumo-base px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="grid gap-1.5">
          <Text as="span">Name</Text>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Support engineer" required />
        </label>
        <label className="grid gap-1.5">
          <Text as="span">Who it is for</Text>
          <Input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="People who answer customer questions"
          />
        </label>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="grid content-start gap-4">
          <Text variant="secondary">Tick everything somebody with this role should be able to do.</Text>
          {groups.map((group) => (
            <fieldset key={group.resource} className="grid gap-2 rounded-md bg-kumo-base px-4 py-3 ring ring-kumo-line">
              <legend className="px-1">
                <Text as="span" bold>
                  {group.title}
                </Text>
              </legend>
              {group.permissions.map((permission) => (
                <label key={permission.id} className="flex items-start gap-2">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={picked.has(permission.id)}
                    onChange={() => toggle(permission.id)}
                  />
                  <Text as="span">{permission.description}</Text>
                </label>
              ))}
            </fieldset>
          ))}
        </div>

        <Preview
          holders={holders}
          holder={holder}
          onHolder={setHolder}
          nothingPicked={chosen.length === 0}
          pending={preview.isFetching}
          error={preview.error ? message(preview.error) : null}
          result={preview.data}
        />
      </div>

      <div className="flex flex-wrap gap-3">
        <Button type="submit" variant="primary" disabled={saving || !name.trim() || chosen.length === 0}>
          {role ? "Save what it allows" : "Create this role"}
        </Button>
        <Button type="button" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

interface PreviewResult {
  allows: { id: string; description: string; fromThis: boolean; fromOther: string[] }[];
  restrictions: { toolId: string; toolName: string; allowed: boolean; detail: string }[];
  holder?: string;
  otherRoles: string[];
  unknown: string[];
}

/** What somebody holding the set being built could actually do. */
function Preview({
  holders,
  holder,
  onHolder,
  nothingPicked,
  pending,
  error,
  result,
}: {
  holders: Holder[];
  holder: string;
  onHolder: (value: string) => void;
  nothingPicked: boolean;
  pending: boolean;
  error: string | null;
  result?: PreviewResult;
}) {
  return (
    <section
      aria-label="What somebody holding this role could do"
      className="grid content-start gap-3 rounded-md bg-kumo-base px-4 py-3 ring ring-kumo-line"
    >
      <Text as="h3" bold>
        What they could do
      </Text>

      <label className="grid gap-1.5">
        <Text as="span">Work it out for</Text>
        <select className={selectClass} value={holder} onChange={(e) => onHolder(e.target.value)}>
          <option value="">Somebody with no other role</option>
          {holders.map((h) => (
            <option key={`${h.kind}:${h.id}`} value={`${h.kind}:${h.id}`}>
              {h.display}
            </option>
          ))}
        </select>
      </label>

      {nothingPicked && <Text variant="secondary">Tick something on the left and the answer appears here.</Text>}
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
      {pending && !result && <Text variant="secondary">Working it out…</Text>}

      {result && (
        <>
          {result.otherRoles.length > 0 && (
            <Text variant="secondary">
              {result.holder} already holds {result.otherRoles.join(", ")}, so some of this they could do anyway.
            </Text>
          )}

          <ul className="grid gap-1.5" aria-live="polite">
            {result.allows.map((allow) => (
              <li key={allow.id} className="grid gap-0.5">
                <Text as="span">{allow.description}</Text>
                {allow.fromOther.length > 0 && (
                  <Text as="span" variant="secondary">
                    {allow.fromThis ? "Also from " : "Only from "}
                    {allow.fromOther.join(", ")}
                  </Text>
                )}
              </li>
            ))}
            {result.allows.length === 0 && (
              <li>
                <Text variant="secondary">Nothing yet.</Text>
              </li>
            )}
          </ul>

          {result.restrictions.length > 0 && (
            <div className="grid gap-1.5 border-t border-kumo-line pt-3">
              <Text as="span" bold>
                Tools with a rule of their own
              </Text>
              <ul className="grid gap-1.5">
                {result.restrictions.map((restriction) => (
                  <li key={restriction.toolId} className="grid gap-0.5">
                    <Text as="span">
                      {restriction.allowed ? "Can run " : "Cannot run "}
                      {restriction.toolName}
                    </Text>
                    <Text as="span" variant="secondary">
                      {restriction.detail}
                    </Text>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.unknown.length > 0 && (
            <Text variant="secondary">
              This workspace does not know what {result.unknown.join(", ")} means, so it would allow nothing.
            </Text>
          )}
        </>
      )}
    </section>
  );
}
