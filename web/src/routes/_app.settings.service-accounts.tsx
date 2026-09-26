import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  createServiceAccountMutation,
  deleteServiceAccountMutation,
  listServiceAccountsOptions,
  listServiceAccountsQueryKey,
  rotateServiceAccountSecretMutation,
  setServiceAccountDisabledMutation,
} from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { message } from "../lib/errors";

export const Route = createFileRoute("/_app/settings/service-accounts")({
  component: ServiceAccounts,
});

function ServiceAccounts() {
  const { signedIn, can } = useSession();
  const qc = useQueryClient();
  const accounts = useQuery({
    ...listServiceAccountsOptions(),
    enabled: signedIn && can("serviceaccounts:manage"),
    retry: false,
  });
  const [name, setName] = useState("");
  const [issued, setIssued] = useState<{ clientId: string; secret: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: listServiceAccountsQueryKey() });

  const create = useMutation({
    ...createServiceAccountMutation(),
    onSuccess: async (a) => {
      setIssued({ clientId: a.clientId, secret: a.secret ?? "" });
      setName("");
      setError(null);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });
  const rotate = useMutation({
    ...rotateServiceAccountSecretMutation(),
    onSuccess: (res, vars) => {
      const account = accounts.data?.accounts?.find((a) => a.id === vars.path.id);
      setIssued({ clientId: account?.clientId ?? "", secret: res.secret });
    },
  });
  const setDisabled = useMutation({ ...setServiceAccountDisabledMutation(), onSuccess: refresh });
  const remove = useMutation({ ...deleteServiceAccountMutation(), onSuccess: refresh });

  if (!can("serviceaccounts:manage")) {
    return <Text>You do not have permission to manage service accounts in this workspace.</Text>;
  }

  const tokenUrl = accounts.data?.tokenUrl ?? "";

  return (
    <div className="grid gap-8">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Service accounts
        </Text>
        <Text>
          A service account is a principal that is not a person: a pipeline, a scheduler, another service. It takes the
          same roles a person would, and nobody has to lend it their own key.
        </Text>
      </div>

      {issued && (
        <div className="grid gap-1.5 rounded-lg px-5 py-4 ring ring-kumo-line" role="alert">
          <Text as="h2" variant="heading3">
            Copy this secret now
          </Text>
          <Text variant="secondary">It is not stored and cannot be shown again.</Text>
          <code className="overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]">
            client_id: {issued.clientId}
            <br />
            client_secret: {issued.secret}
          </code>
          <Text variant="secondary">
            Exchange them for a token at {tokenUrl} with grant_type=client_credentials.
          </Text>
          <div className="flex gap-2">
            <Button onClick={() => void navigator.clipboard.writeText(issued.secret)}>Copy secret</Button>
            <Button onClick={() => setIssued(null)}>Done</Button>
          </div>
        </div>
      )}

      <form
        className="flex flex-wrap items-end gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate({ body: { name } });
        }}
      >
        <label className="grid flex-1 gap-1.5">
          <Text as="span">Name</Text>
          <Input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Nightly export" />
        </label>
        <Button type="submit" variant="primary" disabled={create.isPending || !name}>
          Create account
        </Button>
      </form>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}

      <ul className="grid gap-2">
        {accounts.data?.accounts?.map((a) => (
          <li
            key={a.id}
            className="flex flex-wrap items-center justify-between gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
          >
            <div className="grid gap-1">
              <div className="flex items-center gap-2">
                <Text as="span" bold>
                  {a.name}
                </Text>
                {a.disabledAt && <Badge>disabled</Badge>}
                {a.serverId && <Badge>one server</Badge>}
              </div>
              <Text as="span" variant="secondary">
                <span className="font-mono text-[0.9em]">{a.clientId}</span>
                {a.lastUsedAt ? ` · last used ${new Date(a.lastUsedAt).toLocaleString()}` : " · never used"}
              </Text>
            </div>
            <div className="flex gap-2">
              <Button onClick={() => rotate.mutate({ path: { id: a.id } })} disabled={rotate.isPending}>
                New secret
              </Button>
              <Button
                onClick={() => setDisabled.mutate({ path: { id: a.id }, body: { disabled: !a.disabledAt } })}
                disabled={setDisabled.isPending}
              >
                {a.disabledAt ? "Enable" : "Disable"}
              </Button>
              <Button onClick={() => remove.mutate({ path: { id: a.id } })} disabled={remove.isPending}>
                Delete
              </Button>
            </div>
          </li>
        ))}
        {accounts.data?.accounts?.length === 0 && (
          <li>
            <Text variant="secondary">No service accounts yet.</Text>
          </li>
        )}
      </ul>
    </div>
  );
}
