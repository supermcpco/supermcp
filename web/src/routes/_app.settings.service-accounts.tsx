import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Text } from "@cloudflare/kumo";
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
import { toast } from "../components/shell/toast";
import { EmptyState, FormDialog, HeaderWithAction } from "../components/form-dialog";
import { ConfirmDialog } from "../components/confirm-dialog";
import { LabelledInput } from "../components/labelled-input";

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
  const [creating, setCreating] = useState(false);
  // The account whose deletion is being asked about. It outlives the
  // dialog's closing, so the dialog keeps its name while it fades.
  const [deleting, setDeleting] = useState<{ id: string; name: string } | null>(null);
  const [asking, setAsking] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: listServiceAccountsQueryKey() });

  const create = useMutation({
    ...createServiceAccountMutation(),
    onSuccess: async (a, vars) => {
      toast(`Service account ${vars.body.name} created`);
      setIssued({ clientId: a.clientId, secret: a.secret ?? "" });
      setName("");
      setError(null);
      setCreating(false);
      await refresh();
    },
    onError: (e) => setError(message(e)),
  });
  const nameOf = (id: string) => accounts.data?.accounts?.find((a) => a.id === id)?.name ?? "The service account";
  const failed = (e: unknown) => toast(message(e), { kind: "error" });
  const rotate = useMutation({
    ...rotateServiceAccountSecretMutation(),
    onSuccess: (res, vars) => {
      const account = accounts.data?.accounts?.find((a) => a.id === vars.path.id);
      toast(`New secret issued for ${nameOf(vars.path.id)}`);
      setIssued({ clientId: account?.clientId ?? "", secret: res.secret });
    },
    onError: failed,
  });
  const setDisabled = useMutation({
    ...setServiceAccountDisabledMutation(),
    onSuccess: async (_, vars) => {
      toast(`${nameOf(vars.path.id)} ${vars.body.disabled ? "disabled" : "enabled"}`);
      await refresh();
    },
    onError: failed,
  });
  const remove = useMutation({
    ...deleteServiceAccountMutation(),
    onSuccess: async (_, vars) => {
      toast(`Service account ${nameOf(vars.path.id)} deleted`);
      setAsking(false);
      setDeleteError(null);
      await refresh();
    },
    // Said in the dialog it was asked from, which stays open to say it.
    onError: (e) => setDeleteError(message(e)),
  });

  if (!can("serviceaccounts:manage")) {
    return <Text>You do not have permission to manage service accounts in this workspace.</Text>;
  }

  const tokenUrl = accounts.data?.tokenUrl ?? "";
  const newAccount = (
    <Button variant="primary" onClick={() => setCreating(true)}>
      New service account
    </Button>
  );

  return (
    <div className="grid gap-8">
      <HeaderWithAction action={newAccount}>
        <Text as="h2" variant="heading">
          Service accounts
        </Text>
        <Text>Sign-ins for pipelines and other services, holding roles the way a person does.</Text>
      </HeaderWithAction>

      {issued && (
        <div className="grid gap-1.5 rounded-lg px-5 py-4 ring ring-kumo-line" role="alert">
          <Text as="h3" variant="heading">
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

      <FormDialog
        open={creating}
        onOpenChange={(open) => {
          setCreating(open);
          setError(null);
        }}
        title="New service account"
        description="Its secret is shown once, when it is created."
        submitLabel="Create account"
        pending={create.isPending}
        canSubmit={name !== ""}
        error={error}
        onSubmit={() => create.mutate({ body: { name } })}
      >
        <LabelledInput label="Name" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Nightly export" />
      </FormDialog>

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
              <Button
                variant="secondary-destructive"
                onClick={() => {
                  setDeleteError(null);
                  setDeleting({ id: a.id, name: a.name });
                  setAsking(true);
                }}
                aria-label={`Delete ${a.name}`}
              >
                Delete
              </Button>
            </div>
          </li>
        ))}
      </ul>
      {accounts.data?.accounts?.length === 0 && <EmptyState>No service accounts yet.</EmptyState>}

      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        resourceType="Service account"
        resourceName={deleting?.name ?? ""}
        confirmLabel="Delete service account"
        pending={remove.isPending}
        error={deleteError}
        onConfirm={() => deleting && remove.mutate({ path: { id: deleting.id } })}
      />
    </div>
  );
}
