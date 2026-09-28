import { useId, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Dialog, DialogRoot, DialogTitle, Text } from "@cloudflare/kumo";
import {
  keysCreateMutation,
  keysListOptions,
  keysListQueryKey,
  keysRevokeMutation,
  keysRotateMutation,
  serversListOptions,
} from "../api/@tanstack/react-query.gen";
import type { ApiKeyDto, KeysCreateResponse, RotatedKeyDto } from "../api/types.gen";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";
import { message } from "../lib/errors";
import { toast } from "../components/shell/toast";
import { CopyButton, ConnectClient } from "../components/connect-client";
import { EmptyState, HeaderWithAction } from "../components/form-dialog";
import { ConfirmAction } from "../components/confirm-dialog";
import { canRotate, defaultGraceSeconds, graceChoices, stopsWorking } from "../lib/key-rotation";
import { LabelledInput } from "../components/labelled-input";

export const Route = createFileRoute("/_app/api-keys")({
  component: APIKeys,
});

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

// What a key is for decides its scopes. A client key gets the server's
// defaults; a provisioning key reaches the SCIM endpoints and nothing else.
const purposes = {
  client: undefined,
  scim: ["scim:write"],
} as const;

/** A secret on show: the key it opens, and what it replaced if it was a rotation. */
interface Issued {
  secret: string;
  key: ApiKeyDto;
  replaced?: { prefix: string; expiresAt: string };
}

function APIKeys() {
  const { signedIn } = useSession();
  const qc = useQueryClient();
  const keys = useQuery({ ...keysListOptions(), enabled: signedIn, retry: false });
  const list = keys.data ?? [];
  const [creating, setCreating] = useState(false);
  const [issued, setIssued] = useState<Issued | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);

  // The key last asked about stays named while its dialog fades out.
  const [revoking, setRevoking] = useState<ApiKeyDto | null>(null);
  const [askingRevoke, setAskingRevoke] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const revoke = useMutation({
    ...keysRevokeMutation(),
    onSuccess: async () => {
      if (revoking) toast(`API key ${revoking.name} revoked`);
      setAskingRevoke(false);
      await qc.invalidateQueries({ queryKey: keysListQueryKey() });
    },
    onError: (e) => setRevokeError(message(e)),
  });

  const createKey = (
    <Button variant="primary" onClick={() => setCreating(true)}>
      Create key
    </Button>
  );

  return (
    <div className="grid gap-6">
      <HeaderWithAction action={createKey}>
        <Text as="h1" variant="heading" size="lg">
          API keys
        </Text>
        <Text>A key lets an AI client reach your MCP servers; its secret is shown once, when you create it.</Text>
      </HeaderWithAction>

      {keys.isPending && <Loading />}
      {keys.isError && (
        <div role="alert">
          <Text>{message(keys.error)}</Text>
        </div>
      )}
      {keys.isSuccess && list.length === 0 && (
        <EmptyState title="No API keys yet">
          Create one for each AI client, so each can be revoked on its own.
        </EmptyState>
      )}

      <ul className="grid gap-2">
        {list.map((k) => (
          <li key={k.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="grid gap-1">
              <div className="flex items-center gap-2">
                <Text as="span" bold>
                  {k.name}
                </Text>
                {k.revokedAt && <Badge>revoked</Badge>}
              </div>
              <Text as="span" variant="secondary">
                <span className="font-mono text-[0.9em]">smk_{k.prefix}…</span>
                {k.lastUsedAt ? ` · last used ${new Date(k.lastUsedAt).toLocaleString()}` : " · never used"}
                {k.expiresAt ? ` · expires ${new Date(k.expiresAt).toLocaleDateString()}` : ""}
              </Text>
            </div>
            <div className="flex gap-2">
              {canRotate(k) && rotating !== k.id && (
                <Button onClick={() => setRotating(k.id)}>
                  Rotate<span className="sr-only"> {k.name}</span>
                </Button>
              )}
              {!k.revokedAt && (
                <Button
                  onClick={() => {
                    setRevokeError(null);
                    setRevoking(k);
                    setAskingRevoke(true);
                  }}
                >
                  Revoke<span className="sr-only"> {k.name}</span>
                </Button>
              )}
            </div>
            {rotating === k.id && (
              <ConfirmRotate
                apiKey={k}
                onRotated={(res) => {
                  setIssued({
                    secret: res.secret,
                    key: res.key,
                    replaced: { prefix: k.prefix, expiresAt: res.previousExpiresAt },
                  });
                  setRotating(null);
                }}
                onCancel={() => setRotating(null)}
              />
            )}
          </li>
        ))}
      </ul>

      <CreateKeyDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(res) => {
          setCreating(false);
          setIssued({ secret: res.secret, key: res.key });
        }}
      />
      <SecretDialog issued={issued} onDone={() => setIssued(null)} />
      <ConfirmAction
        open={askingRevoke}
        onOpenChange={setAskingRevoke}
        title={`Revoke ${revoking?.name ?? "this key"}?`}
        confirmLabel="Revoke"
        pending={revoke.isPending}
        error={revokeError}
        onConfirm={() => revoking && revoke.mutate({ path: { id: revoking.id } })}
      >
        Any client using it is refused from then on. This cannot be undone: the client needs a new key.
      </ConfirmAction>
    </div>
  );
}

/**
 * The form for a new key, in a dialog so the list keeps the screen.
 * Mounted per opening, so a name typed and abandoned is not there next time.
 */
function CreateKeyDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (res: KeysCreateResponse) => void;
}) {
  return (
    <DialogRoot open={open} onOpenChange={(next) => !next && onClose()}>
      {open && (
        <Dialog className="grid gap-4 p-6">
          <DialogTitle className="text-lg font-semibold">New API key</DialogTitle>
          <CreateKeyForm onCancel={onClose} onCreated={onCreated} />
        </Dialog>
      )}
    </DialogRoot>
  );
}

function CreateKeyForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: (res: KeysCreateResponse) => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState<keyof typeof purposes>("client");
  const [error, setError] = useState<string | null>(null);
  const purposeId = useId();

  const create = useMutation({
    ...keysCreateMutation(),
    onSuccess: async (res, vars) => {
      // The name only: the secret is shown once, in its own dialog, and nowhere else.
      toast(`API key ${vars.body.name} created`);
      onCreated(res);
      await qc.invalidateQueries({ queryKey: keysListQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });

  return (
    <form
      className="grid gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        const scopes = purposes[purpose];
        create.mutate({ body: scopes ? { name, scopes: [...scopes] } : { name } });
      }}
    >
      <LabelledInput label="Name" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Claude Desktop" />
      <div className="grid gap-1.5">
        <label htmlFor={purposeId}>
          <Text as="span">For</Text>
        </label>
        <select
          id={purposeId}
          className={selectClass}
          value={purpose}
          onChange={(e) => setPurpose(e.currentTarget.value as keyof typeof purposes)}
        >
          <option value="client">An AI client</option>
          <option value="scim">SCIM provisioning</option>
        </select>
      </div>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
      <div className="flex justify-end gap-2">
        <Button onClick={onCancel}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={create.isPending || !name}>
          {create.isPending ? "Creating…" : "Create key"}
        </Button>
      </div>
    </form>
  );
}

/**
 * The one moment a secret is on screen. It closes only on Done, never on
 * a stray click outside or Escape, because closing it is the last chance
 * to copy; after that the secret is dropped from memory with the dialog.
 */
function SecretDialog({ issued, onDone }: { issued: Issued | null; onDone: () => void }) {
  return (
    <DialogRoot open={issued !== null} disablePointerDismissal onOpenChange={() => {}}>
      {issued && (
        <Dialog size="xl" className="grid max-h-[90vh] gap-4 overflow-y-auto p-6">
          <DialogTitle className="text-lg font-semibold">Copy this key now</DialogTitle>
          <SecretBody issued={issued} />
          <div className="flex justify-end">
            <Button variant="primary" onClick={onDone}>
              Done
            </Button>
          </div>
        </Dialog>
      )}
    </DialogRoot>
  );
}

function SecretBody({ issued }: { issued: Issued }) {
  const { can } = useSession();
  const { secret, key, replaced } = issued;
  // A provisioning key reaches SCIM, not MCP servers: no client to connect.
  const forClients = !key.scopes.includes("scim:write");
  const mayListServers = can("servers:read");
  const servers = useQuery({ ...serversListOptions(), enabled: forClients && mayListServers, retry: false });
  const [picked, setPicked] = useState<string | null>(null);
  const secretId = useId();
  const serverSelectId = useId();
  const list = servers.data ?? [];
  // A key bound to one server can only reach that one, so there is no
  // choice to offer; otherwise the first, until another is picked.
  const bound = key.serverId ?? null;
  const serverId = bound ?? picked ?? list[0]?.id;
  const server = list.find((s) => s.id === serverId);

  return (
    <div className="grid gap-4">
      <div className="grid gap-1.5">
        <Text variant="secondary">
          {key.name}: it is not stored and cannot be shown again.
        </Text>
        <label htmlFor={secretId}>
          <Text as="span">Secret</Text>
        </label>
        <div className="flex items-center gap-2">
          <input
            id={secretId}
            readOnly
            value={secret}
            onFocus={(e) => e.currentTarget.select()}
            className="min-w-0 flex-1 rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]"
          />
          <CopyButton text={secret} what="secret" />
        </div>
        {replaced && (
          <Text>
            This replaces <span className="font-mono text-[0.9em]">smk_{replaced.prefix}…</span>.{" "}
            {stopsWorking(replaced.expiresAt)}
          </Text>
        )}
      </div>

      {forClients && mayListServers && (
        <div className="grid gap-3 border-t border-kumo-line pt-4">
          <Text as="h3" variant="heading">
            Connect a client
          </Text>
          {servers.isPending && <Text variant="secondary">Loading…</Text>}
          {servers.isError && <Text variant="secondary">{message(servers.error)}</Text>}
          {servers.data?.length === 0 && (
            <Text>
              There is no MCP server to connect to yet.{" "}
              <Link to="/servers" className="underline">
                Create one on MCP servers
              </Link>
              , then use this key with it.
            </Text>
          )}
          {bound && server && (
            <Text>
              Server: <span className="font-semibold">{server.name}</span>, the only one this key reaches.
            </Text>
          )}
          {!bound && list.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <label htmlFor={serverSelectId}>
                <Text as="span">Server</Text>
              </label>
              <select
                id={serverSelectId}
                className={selectClass}
                value={serverId}
                onChange={(e) => setPicked(e.currentTarget.value)}
              >
                {list.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </div>
          )}
          {server && <ConnectClient key={server.id} server={server} secret={secret} showEndpoint />}
        </div>
      )}
    </div>
  );
}

/**
 * Asks how long the old key should keep working before it is replaced.
 * The replacement's secret is handed back to the screen, which shows it
 * once in the same dialog a new key's secret appears in.
 */
function ConfirmRotate({
  apiKey,
  onRotated,
  onCancel,
}: {
  apiKey: ApiKeyDto;
  onRotated: (res: RotatedKeyDto) => void;
  onCancel: () => void;
}) {
  const qc = useQueryClient();
  const [grace, setGrace] = useState<number>(defaultGraceSeconds);
  const graceId = useId();
  const [error, setError] = useState<string | null>(null);
  const rotate = useMutation({
    ...keysRotateMutation(),
    onSuccess: async (res) => {
      // The name only: the new secret is shown once, in its own dialog.
      toast(`API key ${apiKey.name} rotated`);
      onRotated(res);
      await qc.invalidateQueries({ queryKey: keysListQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });

  return (
    <form
      className="grid w-full gap-3 border-t border-kumo-line pt-3"
      aria-label={`Rotate ${apiKey.name}`}
      onSubmit={(e) => {
        e.preventDefault();
        rotate.mutate({ path: { id: apiKey.id }, body: { graceSeconds: grace } });
      }}
    >
      <Text>
        A new key with the same name and access replaces this one; give clients the new secret before the old one stops
        working.
      </Text>
      <div className="grid gap-1.5">
        <label htmlFor={graceId}>
          <Text as="span">Old key keeps working for</Text>
        </label>
        <select
          id={graceId}
          className={selectClass}
          value={grace}
          onChange={(e) => setGrace(Number(e.currentTarget.value))}
        >
          {graceChoices.map((c) => (
            <option key={c.seconds} value={c.seconds}>
              {c.label}
            </option>
          ))}
        </select>
      </div>
      <div className="flex gap-2">
        <Button type="submit" variant="primary" disabled={rotate.isPending}>
          Rotate {apiKey.name}
        </Button>
        <Button onClick={onCancel}>Cancel</Button>
      </div>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
    </form>
  );
}
