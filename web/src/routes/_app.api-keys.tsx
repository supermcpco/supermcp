import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  keysCreateMutation,
  keysListOptions,
  keysListQueryKey,
  keysRevokeMutation,
  keysRotateMutation,
} from "../api/@tanstack/react-query.gen";
import type { ApiKeyDto, RotatedKeyDto } from "../api/types.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { message } from "../lib/errors";
import { canRotate, defaultGraceSeconds, graceChoices, stopsWorking } from "../lib/key-rotation";

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

function APIKeys() {
  const { signedIn } = useSession();
  const qc = useQueryClient();
  const keys = useQuery({ ...keysListOptions(), enabled: signedIn, retry: false });
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState<keyof typeof purposes>("client");
  const [secret, setSecret] = useState<string | null>(null);
  // Set when the secret on show replaced a key: which one, and when it stops.
  const [replaced, setReplaced] = useState<{ prefix: string; expiresAt: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);

  const create = useMutation({
    ...keysCreateMutation(),
    onSuccess: async (res) => {
      setSecret(res.secret);
      setReplaced(null);
      setName("");
      setError(null);
      await qc.invalidateQueries({ queryKey: keysListQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });
  const revoke = useMutation({
    ...keysRevokeMutation(),
    onSuccess: () => qc.invalidateQueries({ queryKey: keysListQueryKey() }),
  });

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          API keys
        </Text>
        <Text>A key authenticates an AI client to your MCP servers. The secret is shown once, when you create it.</Text>
      </div>

      {secret && (
        <div className="grid gap-1.5 rounded-lg px-5 py-4 ring ring-kumo-line" role="alert">
          <Text as="h2" variant="heading3">
            Copy this key now
          </Text>
          <Text variant="secondary">It is not stored and cannot be shown again.</Text>
          <code className="overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]">{secret}</code>
          {replaced && (
            <Text>
              This replaces <span className="font-mono text-[0.9em]">smk_{replaced.prefix}…</span>.{" "}
              {stopsWorking(replaced.expiresAt)}
            </Text>
          )}
          <div className="flex gap-2">
            <Button onClick={() => void navigator.clipboard.writeText(secret)}>Copy</Button>
            <Button
              onClick={() => {
                setSecret(null);
                setReplaced(null);
              }}
            >
              Done
            </Button>
          </div>
        </div>
      )}

      <form
        className="flex flex-wrap items-end gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
        onSubmit={(e) => {
          e.preventDefault();
          const scopes = purposes[purpose];
          create.mutate({ body: scopes ? { name, scopes: [...scopes] } : { name } });
        }}
      >
        <label className="grid flex-1 gap-1.5">
          <Text as="span">Name</Text>
          <Input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Claude Desktop" />
        </label>
        <label className="grid gap-1.5">
          <Text as="span">For</Text>
          <select
            className={selectClass}
            value={purpose}
            onChange={(e) => setPurpose(e.currentTarget.value as keyof typeof purposes)}
          >
            <option value="client">An AI client</option>
            <option value="scim">SCIM provisioning</option>
          </select>
        </label>
        <Button type="submit" variant="primary" disabled={create.isPending || !name}>
          Create key
        </Button>
      </form>
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}

      <ul className="grid gap-2">
        {keys.data?.map((k) => (
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
                <Button onClick={() => revoke.mutate({ path: { id: k.id } })} disabled={revoke.isPending}>
                  Revoke<span className="sr-only"> {k.name}</span>
                </Button>
              )}
            </div>
            {rotating === k.id && (
              <ConfirmRotate
                apiKey={k}
                onRotated={(res) => {
                  setSecret(res.secret);
                  setReplaced({ prefix: k.prefix, expiresAt: res.previousExpiresAt });
                  setRotating(null);
                }}
                onCancel={() => setRotating(null)}
              />
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Asks how long the old key should keep working before it is replaced.
 * The replacement's secret is handed back to the screen, which shows it
 * once in the same place a new key's secret appears.
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
  const [error, setError] = useState<string | null>(null);
  const rotate = useMutation({
    ...keysRotateMutation(),
    onSuccess: async (res) => {
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
        A new key with the same name and access replaces this one. Clients using the old key need the new secret before
        the old key stops working.
      </Text>
      <label className="grid gap-1.5">
        <Text as="span">Old key keeps working for</Text>
        <select className={selectClass} value={grace} onChange={(e) => setGrace(Number(e.currentTarget.value))}>
          {graceChoices.map((c) => (
            <option key={c.seconds} value={c.seconds}>
              {c.label}
            </option>
          ))}
        </select>
      </label>
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
