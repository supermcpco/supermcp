import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import {
  connectorsListOptions,
  serversCreateMutation,
  serversListOptions,
  serversListQueryKey,
  serversUpdateMutation,
} from "../api/@tanstack/react-query.gen";
import type { Server } from "../api/types.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { message } from "../lib/errors";
import { toast } from "../components/shell/toast";

export const Route = createFileRoute("/_app/servers")({
  component: Servers,
});

function Servers() {
  const { signedIn } = useSession();
  const qc = useQueryClient();
  const servers = useQuery({ ...serversListOptions(), enabled: signedIn, retry: false });
  const connectors = useQuery({ ...connectorsListOptions(), enabled: signedIn, retry: false });
  const [name, setName] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    ...serversCreateMutation(),
    onSuccess: async (server) => {
      toast(`MCP server ${server.name} created`);
      setName("");
      setPicked([]);
      setError(null);
      await qc.invalidateQueries({ queryKey: serversListQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          MCP servers
        </Text>
        <Text>Each server is one endpoint you give an AI client. It exposes the connectors you attach, and nothing else.</Text>
      </div>

      <form
        className="grid max-w-3xl gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate({ body: { name, connectorIds: picked } });
        }}
      >
        <Text as="h2" variant="heading3">
          New server
        </Text>
        <label className="grid gap-1.5">
          <Text as="span">Name</Text>
          <Input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Support desk" />
        </label>
        <fieldset className="grid gap-1.5">
          <legend>
            <Text as="span">Connectors</Text>
          </legend>
          {connectors.data?.length === 0 && <Text variant="secondary">Install a connector first.</Text>}
          {connectors.data?.map((c) => (
            <label key={c.id} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={picked.includes(c.id)}
                onChange={(e) => setPicked((p) => (e.target.checked ? [...p, c.id] : p.filter((x) => x !== c.id)))}
              />
              <Text as="span">
                {c.name} ({c.toolCount} tools)
              </Text>
            </label>
          ))}
        </fieldset>
        {error && (
          <div role="alert">
            <Text>{error}</Text>
          </div>
        )}
        <Button type="submit" variant="primary" disabled={create.isPending || !name}>
          {create.isPending ? "Creating…" : "Create server"}
        </Button>
      </form>

      <ul className="grid gap-3">
        {servers.data?.map((s) => (
          <li key={s.id} className="rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="grid gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Text as="span" bold>
                  {s.name}
                </Text>
                {!s.enabled && <Badge>disabled</Badge>}
                <Text as="span" variant="secondary">
                  {s.connectorIds.length === 1 ? "1 connector" : `${s.connectorIds.length} connectors`}
                </Text>
              </div>
              <Endpoint id={s.id} />
              <Sessions server={s} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

/**
 * Whether the endpoint keeps a session per client. Stateful is what lets
 * the server ask the client to confirm a call held for approval; it keeps
 * the session on one replica, so it needs sticky routing.
 */
function Sessions({ server }: { server: Server }) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const update = useMutation({
    ...serversUpdateMutation(),
    onSuccess: async () => {
      setError(null);
      await qc.invalidateQueries({ queryKey: serversListQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });
  return (
    <div className="grid gap-1.5">
      <label className="flex flex-wrap items-center gap-2">
        <Text as="span">Sessions</Text>
        <select
          className={selectClass}
          value={server.sessions}
          disabled={update.isPending}
          onChange={(e) =>
            update.mutate({
              path: { id: server.id },
              body: { sessions: e.currentTarget.value as Server["sessions"], expectedVersion: server.version },
            })
          }
        >
          <option value="stateless">Stateless: any replica answers</option>
          <option value="stateful">Stateful: can ask the client to confirm</option>
        </select>
      </label>
      {server.sessions === "stateful" && (
        <Text variant="secondary">
          Each client keeps to the replica it started on, so the load balancer needs sticky routing. Clients connected
          when this changes have to reconnect.
        </Text>
      )}
      {error && (
        <div role="alert">
          <Text>{error}</Text>
        </div>
      )}
    </div>
  );
}

/** The URL to paste into an AI client, with the copy button next to it. */
function Endpoint({ id }: { id: string }) {
  const url = `${window.location.origin}/mcp/${id}`;
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2">
      <code className="flex-1 overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]">{url}</code>
      <Button
        onClick={() => {
          void navigator.clipboard.writeText(url);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </Button>
    </div>
  );
}
