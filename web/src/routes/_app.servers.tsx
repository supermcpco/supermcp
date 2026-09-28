import { useId, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Collapsible, Dialog, DialogRoot, DialogTitle, Input, Text } from "@cloudflare/kumo";
import {
  connectorsListOptions,
  serversCreateMutation,
  serversListOptions,
  serversListQueryKey,
  serversUpdateMutation,
} from "../api/@tanstack/react-query.gen";
import type { Server } from "../api/types.gen";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";
import { message } from "../lib/errors";
import { toast } from "../components/shell/toast";
import { ConnectClient, Endpoint } from "../components/connect-client";
import { EmptyState, HeaderWithAction } from "../components/form-dialog";

export const Route = createFileRoute("/_app/servers")({
  component: Servers,
});

function Servers() {
  const { signedIn, can } = useSession();
  const servers = useQuery({ ...serversListOptions(), enabled: signedIn, retry: false });
  const list = servers.data ?? [];
  const [creating, setCreating] = useState(false);
  const mayCreate = can("servers:create");
  const newServer = mayCreate && (
    <Button variant="primary" onClick={() => setCreating(true)}>
      Create server
    </Button>
  );

  return (
    <div className="grid gap-6">
      <HeaderWithAction action={newServer}>
        <Text as="h1" variant="heading" size="lg">
          MCP servers
        </Text>
        <Text>Each server is one endpoint you give an AI client, offering only the connectors you attach.</Text>
      </HeaderWithAction>

      {servers.isPending && <Loading />}
      {servers.isError && (
        <div role="alert">
          <Text>{message(servers.error)}</Text>
        </div>
      )}
      {servers.isSuccess && list.length === 0 && (
        <EmptyState title="No MCP servers yet" action={newServer}>
          Create one, attach connectors to it, and give its endpoint to an AI client.
        </EmptyState>
      )}

      <ul className="grid gap-3">
        {list.map((s) => (
          <li key={s.id} className="rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="grid gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Text as="span" bold>
                  {s.name}
                </Text>
                {!s.enabled && <Badge>disabled</Badge>}
                <Text as="span" variant="secondary">
                  {s.connectorIds.length === 1 ? "1 connector" : `${s.connectorIds.length} connectors`}
                </Text>
              </div>
              <Endpoint serverId={s.id} of={s.name} />
              <Sessions server={s} />
              <ConnectPanel server={s} />
            </div>
          </li>
        ))}
      </ul>

      {mayCreate && <NewServerDialog open={creating} onClose={() => setCreating(false)} />}
    </div>
  );
}

/** The snippets for one server, folded away until asked for. */
function ConnectPanel({ server }: { server: Server }) {
  const [open, setOpen] = useState(false);
  return (
    <Collapsible.Root open={open} onOpenChange={setOpen}>
      <Collapsible.Trigger render={<Button />}>
        {open ? "Hide connection details" : "Connect a client"}
        <span className="sr-only"> to {server.name}</span>
      </Collapsible.Trigger>
      <Collapsible.Panel className="mt-3 border-t border-kumo-line pt-3">
        <ConnectClient server={server} />
      </Collapsible.Panel>
    </Collapsible.Root>
  );
}

/**
 * The form for a new server, in a dialog so the list keeps the screen.
 * Mounted per opening, so a name typed and abandoned is not there next time.
 */
function NewServerDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <DialogRoot open={open} onOpenChange={(next) => !next && onClose()}>
      {open && (
        <Dialog size="lg" className="grid gap-4 p-6">
          <DialogTitle className="text-lg font-semibold">New server</DialogTitle>
          <NewServerForm onDone={onClose} />
        </Dialog>
      )}
    </DialogRoot>
  );
}

function NewServerForm({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const connectors = useQuery({ ...connectorsListOptions(), retry: false });
  const [name, setName] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    ...serversCreateMutation(),
    onSuccess: async (server) => {
      toast(`MCP server ${server.name} created`);
      await qc.invalidateQueries({ queryKey: serversListQueryKey() });
      onDone();
    },
    onError: (e) => setError(message(e)),
  });

  return (
    <form
      className="grid gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        create.mutate({ body: { name, connectorIds: picked } });
      }}
    >
      <label className="grid gap-1.5">
        <Text as="span">Name</Text>
        <Input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Support desk" />
      </label>
      <fieldset className="grid gap-1.5">
        <legend>
          <Text as="span">Connectors</Text>
        </legend>
        {connectors.isPending && <Text variant="secondary">Loading…</Text>}
        {connectors.isError && <Text variant="secondary">{message(connectors.error)}</Text>}
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
      <div className="flex justify-end gap-2">
        <Button onClick={onDone}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={create.isPending || !name}>
          {create.isPending ? "Creating…" : "Create server"}
        </Button>
      </div>
    </form>
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
  const selectId = useId();
  const [error, setError] = useState<string | null>(null);
  const update = useMutation({
    ...serversUpdateMutation(),
    onSuccess: async (updated) => {
      setError(null);
      toast(`${updated.name} now uses ${updated.sessions} sessions`);
      await qc.invalidateQueries({ queryKey: serversListQueryKey() });
    },
    onError: (e) => setError(message(e)),
  });
  return (
    <div className="grid gap-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={selectId}>
          <Text as="span">Sessions</Text>
        </label>
        <select
          id={selectId}
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
      </div>
      {server.sessions === "stateful" && (
        <Text variant="secondary">
          Each client keeps to one replica, so this needs sticky routing; connected clients must reconnect.
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
