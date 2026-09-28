import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { CheckCircle, Circle } from "@phosphor-icons/react";
import {
  catalogListOptions,
  connectorsListOptions,
  invocationsListOptions,
  keysListOptions,
  serversListOptions,
} from "../api/@tanstack/react-query.gen";
import type { InvocationDto, Server } from "../api/types.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { message } from "../lib/errors";
import { countLabel, isSetUp, isUndecided, setupSteps, summarizeLastDay, type SetupStep } from "../lib/setup";
import { ConnectClient, Endpoint } from "../components/connect-client";

export const Route = createFileRoute("/_app/")({
  component: Overview,
});

// As many calls as the server hands back at once: the day's counts are
// taken from these, so the more the better.
const callLimit = 500;

function Overview() {
  const { signedIn, can } = useSession();
  const may = {
    connectors: can("connectors:read"),
    servers: can("servers:read"),
    keys: can("apikeys:self:manage"),
    // The tool-call list asks for the same permission as the connectors.
    calls: can("connectors:read"),
  };
  const catalog = useQuery(catalogListOptions({}));
  const connectors = useQuery({ ...connectorsListOptions(), enabled: signedIn && may.connectors, retry: false });
  const servers = useQuery({ ...serversListOptions(), enabled: signedIn && may.servers, retry: false });
  const keys = useQuery({ ...keysListOptions(), enabled: signedIn && may.keys, retry: false });
  const calls = useQuery({
    ...invocationsListOptions({ query: { limit: callLimit } }),
    enabled: signedIn && may.calls,
    retry: false,
    refetchInterval: 10_000,
  });

  // The server answers an empty list as null; that is still an answer.
  const connectorList = answered(connectors.data);
  const serverList = answered(servers.data);
  const callList = answered(calls.data);
  const steps = setupSteps({
    connectors: { readable: may.connectors, data: connectorList },
    servers: { readable: may.servers, data: serverList },
    keys: { readable: may.keys, data: answered(keys.data) },
    calls: { readable: may.calls, data: callList },
  });
  const failed = [connectors, servers, keys, calls].filter((q) => q.isError);
  const loading = isUndecided(steps) && failed.length === 0;

  const total = catalog.data?.count ?? 0;
  const keyless = catalog.data?.adapters.filter((a) => a.keyless).length ?? 0;

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Overview
        </Text>
        <Text>Turn the systems you already run into tools for Claude, ChatGPT and Copilot.</Text>
      </div>

      {failed.map((q, i) => (
        <div key={i} role="alert">
          <Text>{message(q.error)}</Text>
        </div>
      ))}

      {/* One height for all three states, so the page does not jump when the answer arrives. */}
      <div className="min-h-[28rem]">
        {loading ? (
          <Text variant="secondary" aria-busy="true">
            Loading…
          </Text>
        ) : isSetUp(steps) ? (
          <Dashboard
            connectors={connectorList?.length}
            servers={serverList}
            calls={callList}
          />
        ) : (
          <Checklist
            steps={steps}
            firstServer={serverList?.[0]}
            catalog={catalog.data ? { total, keyless } : undefined}
          />
        )}
      </div>
    </div>
  );
}

function answered<T>(data: T[] | null | undefined): T[] | undefined {
  return data === null ? [] : data;
}

function Checklist({
  steps,
  firstServer,
  catalog,
}: {
  steps: SetupStep[];
  firstServer?: Server;
  /** How many adapters the catalog offers, said beside the step that opens it. */
  catalog?: { total: number; keyless: number };
}) {
  const doneCount = steps.filter((s) => s.done === true).length;
  const current = steps.find((s) => s.done !== true);
  return (
    <section aria-labelledby="setup-heading" className="grid max-w-3xl gap-4">
      <div className="grid gap-1">
        <Text as="h2" variant="heading3">
          <span id="setup-heading">Set up your workspace</span>
        </Text>
        <Text variant="secondary">
          {doneCount} of {steps.length} steps done.
        </Text>
      </div>
      <ol className="grid gap-3">
        {steps.map((s, i) => (
          <li key={s.id} className="rounded-lg px-5 py-4 ring ring-kumo-line">
            <div className="flex items-start gap-3">
              <span aria-hidden="true" className="mt-0.5">
                {s.done ? <CheckCircle size={20} weight="fill" /> : <Circle size={20} />}
              </span>
              <div className="grid flex-1 gap-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <Text as="h3" bold>
                    {i + 1}. {s.title}
                  </Text>
                  <Text as="span" variant="secondary">
                    {s.done === true ? "Done" : s.done === false ? "To do" : "Could not check"}
                  </Text>
                </div>
                {s.done !== true && <Text variant="secondary">{s.description}</Text>}
                {s.done !== true && (
                  <Text>
                    <Link to={s.to} className="underline">
                      {s.action}
                    </Link>
                    {s.id === "connector" && catalog && (
                      <Text as="span" variant="secondary">
                        {" "}
                        · {catalog.total} adapters, {catalog.keyless} needing no credentials
                      </Text>
                    )}
                  </Text>
                )}
                {s === current && s.id === "client" && firstServer && (
                  <div className="mt-2 border-t border-kumo-line pt-3">
                    <ConnectClient server={firstServer} showEndpoint />
                  </div>
                )}
              </div>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function Dashboard({
  connectors,
  servers,
  calls,
}: {
  connectors: number | undefined;
  servers: Server[] | undefined;
  calls: InvocationDto[] | undefined;
}) {
  const day = calls ? summarizeLastDay(calls, callLimit) : undefined;
  const recent = calls?.slice(0, 10) ?? [];
  return (
    <div className="grid gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {connectors !== undefined && <Stat label="Connectors" value={String(connectors)} />}
        {servers && <Stat label="MCP servers" value={String(servers.length)} />}
        {day && <Stat label="Calls in the last 24 hours" value={countLabel(day.calls, day.atLeast)} />}
        {day && <Stat label="Failures in the last 24 hours" value={countLabel(day.failures, day.atLeast)} />}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {calls && (
          <section aria-labelledby="recent-heading" className="grid content-start gap-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <Text as="h2" variant="heading3">
                <span id="recent-heading">Recent tool calls</span>
              </Text>
              <Link to="/tool-calls" className="underline">
                <Text as="span">All tool calls</Text>
              </Link>
            </div>
            {recent.length === 0 ? (
              <Text variant="secondary">No calls yet.</Text>
            ) : (
              <table className="w-full">
                <thead className="border-b border-kumo-line text-left">
                  <tr>
                    <th className="py-2">
                      <Text as="span" variant="secondary">
                        Tool
                      </Text>
                    </th>
                    <th className="py-2">
                      <Text as="span" variant="secondary">
                        Status
                      </Text>
                    </th>
                    <th className="py-2">
                      <Text as="span" variant="secondary">
                        Duration
                      </Text>
                    </th>
                    <th className="py-2">
                      <Text as="span" variant="secondary">
                        When
                      </Text>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((c) => (
                    <tr key={c.id} className="border-b border-kumo-line">
                      <td className="py-2 font-mono text-[0.9em] break-all">{c.toolName}</td>
                      <td className="py-2">
                        {c.status === "success" ? <Text as="span">ok</Text> : <Badge>{c.status}</Badge>}
                      </td>
                      <td className="py-2">
                        <Text as="span">{c.durationMs} ms</Text>
                      </td>
                      <td className="py-2">
                        <Text as="span" variant="secondary">
                          {new Date(c.createdAt).toLocaleString()}
                        </Text>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )}

        {servers && (
          <section aria-labelledby="servers-heading" className="grid content-start gap-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <Text as="h2" variant="heading3">
                <span id="servers-heading">MCP servers</span>
              </Text>
              <Link to="/servers" className="underline">
                <Text as="span">Manage servers</Text>
              </Link>
            </div>
            <ul className="grid gap-3">
              {servers.map((s) => (
                <li key={s.id} className="grid gap-2 rounded-lg px-5 py-4 ring ring-kumo-line">
                  <div className="flex flex-wrap items-center gap-2">
                    <Text as="span" bold>
                      {s.name}
                    </Text>
                    {!s.enabled && <Badge>disabled</Badge>}
                  </div>
                  <Endpoint serverId={s.id} of={s.name} />
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg px-5 py-4 ring ring-kumo-line">
      <div className="grid gap-1">
        <Text as="span" variant="secondary">
          {label}
        </Text>
        <Text as="span" variant="heading2">
          {value}
        </Text>
      </div>
    </div>
  );
}
