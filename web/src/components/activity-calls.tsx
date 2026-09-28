import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button, Text } from "@cloudflare/kumo";
import { invocationsList } from "../api/sdk.gen";
import { connectorsListOptions, serversListOptions } from "../api/@tanstack/react-query.gen";
import { EmptyState } from "./form-dialog";
import { Described } from "./help-popover";
import { PeriodSelect } from "./period-select";
import {
  callsQuery,
  isFiltered,
  parseActivitySearch,
  statusFilterLabels,
  statusFilters,
  statusLabel,
  type CallsSearch,
} from "../lib/activity";
import { plural } from "../lib/analytics";
import { useDebounced } from "../lib/debounce";
import { message, status as httpStatus } from "../lib/errors";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";
import { LabelledInput } from "./labelled-input";

/** How many of the latest calls the tab shows, with or without filters. */
const shownCalls = 100;

/** How often the plain list asks again, and how often a search does. */
const latestEvery = 10_000;
const searchEvery = 30_000;

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

/**
 * The calls tab of the activity screen: the latest calls AI clients made
 * through this workspace, filtered by the server. The filters live in the
 * address, which the screen owns.
 *
 * With no filter the list is the plain latest calls. Any filter makes it
 * a search, which the server holds to the same limits as the analytics:
 * two at once per workspace. A third is refused, and the tab says so
 * calmly rather than as a failure.
 */
export function CallsPanel({ search, onSearch }: { search: CallsSearch; onSearch: (change: CallsSearch) => void }) {
  const { signedIn, can } = useSession();
  // The server may refuse the MCP server filter to a viewer whose
  // permissions changed since the session was read; the filter is then
  // put away for the rest of the visit.
  const [serverRefused, setServerRefused] = useState(false);
  const mayFilterServers = can("servers:read") && !serverRefused;

  // Typing a name searches once the typing pauses, not at every key.
  const q = useDebounced(search.q ?? "", 400);
  const filters: CallsSearch = {
    status: search.status,
    q: q.trim() || undefined,
    connector: search.connector,
    server: mayFilterServers ? search.server : undefined,
    period: search.period,
  };
  const filtered = isFiltered(filters);

  const connectors = useQuery({ ...connectorsListOptions(), enabled: signedIn, retry: false });
  const servers = useQuery({ ...serversListOptions(), enabled: signedIn && mayFilterServers, retry: false });

  // The period is worked out when the request is made, so each refresh
  // moves it forward to the present.
  const calls = useQuery({
    queryKey: ["activity", "calls", filters],
    queryFn: async ({ signal }) => {
      const query = callsQuery(filters, shownCalls, new Date());
      try {
        const { data } = await invocationsList({ query, signal, throwOnError: true });
        return data ?? [];
      } catch (e) {
        if (httpStatus(e) === 403 && query.serverId) {
          setServerRefused(true);
          onSearch({ server: undefined });
        }
        throw e;
      }
    },
    enabled: signedIn,
    retry: false,
    refetchInterval: filtered ? searchEvery : latestEvery,
    placeholderData: keepPreviousData,
  });

  const rows = calls.data ?? [];
  const busy = calls.isError && httpStatus(calls.error) === 429;
  const names = new Map((connectors.data ?? []).map((c) => [c.id, c.name]));
  const clear = () =>
    onSearch({ status: undefined, q: undefined, connector: undefined, server: undefined, period: undefined });

  return (
    <div className="grid gap-6">
      <Described
        label="About the calls"
        title="What this list holds"
        help={
          <>
            <Text as="p">
              The latest {shownCalls} calls that match the filters, newest first. With no filter the list checks for new
              calls every {latestEvery / 1000} seconds; with one, every {searchEvery / 1000} seconds.
            </Text>
            <Text as="p">
              A filtered list is a search over every call kept, and a workspace runs two searches or analytics queries
              at a time. For counts over a period, open the Analytics tab.
            </Text>
          </>
        }
      >
        Every call an AI client made through this workspace, newest first.
      </Described>

      {/* Held open while the list loads, so the empty and the filled tab start at the same height. */}
      <div className="grid min-h-48 content-start gap-4">
        {calls.isPending && <Loading />}
        {calls.data && !filtered && rows.length === 0 && (
          <EmptyState title="No calls yet">
            Calls appear here once an AI client is connected to one of your MCP servers and uses a tool.{" "}
            <Link to="/servers" className="underline">
              Connect a client
            </Link>
          </EmptyState>
        )}
        {(filtered || rows.length > 0 || calls.isError) && (
          <>
            <div role="search" aria-label="Filter the calls" className="flex flex-wrap items-end gap-4">
              <label className="grid gap-1.5">
                <Text as="span">Status</Text>
                <select
                  className={selectClass}
                  value={search.status ?? "all"}
                  onChange={(e) => onSearch({ status: parseActivitySearch({ status: e.target.value }).status })}
                >
                  {statusFilters.map((s) => (
                    <option key={s} value={s}>
                      {statusFilterLabels[s]}
                    </option>
                  ))}
                </select>
              </label>
              <label className="grid gap-1.5">
                <Text as="span">Connector</Text>
                <select
                  className={selectClass}
                  value={search.connector ?? ""}
                  onChange={(e) => onSearch({ connector: e.target.value || undefined })}
                >
                  <option value="">All connectors</option>
                  {(connectors.data ?? []).map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                  {search.connector && connectors.data && !names.has(search.connector) && (
                    <option value={search.connector}>A removed connector</option>
                  )}
                </select>
              </label>
              {mayFilterServers && (
                <label className="grid gap-1.5">
                  <Text as="span">MCP server</Text>
                  <select
                    className={selectClass}
                    value={search.server ?? ""}
                    onChange={(e) => onSearch({ server: e.target.value || undefined })}
                  >
                    <option value="">All MCP servers</option>
                    {(servers.data ?? []).map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                    {search.server && servers.data && !servers.data.some((s) => s.id === search.server) && (
                      <option value={search.server}>A removed MCP server</option>
                    )}
                  </select>
                </label>
              )}
              <PeriodSelect value={search.period} onChange={(period) => onSearch({ period })} anyLabel="Any time" />
              <LabelledInput
                label="Tool name"
                type="search"
                value={search.q ?? ""}
                onChange={(e) => onSearch({ q: e.target.value })}
                placeholder="Part of a name"
              />
              {calls.data && (
                <Text variant="secondary" aria-live="polite">
                  {rows.length >= shownCalls ? `The latest ${shownCalls} calls` : plural(rows.length, "call")}
                </Text>
              )}
            </div>

            {busy ? (
              <div role="status" className="flex flex-wrap items-center gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
                <Text>Another search is still running, try again in a moment.</Text>
                <Button onClick={() => void calls.refetch()}>Try again</Button>
              </div>
            ) : calls.isError ? (
              <Text role="alert">The calls could not be loaded: {message(calls.error)}</Text>
            ) : calls.data && rows.length === 0 ? (
              <EmptyState title="No calls match" action={<Button onClick={clear}>Clear the filters</Button>}>
                No call kept in this workspace matches all of the filters.
              </EmptyState>
            ) : (
              rows.length > 0 && (
                <table className="w-full text-left" aria-busy={calls.isPlaceholderData}>
                  <caption className="sr-only">Latest tool calls</caption>
                  <thead className="border-b border-kumo-line">
                    <tr>
                      {["Tool", "Connector", "Status", "Duration", "When"].map((h) => (
                        <th key={h} scope="col" className="py-2 pr-4">
                          <Text as="span" variant="secondary">
                            {h}
                          </Text>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((i) => (
                      <tr key={i.id} className="border-b border-kumo-line">
                        <th scope="row" className="py-2 pr-4 font-mono text-[0.9em] font-normal">
                          {i.toolName}
                        </th>
                        <td className="py-2 pr-4">
                          <CallConnector connectorId={i.connectorId} names={connectors.data ? names : undefined} />
                        </td>
                        <td className="py-2 pr-4">
                          {i.status === "success" ? (
                            <Text as="span">{statusLabel(i.status)}</Text>
                          ) : (
                            <Badge>{statusLabel(i.status)}</Badge>
                          )}
                        </td>
                        <td className="py-2 pr-4">
                          <Text as="span">{i.durationMs} ms</Text>
                        </td>
                        <td className="py-2">
                          <Text as="span" variant="secondary">
                            {new Date(i.createdAt).toLocaleString()}
                          </Text>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}
          </>
        )}
      </div>
    </div>
  );
}

/**
 * Which connector a call went to, as a link to it. A call that reached no
 * connector says so with a dash, and one whose connector has since been
 * removed says that rather than offering a link that leads nowhere.
 * `names` is undefined while the connectors are still being read; the
 * link is offered meanwhile, since most calls go to a connector that is
 * still there.
 */
export function CallConnector({ connectorId, names }: { connectorId?: string; names: Map<string, string> | undefined }) {
  if (!connectorId) {
    return (
      <Text as="span" variant="secondary">
        –
      </Text>
    );
  }
  if (names && !names.has(connectorId)) {
    return (
      <Text as="span" variant="secondary">
        A removed connector
      </Text>
    );
  }
  return (
    <Link to="/connectors/$id" params={{ id: connectorId }} className="underline">
      <Text as="span">{names?.get(connectorId) ?? "Open the connector"}</Text>
    </Link>
  );
}
