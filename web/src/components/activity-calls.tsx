import { useQuery } from "@tanstack/react-query";
import { Button, Input, LinkButton, Text } from "@cloudflare/kumo";
import { invocationsListOptions } from "../api/@tanstack/react-query.gen";
import { EmptyState } from "./form-dialog";
import { Described } from "./help-popover";
import { filterCalls, statusFilterLabels, statusFilters, statusLabel, type CallsSearch } from "../lib/activity";
import { message } from "../lib/errors";
import { useSession } from "../lib/session";
import { Badge, Loading } from "../lib/ui";

/** How many of the latest calls the tab loads; the filters work over these. */
const shownCalls = 100;

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

/**
 * The calls tab of the activity screen: the latest calls AI clients made
 * through this workspace. The API returns the newest calls and takes no
 * filter, so the status and name filters work over the rows loaded here.
 * They live in the address, which the screen owns.
 */
export function CallsPanel({ search, onSearch }: { search: CallsSearch; onSearch: (change: CallsSearch) => void }) {
  const { signedIn } = useSession();
  const q = useQuery({
    ...invocationsListOptions({ query: { limit: shownCalls } }),
    enabled: signedIn,
    retry: false,
    refetchInterval: 10_000,
  });

  const calls = q.data ?? [];
  const shown = filterCalls(calls, search);
  const filtered = search.status !== undefined || search.q !== undefined;

  return (
    <div className="grid gap-6">
      <Described
        label="About the calls"
        title="What this list holds"
        help={
          <>
            <Text as="p">
              The latest {shownCalls} calls, newest first. The list checks for new ones every 10 seconds.
            </Text>
            <Text as="p">
              The filters search those {shownCalls} calls only. For counts over a longer period, open the Analytics tab.
            </Text>
          </>
        }
      >
        Every call an AI client made through this workspace, newest first.
      </Described>

      {/* Held open while the list loads, so the empty and the filled tab start at the same height. */}
      <div className="grid min-h-48 content-start gap-4">
        {q.isError && <Text role="alert">The calls could not be loaded: {message(q.error)}</Text>}
        {q.isPending && <Loading />}
        {q.data && calls.length === 0 && (
          <EmptyState
            action={
              <LinkButton href="/servers" variant="primary">
                Connect a client
              </LinkButton>
            }
          >
            <strong className="block font-semibold text-kumo-default">No calls yet</strong>
            Calls appear here once an AI client is connected to one of your MCP servers and uses a tool.
          </EmptyState>
        )}
        {calls.length > 0 && (
          <>
            <div role="search" aria-label="Filter the calls" className="flex flex-wrap items-end gap-4">
              <label className="grid gap-1.5">
                <Text as="span">Status</Text>
                <select
                  className={selectClass}
                  value={search.status ?? "all"}
                  onChange={(e) => {
                    const v = e.target.value;
                    onSearch({ status: v === "success" || v === "failed" ? v : undefined });
                  }}
                >
                  {statusFilters.map((s) => (
                    <option key={s} value={s}>
                      {statusFilterLabels[s]}
                    </option>
                  ))}
                </select>
              </label>
              <label className="grid gap-1.5">
                <Text as="span">Tool name</Text>
                <Input
                  type="search"
                  value={search.q ?? ""}
                  onChange={(e) => onSearch({ q: e.target.value })}
                  placeholder="Part of a name"
                />
              </label>
              <Text variant="secondary" aria-live="polite">
                {filtered ? `${shown.length} of ${calls.length} calls` : `${calls.length} calls`}
              </Text>
            </div>

            {shown.length === 0 ? (
              <EmptyState action={<Button onClick={() => onSearch({ status: undefined, q: undefined })}>Clear the filters</Button>}>
                <strong className="block font-semibold text-kumo-default">No calls match</strong>
                None of the latest {calls.length} calls has that status and a tool name containing what was typed.
              </EmptyState>
            ) : (
              <table className="w-full text-left">
                <caption className="sr-only">Latest tool calls</caption>
                <thead className="border-b border-kumo-line">
                  <tr>
                    <th scope="col" className="py-2 pr-4">
                      <Text as="span" variant="secondary">
                        Tool
                      </Text>
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      <Text as="span" variant="secondary">
                        Status
                      </Text>
                    </th>
                    <th scope="col" className="py-2 pr-4">
                      <Text as="span" variant="secondary">
                        Duration
                      </Text>
                    </th>
                    <th scope="col" className="py-2">
                      <Text as="span" variant="secondary">
                        When
                      </Text>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((i) => (
                    <tr key={i.id} className="border-b border-kumo-line">
                      <th scope="row" className="py-2 pr-4 font-mono text-[0.9em] font-normal">
                        {i.toolName}
                      </th>
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
            )}
          </>
        )}
      </div>
    </div>
  );
}
