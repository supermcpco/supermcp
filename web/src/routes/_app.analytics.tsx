import { useId, useMemo } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { analyticsUsage } from "../api/sdk.gen";
import type { UsageReport } from "../api/types.gen";
import { Chart, type ChartOption } from "../components/chart";
import {
  bucketLabel,
  defaultDimension,
  defaultRange,
  allowedDimensions,
  refreshInterval,
  refreshLabel,
  dimensionLabels,
  errorRate,
  formatMs,
  groupName,
  parseAnalyticsSearch,
  plural,
  rangeLabels,
  ranges,
  usageWindow,
  type Dimension,
  type Range,
} from "../lib/analytics";
import { message } from "../lib/errors";
import { useSession } from "../lib/session";
import { Loading } from "../lib/ui";

export const Route = createFileRoute("/_app/analytics")({
  component: Analytics,
  validateSearch: parseAnalyticsSearch,
});

function Analytics() {
  const { signedIn, can } = useSession();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const range = search.range ?? defaultRange;
  const allowed = can("connectors:read");
  const choices = allowedDimensions(can("servers:read"));
  const by = search.by && choices.includes(search.by) ? search.by : defaultDimension;

  // The window is worked out when the request is made, not when the
  // screen renders, so each refresh moves it forward to the present.
  const usage = useQuery({
    queryKey: ["analytics", "usage", range, by],
    queryFn: async ({ signal }) => {
      const { data } = await analyticsUsage({
        query: { ...usageWindow(range, new Date()), by },
        signal,
        throwOnError: true,
      });
      return data;
    },
    enabled: signedIn && allowed,
    retry: false,
    refetchInterval: refreshInterval(range),
    placeholderData: keepPreviousData,
  });

  if (!allowed) {
    return <Text>You do not have permission to see this workspace's tool calls.</Text>;
  }

  const setSearch = (next: { range?: Range; by?: Dimension }) =>
    navigate({
      search: (prev) => {
        const merged = { ...prev, ...next };
        return {
          ...(merged.range && merged.range !== defaultRange ? { range: merged.range } : {}),
          ...(merged.by && merged.by !== defaultDimension ? { by: merged.by } : {}),
        };
      },
      replace: true,
    });

  const report = usage.data;
  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Analytics
        </Text>
        <Text>How much this workspace's tools are called, how often the calls fail, and how long they take.</Text>
      </div>

      <label className="grid w-fit gap-1.5">
        <Text as="span">Period</Text>
        <select
          className="rounded-md border border-kumo-line bg-kumo-base px-3 py-2"
          value={range}
          onChange={(e) => setSearch(parseAnalyticsSearch({ range: e.target.value }))}
        >
          {ranges.map((r) => (
            <option key={r} value={r}>
              {rangeLabels[r]}
            </option>
          ))}
        </select>
      </label>

      {usage.isError && (
        <Text role="alert">The figures could not be loaded: {message(usage.error)}</Text>
      )}
      {usage.isPending && <Loading />}
      {report && report.totals.calls === 0 && (
        <Text variant="secondary">
          No tool calls in this period. This screen checks again every {refreshLabel(range)}.
        </Text>
      )}
      {report && report.totals.calls > 0 && (
        <>
          <Totals report={report} />
          <Charts report={report} />
          <Top report={report} by={by} choices={choices} onBy={(next) => setSearch({ by: next })} />
        </>
      )}
    </div>
  );
}

/** The period in figures: what a chart shows, said so everybody can read it. */
function Totals({ report }: { report: UsageReport }) {
  const id = useId();
  const t = report.totals;
  const figures = [
    { label: "Calls", value: t.calls.toLocaleString() },
    { label: "Errors", value: `${t.errors.toLocaleString()} (${errorRate(t.calls, t.errors)})` },
    { label: "Median duration", value: formatMs(t.p50Ms) },
    { label: "95th percentile duration", value: formatMs(t.p95Ms) },
  ];
  return (
    <section aria-label="Totals for the period" className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {figures.map((f, i) => (
        // A group named by its label, so the figure can be found by what it is.
        <div
          key={f.label}
          role="group"
          aria-labelledby={`${id}-${i}`}
          className="grid gap-1 rounded-lg px-4 py-3 ring ring-kumo-line"
        >
          <Text as="span" variant="secondary" id={`${id}-${i}`}>
            {f.label}
          </Text>
          <Text as="p" variant="heading3">
            {f.value}
          </Text>
        </div>
      ))}
    </section>
  );
}

function Charts({ report }: { report: UsageReport }) {
  const { volume, latency } = useMemo(() => chartOptions(report), [report]);
  const t = report.totals;
  return (
    <div className="grid gap-6 xl:grid-cols-2">
      <section aria-labelledby="calls-over-time" className="grid gap-2">
        <Text as="h2" variant="heading3" id="calls-over-time">
          Calls and errors
        </Text>
        <Chart
          option={volume}
          label={`Calls and errors per ${report.bucket}: ${plural(t.calls, "call")} and ${plural(t.errors, "error")} in total.`}
        />
      </section>
      <section aria-labelledby="latency-over-time" className="grid gap-2">
        <Text as="h2" variant="heading3" id="latency-over-time">
          Duration
        </Text>
        <Chart
          option={latency}
          label={`Median and 95th percentile call duration per ${report.bucket}: ${formatMs(t.p50Ms)} and ${formatMs(t.p95Ms)} over the period.`}
        />
      </section>
    </div>
  );
}

function chartOptions(report: UsageReport): { volume: ChartOption; latency: ChartOption } {
  const x = report.series.map((p) => bucketLabel(p.start, report.bucket));
  const grid = { left: 48, right: 16, top: 32, bottom: 32 };
  const axis = { type: "category" as const, data: x };
  // Drawn on the canvas rather than as HTML: the HTML tooltip writes its
  // markup through innerHTML with inline styles, which the page's content
  // security policy (style-src 'self') refuses.
  const tooltip = { trigger: "axis" as const, renderMode: "richText" as const };
  return {
    volume: {
      grid,
      legend: { top: 0 },
      tooltip,
      xAxis: axis,
      yAxis: { type: "value", minInterval: 1 },
      series: [
        { name: "Calls", type: "bar", data: report.series.map((p) => p.calls) },
        { name: "Errors", type: "bar", data: report.series.map((p) => p.errors) },
      ],
    },
    latency: {
      grid,
      legend: { top: 0 },
      tooltip: { ...tooltip, valueFormatter: (v) => (typeof v === "number" ? formatMs(v) : "–") },
      xAxis: axis,
      yAxis: { type: "value", axisLabel: { formatter: "{value} ms" } },
      series: [
        { name: "p50", type: "line", connectNulls: false, data: report.series.map((p) => p.p50Ms ?? null) },
        { name: "p95", type: "line", connectNulls: false, data: report.series.map((p) => p.p95Ms ?? null) },
      ],
    },
  };
}

function Top({
  report,
  by,
  choices,
  onBy,
}: {
  report: UsageReport;
  by: Dimension;
  choices: readonly Dimension[];
  onBy: (by: Dimension) => void;
}) {
  const noun = dimensionLabels[by];
  return (
    <section aria-labelledby="top-heading" className="grid gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <Text as="h2" variant="heading3" id="top-heading">
          Busiest by {noun.toLowerCase()}
        </Text>
        <div role="radiogroup" aria-label="Break down by" className="flex gap-1">
          {choices.map((d) => (
            <button
              key={d}
              type="button"
              role="radio"
              aria-checked={d === by}
              onClick={() => onBy(d)}
              className={`rounded-md px-3 py-1.5 ring ring-kumo-line ${d === by ? "bg-kumo-tint font-medium" : "hover:bg-kumo-tint"}`}
            >
              <Text as="span">{dimensionLabels[d]}</Text>
            </button>
          ))}
        </div>
      </div>
      <table className="w-full text-left">
        <caption className="sr-only">
          The {report.top.length} busiest by {noun.toLowerCase()} in the period
        </caption>
        <thead className="border-b border-kumo-line">
          <tr>
            <th scope="col" className="py-2 pr-4">
              <Text as="span" variant="secondary">
                {noun}
              </Text>
            </th>
            <th scope="col" className="py-2 pr-4 text-right">
              <Text as="span" variant="secondary">
                Calls
              </Text>
            </th>
            <th scope="col" className="py-2 pr-4 text-right">
              <Text as="span" variant="secondary">
                Errors
              </Text>
            </th>
            <th scope="col" className="py-2 pr-4 text-right">
              <Text as="span" variant="secondary">
                Median
              </Text>
            </th>
            <th scope="col" className="py-2 text-right">
              <Text as="span" variant="secondary">
                95th percentile
              </Text>
            </th>
          </tr>
        </thead>
        <tbody>
          {report.top.map((g) => (
            <tr key={g.id || "none"} className="border-b border-kumo-line">
              <th scope="row" className="py-2 pr-4 font-normal">
                <Text as="span">{groupName(by, g.id, g.name)}</Text>
              </th>
              <td className="py-2 pr-4 text-right">
                <Text as="span">{g.calls.toLocaleString()}</Text>
              </td>
              <td className="py-2 pr-4 text-right">
                <Text as="span">
                  {g.errors.toLocaleString()} ({errorRate(g.calls, g.errors)})
                </Text>
              </td>
              <td className="py-2 pr-4 text-right">
                <Text as="span">{formatMs(g.p50Ms)}</Text>
              </td>
              <td className="py-2 text-right">
                <Text as="span">{formatMs(g.p95Ms)}</Text>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
