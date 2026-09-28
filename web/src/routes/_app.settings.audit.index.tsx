import { useEffect, useId, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { auditListOptions, auditVerifyOptions } from "../api/@tanstack/react-query.gen";
import {
  auditCategories,
  auditExportHref,
  auditSearchMax,
  auditTypingMs,
  parseAuditSearch,
  type AuditSearch,
} from "../lib/audit";
import { useDebounced } from "../lib/debounce";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";
import { LabelledInput } from "../components/labelled-input";
import { LabelledSelect } from "../components/select";

/**
 * The trail itself: whether its chain still verifies, the filters, the
 * events, and the export of what the filters leave. The filters live in
 * the address, so a reload or a shared link shows the same narrowed trail.
 */
export const Route = createFileRoute("/_app/settings/audit/")({
  component: AuditLog,
  validateSearch: parseAuditSearch,
});

function AuditLog() {
  const { signedIn, can } = useSession();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const allowed = can("audit:read");
  const searchHint = useId();

  // The two text filters are typed into drafts and reach the address, and
  // the server, once typing pauses. The address is where they are read
  // from when the screen opens, so a reload or a shared link shows the
  // same narrowed trail.
  const [draft, setDraft] = useState({ actor: search.actor ?? "", q: search.q ?? "" });
  const settled = useDebounced(draft, auditTypingMs);
  const actor = settled.actor.trim();
  const q = settled.q.trim();
  useEffect(() => {
    if (actor === (search.actor ?? "") && q === (search.q ?? "")) return;
    void navigate({
      search: (prev) => parseAuditSearch({ ...prev, actor, q }),
      replace: true,
    });
  }, [actor, q, search.actor, search.q, navigate]);
  const setCategory = (category: string) =>
    void navigate({
      search: (prev) => parseAuditSearch({ ...prev, category }),
      replace: true,
    });
  const filters: AuditSearch = { category: search.category, actor: actor || undefined, q: q || undefined };

  const events = useQuery({
    ...auditListOptions({ query: { category: filters.category, actorId: filters.actor, q: filters.q, limit: 100 } }),
    enabled: signedIn && allowed,
    retry: false,
    // A new search keeps the previous list on screen until its answer
    // arrives, rather than blanking the table on every pause in typing.
    placeholderData: keepPreviousData,
    // The writer batches, so an event lands a moment after the action that
    // caused it. A screen that only loads once shows an empty trail to
    // someone who just did something, which reads as "nothing was
    // recorded". A search is not repeated on a timer: it is the costly
    // query, and whoever is searching is looking back, not waiting for
    // what comes next.
    refetchInterval: filters.q ? false : 5_000,
    refetchOnWindowFocus: true,
  });

  // The layout above refuses somebody who may not read the trail, so
  // there is nothing to say here that it has not said.
  if (!allowed) return null;

  return (
    <div className="grid gap-6">
      <ChainStatus />

      <div className="flex flex-wrap items-end gap-3">
        <LabelledSelect
          label="Category"
          value={search.category ?? ""}
          onChange={setCategory}
          options={["", ...auditCategories].map((c) => ({ value: c, label: c === "" ? "Everything" : c }))}
        />
        <LabelledInput
          labelClassName="grid flex-1 gap-1.5"
          label="Actor"
          value={draft.actor}
          onChange={(e) => setDraft((d) => ({ ...d, actor: e.target.value }))}
          placeholder="User id"
        />
        <div className="grid flex-[2] gap-1.5">
          <LabelledInput
            label="Search"
            type="search"
            value={draft.q}
            maxLength={auditSearchMax}
            onChange={(e) => setDraft((d) => ({ ...d, q: e.target.value }))}
            placeholder='connector.created, "quarterly review", -denied'
            aria-describedby={searchHint}
          />
          <Text as="span" variant="secondary" id={searchHint}>
            Whole words, any case. An export records its search in the trail, so do not search for a secret.
          </Text>
        </div>
        <a className="rounded-md px-4 py-2 ring ring-kumo-line hover:bg-kumo-tint" href={auditExportHref(filters)}>
          <Text as="span">Export</Text>
        </a>
      </div>

      <table className="w-full text-left">
        <thead>
          <tr className="border-b border-kumo-line">
            <th className="py-2 pr-4">
              <Text as="span" variant="secondary">
                When
              </Text>
            </th>
            <th className="py-2 pr-4">
              <Text as="span" variant="secondary">
                Action
              </Text>
            </th>
            <th className="py-2 pr-4">
              <Text as="span" variant="secondary">
                Who
              </Text>
            </th>
            <th className="py-2 pr-4">
              <Text as="span" variant="secondary">
                On what
              </Text>
            </th>
            <th className="py-2">
              <Text as="span" variant="secondary">
                Outcome
              </Text>
            </th>
          </tr>
        </thead>
        <tbody>
          {events.data?.events?.map((e) => (
            <tr key={e.id} className="border-b border-kumo-line align-top">
              <td className="py-2 pr-4 whitespace-nowrap">
                <Text as="span" variant="secondary">
                  {new Date(e.time).toLocaleString()}
                </Text>
              </td>
              <td className="py-2 pr-4">
                <span className="font-mono text-[0.9em]">{e.action}</span>
              </td>
              <td className="py-2 pr-4">
                <Text as="span">{e.actorDisplay || e.actorId || e.actorKind}</Text>
              </td>
              <td className="py-2 pr-4">
                <Text as="span" variant="secondary">
                  {e.targetDisplay || e.targetId || ""}
                </Text>
              </td>
              <td className="py-2">
                <Badge>{e.outcome}</Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {events.data?.events?.length === 0 && (
        <Text variant="secondary">
          {filters.category || filters.actor || filters.q ? "Nothing matches these filters." : "Nothing recorded yet."}
        </Text>
      )}
    </div>
  );
}

/** Says whether the chain still verifies, which is the whole point of it. */
function ChainStatus() {
  const verify = useQuery({ ...auditVerifyOptions(), retry: false, refetchInterval: 30_000 });
  if (verify.isPending) return null;
  const v = verify.data;
  if (!v) return null;
  return (
    <div className="rounded-lg px-5 py-4 ring ring-kumo-line" role="status">
      <div className="flex flex-wrap items-center gap-2">
        <Text as="span" bold>
          {v.valid ? "The chain is intact" : "The chain is broken"}
        </Text>
        <Badge>{v.checked === 1 ? "1 event checked" : `${v.checked} events checked`}</Badge>
      </div>
      <Text variant="secondary">
        {v.valid
          ? `${v.scrubbed ? `${v.scrubbed} of them had their content removed under a retention rule. ` : ""}Sequence ${v.firstSeq} to ${v.lastSeq} verifies against its hashes${v.anchors ? ` and ${v.anchors === 1 ? "1 checkpoint" : `${v.anchors} checkpoints`}` : ""}.`
          : `${v.explanation ?? "A record does not follow the one before it."} First break at sequence ${v.brokenAt}.`}
      </Text>
    </div>
  );
}

