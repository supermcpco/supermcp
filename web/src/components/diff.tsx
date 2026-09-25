import { useMemo, useState } from "react";
import { Button, Text } from "@cloudflare/kumo";
import { asComparableText, changedLines, diffLines, readsSideBySide } from "../lib/diff";

/** How many rows a comparison shows before it asks to be opened up. */
const previewRows = 24;

/**
 * Two versions of a block of text, lined up so the change stands out.
 *
 * The colours are a hint and never the message: every line that differs
 * also carries a marker and a word, because a reader who cannot tell the
 * two tints apart still has to be able to tell what happened.
 */
export function SideBySideDiff({ label, before, after }: { label: string; before: unknown; after: unknown }) {
  const rows = useMemo(() => diffLines(asComparableText(before), asComparableText(after)), [before, after]);
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? rows : rows.slice(0, previewRows);
  const hidden = rows.length - shown.length;

  return (
    <div className="grid gap-2">
      <div className="overflow-x-auto rounded-md ring ring-kumo-line">
        <table className="w-full table-fixed border-collapse text-left font-mono text-[0.8rem]">
          <caption className="sr-only">
            {label}, the version before the change on the left and the version after it on the right. A line marked
            &ldquo;removed&rdquo; is only in the earlier version; a line marked &ldquo;added&rdquo; is only in the later
            one.
          </caption>
          <thead>
            <tr className="bg-kumo-tint">
              <th scope="col" colSpan={2} className="w-1/2 px-3 py-1.5 font-sans font-normal">
                <Text as="span" variant="secondary">
                  Before
                </Text>
              </th>
              <th scope="col" colSpan={2} className="w-1/2 px-3 py-1.5 font-sans font-normal">
                <Text as="span" variant="secondary">
                  After
                </Text>
              </th>
            </tr>
          </thead>
          <tbody>
            {shown.map((row, index) => (
              <tr key={`${row.left?.number ?? "-"}:${row.right?.number ?? "-"}:${index}`} className="align-top">
                <Side cell={row.left} state={row.change === "same" ? "same" : "removed"} />
                <Side cell={row.right} state={row.change === "same" ? "same" : "added"} />
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hidden > 0 && (
        <div>
          <Button onClick={() => setShowAll(true)}>
            Show the other {hidden} {hidden === 1 ? "line" : "lines"}
          </Button>
        </div>
      )}
    </div>
  );
}

/** One version's cell: the line number it has there, and the line. */
function Side({ cell, state }: { cell?: { number: number; text: string }; state: "same" | "removed" | "added" }) {
  const changed = cell !== undefined && state !== "same";
  const tint = !changed ? "" : state === "removed" ? "bg-kumo-danger-tint" : "bg-kumo-success-tint";
  return (
    <>
      <td className={`w-10 px-2 py-0.5 text-right tabular-nums text-kumo-subtle ${tint}`}>{cell?.number ?? ""}</td>
      <td className={`px-2 py-0.5 break-words whitespace-pre-wrap ${tint}`}>
        {changed && (
          <>
            <span className="sr-only">{state === "removed" ? "removed: " : "added: "}</span>
            <span aria-hidden className="pr-1 text-kumo-subtle">
              {state === "removed" ? "−" : "+"}
            </span>
          </>
        )}
        {cell?.text === "" ? " " : cell?.text}
      </td>
    </>
  );
}

/**
 * What one recorded change actually changed, field by field.
 *
 * Short values read better on one line, so they keep the before-and-after
 * they always had. Anything with lines in it — instructions, a JSON
 * schema, a SQL statement, a template — gets the side-by-side view, which
 * is the only way to see which line moved.
 */
export function FieldChanges({ diff }: { diff?: { before?: Record<string, unknown>; after?: Record<string, unknown> } | null }) {
  if (!diff) return null;
  const fields = changedFields(diff);
  if (fields.length === 0) return null;
  return (
    <dl className="grid gap-3 border-t border-kumo-line pt-2">
      {fields.map((field) => {
        const before = diff.before?.[field];
        const after = diff.after?.[field];
        const label = fieldLabel(field);
        return (
          <div key={field} className="grid gap-1">
            <dt>
              <Text as="span" variant="secondary">
                {label}
              </Text>
            </dt>
            <dd>
              {readsSideBySide(before, after) ? (
                <SideBySideDiff label={label} before={before} after={after} />
              ) : (
                <span className="flex flex-wrap items-baseline gap-2">
                  <Text as="span" variant="secondary">
                    {plainly(before)}
                  </Text>
                  <Text as="span" variant="secondary">
                    <span className="sr-only">became</span>
                    <span aria-hidden>&rarr;</span>
                  </Text>
                  <Text as="span">{plainly(after)}</Text>
                </span>
              )}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

/** A one-line summary for a history entry somebody has not opened yet. */
export function ChangeSummary({ diff }: { diff?: { before?: Record<string, unknown>; after?: Record<string, unknown> } | null }) {
  const fields = diff ? changedFields(diff) : [];
  if (fields.length === 0) return null;
  const lines = fields.reduce(
    (total, field) => total + changedLines(diffLines(asComparableText(diff?.before?.[field]), asComparableText(diff?.after?.[field]))),
    0,
  );
  return (
    <Text as="span" variant="secondary">
      {fields.map(fieldLabel).join(", ")} · {lines} {lines === 1 ? "line" : "lines"}
    </Text>
  );
}

/**
 * The fields a reader cares about. Bookkeeping the database owns is not a
 * change anybody made, and a list of it buries the one line that matters.
 */
function changedFields(diff: { before?: Record<string, unknown>; after?: Record<string, unknown> }): string[] {
  const internal = new Set([
    "id",
    "organizationId",
    "createdAt",
    "updatedAt",
    "version",
    "revision",
    "toolCount",
    "credentials",
    "holders",
    "builtIn",
    // A custom detector's: who saved it last is the revision's own
    // author, and its policy name follows from its name.
    "updatedBy",
    "detector",
  ]);
  return [...new Set([...Object.keys(diff.before ?? {}), ...Object.keys(diff.after ?? {})])].filter(
    (field) => !internal.has(field),
  );
}

/** The product's own word for a field, rather than the column's. */
function fieldLabel(field: string): string {
  const named: Record<string, string> = {
    action: "What it does",
    auth: "How it signs in",
    catalogHash: "Catalogue version",
    catalogSlug: "Catalogue entry",
    connectorIds: "Connectors it offers",
    definition: "What the tool expects",
    description: "Description",
    detectors: "Detectors it runs",
    flags: "Case (i ignores it)",
    mustMatch: "Samples it must match",
    mustNotMatch: "Samples it must not match",
    pattern: "Pattern",
    enabled: "Offered to clients",
    instructions: "Instructions",
    name: "Name",
    permissions: "What it allows",
    readOnly: "Locked to the catalogue",
    scan: "What it reads",
    source: "Where it came from",
    transport: "How it is reached",
  };
  if (named[field]) return named[field];
  const spaced = field.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/** Shows a value the way a person reads it, not the way JSON prints it. */
function plainly(value: unknown): string {
  if (value === undefined) return "not set";
  if (value === null) return "empty";
  if (typeof value === "string") return value === "" ? "empty" : value;
  if (typeof value === "boolean") return value ? "on" : "off";
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.length === 0 ? "nothing" : value.join(", ");
  return JSON.stringify(value);
}
