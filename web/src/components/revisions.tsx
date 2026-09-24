import { Button, Text } from "@cloudflare/kumo";
import { Badge } from "../lib/ui";
import { FieldChanges } from "./diff";

/** One recorded change, as every history screen receives it. */
export interface Revision {
  revision: number;
  action: string;
  createdAt: string;
  actorDisplay?: string;
  actorId?: string;
  diff?: { before?: Record<string, unknown>; after?: Record<string, unknown> } | null;
}

/**
 * A list of recorded changes, newest first, with the version somebody can
 * go back to.
 *
 * Restoring is offered on every version but the newest, because the
 * newest is the one already in force. A restore is recorded as a further
 * change rather than a rewind, so the history of a mistake survives being
 * corrected.
 */
export function RevisionList({
  revisions,
  canRestore,
  restoring,
  onRestore,
  empty,
}: {
  revisions: Revision[];
  canRestore: boolean;
  restoring: boolean;
  onRestore: (revision: number) => void;
  empty: string;
}) {
  if (revisions.length === 0) {
    return <Text variant="secondary">{empty}</Text>;
  }
  return (
    <ul className="grid gap-2">
      {revisions.map((r, index) => (
        <li key={r.revision} className="grid gap-2 rounded-lg px-5 py-4 ring ring-kumo-line">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="grid gap-1">
              <div className="flex items-center gap-2">
                <Text as="span" bold>
                  Version {r.revision}
                </Text>
                <Badge>{r.action}</Badge>
                {index === 0 && <Badge>current</Badge>}
              </div>
              <Text as="span" variant="secondary">
                {new Date(r.createdAt).toLocaleString()}
                {r.actorDisplay ? ` · ${r.actorDisplay}` : ""}
                {/* A change with nobody behind it was recorded by the system
                    itself, such as the state a tool was installed in. */}
                {!r.actorDisplay && !r.actorId ? " · recorded by the system" : ""}
              </Text>
            </div>
            {index !== 0 && canRestore && (
              <Button onClick={() => onRestore(r.revision)} disabled={restoring}>
                Restore this version
              </Button>
            )}
          </div>
          <FieldChanges diff={r.diff} />
        </li>
      ))}
    </ul>
  );
}
