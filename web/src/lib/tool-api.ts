import { useEffect, useState } from "react";
import { keepPreviousData, useQuery, type QueryClient } from "@tanstack/react-query";
import { toolsDraftDryRun } from "../api";
import {
  connectorsGetQueryKey,
  connectorsListQueryKey,
  connectorsToolsQueryKey,
  toolsGetQueryKey,
  toolsReferencesQueryKey,
  toolsRevisionsListQueryKey,
} from "../api/@tanstack/react-query.gen";
import { details, status } from "./errors";
import { isObject, parseJson, type Json, type Transport } from "./tool-definition";

// What the tool screens share with each other: how to tell the server's
// conflicts apart, what to refresh after a change, and the live preview.

const transports: readonly Transport[] = ["http", "graphql", "database", "soap", "mcp"];

/** A connector's transport, which decides what a tool on it can say. */
export function transportOf(transport: Record<string, unknown> | undefined): Transport {
  const t = transport?.type;
  return typeof t === "string" && (transports as readonly string[]).includes(t) ? (t as Transport) : "http";
}

/** The stable codes a tool write's 409 carries in its problem details. */
export type ConflictCode = "version_conflict" | "name_taken" | "not_deletable" | "references_unacknowledged";

const conflictCodes: readonly string[] = ["version_conflict", "name_taken", "not_deletable", "references_unacknowledged"];

/** Which conflict a failed tool write ran into, if it was one. */
export function conflictCode(e: unknown): ConflictCode | undefined {
  if (status(e) !== 409) return undefined;
  for (const d of details(e)) {
    if (typeof d.value === "string" && conflictCodes.includes(d.value)) return d.value as ConflictCode;
  }
  return undefined;
}

/** The 409 for a rename, delete or restore that approval policies would notice. */
export function isReferencesConflict(e: unknown): boolean {
  return conflictCode(e) === "references_unacknowledged";
}

/** The 409 for a save made against a version somebody has since replaced. */
export function isVersionConflict(e: unknown): boolean {
  return conflictCode(e) === "version_conflict";
}

/** A policy that has to be acknowledged before the change goes through. */
export interface BlockingPolicy {
  id: string;
  name: string;
}

/** The approval policies a references 409 names, one detail each. */
export function blockingPolicies(e: unknown): BlockingPolicy[] {
  return details(e)
    .filter((d) => d.location === "references.approvalPolicies")
    .map((d) => ({ id: String(d.value ?? ""), name: d.message ?? String(d.value ?? "") }));
}

/** Everything that shows a tool, for after it changed. */
export async function invalidateTool(
  qc: QueryClient,
  connectorId: string,
  toolId?: string,
): Promise<void> {
  const keys: unknown[][] = [
    connectorsToolsQueryKey({ path: { id: connectorId } }),
    connectorsGetQueryKey({ path: { id: connectorId } }),
    connectorsListQueryKey(),
  ];
  if (toolId) {
    keys.push(
      toolsGetQueryKey({ path: { id: toolId } }),
      toolsRevisionsListQueryKey({ path: { id: toolId } }),
      toolsReferencesQueryKey({ path: { id: toolId } }),
    );
  }
  await Promise.all(keys.map((queryKey) => qc.invalidateQueries({ queryKey })));
}

/** How long typing has to pause before the draft is sent to be rendered. */
const debounceMs = 400;

/** Turns the arguments text into the plain object the API takes. */
function toPlain(v: Json): unknown {
  if (isObject(v)) return Object.fromEntries([...v].map(([k, item]) => [k, toPlain(item)]));
  if (Array.isArray(v)) return v.map(toPlain);
  return v;
}

/** The arguments text, or why it cannot be sent. */
export function readArguments(text: string): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  if (text.trim() === "") return { ok: true, value: {} };
  try {
    const v = parseJson(text);
    if (!isObject(v)) return { ok: false, error: "Arguments are a JSON object, between { and }." };
    return { ok: true, value: toPlain(v) as Record<string, unknown> };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** A value that only changes once it has stopped changing for a moment. */
function useDebounced<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return settled;
}

/**
 * Asks the server what the unsaved draft would send, and what it thinks of
 * it. The same call answers both, so the form's issues and the preview
 * never disagree about which draft they describe.
 */
export function useDraftDryRun({
  connectorId,
  toolId,
  definition,
  args,
  enabled,
}: {
  connectorId: string;
  toolId?: string;
  /** The draft as JSON text, or null while it does not parse. */
  definition: string | null;
  args: string;
  enabled: boolean;
}) {
  // Each is debounced on its own: a fresh object every render would never
  // settle, and would ask the server again every time it did.
  const settled = { definition: useDebounced(definition, debounceMs), args: useDebounced(args, debounceMs) };
  const parsedArgs = readArguments(settled.args);
  return useQuery({
    queryKey: ["tools-draft-dry-run", connectorId, toolId ?? "", settled.definition, settled.args],
    enabled: enabled && settled.definition !== null && parsedArgs.ok,
    retry: false,
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }) => {
      const { data } = await toolsDraftDryRun({
        path: { id: connectorId },
        body: {
          definition: settled.definition ?? "",
          toolId,
          arguments: parsedArgs.ok ? parsedArgs.value : {},
        },
        signal,
        throwOnError: true,
      });
      return data;
    },
  });
}

