// What the audit explorer keeps in its address, so a narrowed trail can be
// reloaded, bookmarked and handed to a colleague.

export const auditCategories = ["auth", "admin", "tool", "authz", "secrets", "system", "governance"] as const;
export type AuditCategory = (typeof auditCategories)[number];

/** The longest search the server takes. */
export const auditSearchMax = 200;

/** How long typing has to pause before a search or actor is asked for. */
export const auditTypingMs = 300;

export interface AuditSearch {
  category?: AuditCategory;
  actor?: string;
  q?: string;
}

/**
 * Reads the explorer's filters from the address. What it does not know is
 * dropped and blanks are left out, so the plain /settings/audit stays plain.
 * A search longer than the server takes is cut to fit rather than refused.
 */
export function parseAuditSearch(search: Record<string, unknown>): AuditSearch {
  const out: AuditSearch = {};
  if (typeof search.category === "string" && (auditCategories as readonly string[]).includes(search.category)) {
    out.category = search.category as AuditCategory;
  }
  const actor = text(search.actor);
  if (actor) out.actor = actor;
  const q = text(search.q)?.slice(0, auditSearchMax).trim();
  if (q) out.q = q;
  return out;
}

function text(v: unknown): string | undefined {
  // A search of digits alone arrives from the router as a number.
  if (typeof v === "number") return String(v);
  if (typeof v !== "string") return undefined;
  return v.trim() || undefined;
}

/** The export link for exactly what the screen shows. */
export function auditExportHref(search: AuditSearch): string {
  const params = new URLSearchParams();
  if (search.category) params.set("category", search.category);
  if (search.actor) params.set("actorId", search.actor);
  if (search.q) params.set("q", search.q);
  const qs = params.toString();
  return `/api/v1/audit/export${qs ? `?${qs}` : ""}`;
}
