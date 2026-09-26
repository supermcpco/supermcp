/** Pulls the server's problem detail out of a failed request. */
export function message(e: unknown): string {
  const detail = (e as { detail?: string; message?: string } | undefined)?.detail;
  if (detail) return detail;
  const msg = (e as { message?: string } | undefined)?.message;
  return msg || "Something went wrong.";
}

/** The HTTP status a failed request carried, when the server said. */
export function status(e: unknown): number | undefined {
  const s = (e as { status?: unknown } | undefined)?.status;
  return typeof s === "number" ? s : undefined;
}

/** The per-field details of a problem (a 422 lists one per thing wrong). */
export function details(e: unknown): { location?: string; message?: string; value?: unknown }[] {
  return (e as { errors?: { location?: string; message?: string; value?: unknown }[] | null } | undefined)?.errors ?? [];
}

/**
 * A message as a sentence: capitalised and closed with a full stop, so a
 * terse server detail ("invalid credentials") reads as something said to a
 * person. The words are the server's; only the edges change.
 */
export function asSentence(text: string): string {
  const t = text.trim();
  if (!t) return t;
  const capital = t[0].toUpperCase() + t.slice(1);
  return /[.!?…]$/.test(capital) ? capital : `${capital}.`;
}
