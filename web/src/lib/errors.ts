/** Pulls the server's problem detail out of a failed request. */
export function message(e: unknown): string {
  const detail = (e as { detail?: string; message?: string } | undefined)?.detail;
  if (detail) return detail;
  const msg = (e as { message?: string } | undefined)?.message;
  return msg || "Something went wrong.";
}
