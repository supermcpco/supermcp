// How long a rotated API key keeps working. The server refuses anything
// over seven days, so the longest choice is exactly that.
export const maxGraceSeconds = 7 * 24 * 60 * 60;

export const graceChoices = [
  { seconds: 0, label: "No time: stop it now" },
  { seconds: 60 * 60, label: "1 hour" },
  { seconds: 24 * 60 * 60, label: "24 hours" },
  { seconds: maxGraceSeconds, label: "7 days" },
] as const;

// The choice offered first: long enough to redeploy a client, short enough
// that the old key does not linger.
export const defaultGraceSeconds = 24 * 60 * 60;

// canRotate is false for a key that is revoked or already expired; the
// server refuses those, so the screen does not offer it.
export function canRotate(key: { revokedAt?: string; expiresAt?: string }, now: Date = new Date()): boolean {
  if (key.revokedAt) return false;
  return !key.expiresAt || new Date(key.expiresAt).getTime() > now.getTime();
}

// stopsWorking says when the old key stops, in words a person can act on.
export function stopsWorking(expiresAt: string, now: Date = new Date()): string {
  const at = new Date(expiresAt);
  if (at.getTime() <= now.getTime()) return "It has stopped working.";
  return `It stops working at ${at.toLocaleString()}.`;
}
