import { details, message, status } from "./errors";

// Helpers for the members screen and the invite page. Kept apart from the
// components so the wording and the arithmetic can be tested without a
// browser.

/**
 * Why the server refused a change to a membership or an invite, in words
 * a person can act on. A 409 carries a stable code in errors[].value; the
 * message is matched on that, never on the server's prose.
 */
const conflicts: Record<string, string> = {
  self: "You cannot change your own membership. Ask another administrator to do it.",
  last_owner: "The workspace must keep at least one active owner. Make someone else an owner first.",
  scim_managed: "This member is managed by your identity provider. Deactivate or remove them there.",
  invite_exists: "An invitation for this email address is already open. Revoke it first to send a new one.",
};

/** The stable code of a refusal, when the server gave one. */
export function conflictCode(e: unknown): string | undefined {
  for (const d of details(e)) {
    if (typeof d.value === "string" && d.value in conflicts) return d.value;
  }
  return undefined;
}

/** What to tell somebody whose change to a member or invite failed. */
export function memberError(e: unknown): string {
  const code = conflictCode(e);
  if (code) return conflicts[code];
  if (status(e) === 501) return notReady;
  return message(e);
}

/** What a screen says while the server has no members API yet. */
export const notReady = "Managing members is not available on this server yet.";

/** The one thing the invite page says about any link that does not work. */
export const inviteInvalid = "This invitation is not valid or has expired.";

/**
 * What the invite page says when accepting fails. Every flavour of "no
 * such invite" reads the same, so a link cannot be used to learn whether
 * an invitation ever existed.
 */
export function acceptError(e: unknown): { text: string; signInFirst: boolean } {
  const s = status(e);
  if (s === 404) return { text: inviteInvalid, signInFirst: false };
  if (s === 403) return { text: "This invitation is for a different email address.", signInFirst: false };
  // The only other refusal is an account that already exists for the
  // email: the server will not attach it to an unauthenticated request.
  if (s === 409)
    return { text: "An account already exists for this email address. Sign in to accept the invitation.", signInFirst: true };
  if (s === 501) return { text: "Accepting invitations is not available on this server yet.", signInFirst: false };
  return { text: message(e), signInFirst: false };
}

const sources: Record<string, string> = { password: "Password", sso: "SSO", scim: "SCIM" };

/** How a member signs in, as the badge shows it. */
export function sourceLabel(source: string): string {
  return sources[source] ?? source;
}

const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 60 * 60],
  ["month", 30 * 24 * 60 * 60],
  ["week", 7 * 24 * 60 * 60],
  ["day", 24 * 60 * 60],
  ["hour", 60 * 60],
  ["minute", 60],
];

/** "3 days ago", "in 2 hours", "just now"; "Never" when there is no time. */
export function relativeTime(iso: string | undefined, now: Date = new Date(), locale = "en"): string {
  if (!iso) return "Never";
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return "Never";
  const seconds = Math.round((at - now.getTime()) / 1000);
  const format = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return format.format(Math.trunc(seconds / size), unit);
  }
  return "just now";
}

/** The server accepts 1 to 30 days; 7 when nothing sensible was given. */
export const defaultExpiryDays = 7;
export const maxExpiryDays = 30;

export function expiryDays(input: string | number): number {
  const n = typeof input === "number" ? input : Number.parseInt(input, 10);
  if (!Number.isFinite(n)) return defaultExpiryDays;
  return Math.min(maxExpiryDays, Math.max(1, Math.trunc(n)));
}

/**
 * Where to go after signing in. Only a path on this site: anything that
 * could leave it (an absolute URL, "//host", "/\\host") goes home instead.
 */
export function safeNext(next: string | undefined): string {
  if (!next || !next.startsWith("/")) return "/";
  if (next.startsWith("//") || next.startsWith("/\\")) return "/";
  return next;
}

/** Whether the signed-in person is the one the invite was sent to. */
export function sameEmail(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}
