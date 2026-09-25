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
  already_member: "This person is already a member of the workspace. Change their role or reactivate them instead.",
  invite_limit: "Too many invitations are open. Revoke some, or wait for them to be accepted, before sending more.",
};

/** What any screen says when the server has locked the caller out for a while. */
export const tooManyAttempts = "Too many attempts. Wait a few minutes, then try again.";

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
  if (status(e) === 429) return tooManyAttempts;
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
 * an invitation ever existed. A 409 is matched on its stable code, never
 * on the server's prose.
 */
export function acceptError(e: unknown): { text: string; signInFirst: boolean } {
  const s = status(e);
  if (s === 404) return { text: inviteInvalid, signInFirst: false };
  if (s === 403) return { text: "This invitation is for a different email address.", signInFirst: false };
  if (s === 429) return { text: tooManyAttempts, signInFirst: false };
  if (s === 409) {
    if (hasCode(e, "account_exists"))
      return {
        text: "An account already exists for this email address. Sign in first, then accept the invitation.",
        signInFirst: true,
      };
    if (hasCode(e, "already_member"))
      return { text: "You are already a member of this workspace.", signInFirst: false };
  }
  if (s === 501) return { text: "Accepting invitations is not available on this server yet.", signInFirst: false };
  return { text: message(e), signInFirst: false };
}

/** What the invite page says when looking the link up fails. */
export function lookupError(e: unknown): string {
  const s = status(e);
  if (s === 429) return tooManyAttempts;
  if (s === 501) return "Invitations are not available on this server yet.";
  return inviteInvalid;
}

function hasCode(e: unknown, code: string): boolean {
  return details(e).some((d) => d.value === code);
}

/** The shape of a workspace's password policy, as the server sends it. */
export type PasswordRules = { minLength: number; requireClasses: number };

/**
 * The workspace's password rules in one sentence, for the hint under a new
 * password. Zero or missing values fall back to the server's defaults
 * (12 characters, 2 classes), as the server's own check does.
 */
export function passwordHint(policy: Partial<PasswordRules> | undefined): string {
  const length = policy?.minLength && policy.minLength > 0 ? policy.minLength : 12;
  const classes = policy?.requireClasses && policy.requireClasses > 0 ? Math.min(4, policy.requireClasses) : 2;
  const head = `At least ${length} characters`;
  if (classes <= 1) return `${head}.`;
  if (classes >= 4) return `${head}, using lower case, upper case, digits and symbols.`;
  return `${head}, using at least ${classes} of lower case, upper case, digits and symbols.`;
}

/** The minimum length the password field enforces before submitting. */
export function passwordMinLength(policy: Partial<PasswordRules> | undefined): number {
  return policy?.minLength && policy.minLength > 0 ? policy.minLength : 12;
}

/** "Sent by Ada Lovelace"; nothing when the sender is unknown or has left. */
export function invitedBy(name: string | undefined): string | undefined {
  const n = name?.trim();
  return n ? `sent by ${n}` : undefined;
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
