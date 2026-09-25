/**
 * Why a re-authentication through a provider was not accepted, as the
 * server names it on the way back to /reauth. The server decides; this
 * only says it in words a person can act on.
 */
const reasons: Record<string, string> = {
  reauth_mismatch:
    "That sign-in was for a different account, workspace or provider than the one you are using, so it was not accepted.",
  reauth_unconfirmed:
    "Your sign-in provider did not say when you signed in, so it cannot confirm it is you. Sign in with your password, or ask an administrator to make this change.",
  reauth_not_recent:
    "Your sign-in provider answered from an earlier sign-in instead of asking you again. Sign out of the provider, then try again.",
};

export function reauthError(code: string | undefined): string | undefined {
  if (!code) return undefined;
  return reasons[code] ?? "Signing in again did not complete. Try again.";
}
