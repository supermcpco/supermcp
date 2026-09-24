import { Link } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";

/** A small state marker: revoked, disabled, off. */
export function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-full bg-kumo-tint px-2 py-0.5 text-[12px] text-kumo-subtle ring ring-kumo-line">
      {children}
    </span>
  );
}

/** What a screen shows instead of its content when nobody is signed in. */
export function SignInFirst() {
  return (
    <div className="grid gap-1.5">
      <Text as="h1" variant="heading2">
        Sign in
      </Text>
      <Text>
        <Link to="/login" search={{}} className="underline">
          Sign in
        </Link>{" "}
        to manage this workspace.
      </Text>
    </div>
  );
}

/**
 * What a screen shows while it is still finding out who the viewer is.
 * Anything more definite would be a guess, and the wrong guess tells a
 * signed-in person to sign in again.
 */
export function Loading() {
  return (
    <Text variant="secondary" aria-busy="true">
      Loading…
    </Text>
  );
}
