import type { ReactNode } from "react";
import { Text } from "@cloudflare/kumo";

/**
 * The card on a page outside the console (signing in, creating a
 * workspace, accepting an invitation), with what belongs under it rather
 * than in it, such as the way over to the other form.
 *
 * On a phone the card's edge is dropped: the page is the card, and its
 * padding would only narrow the fields.
 */
export function PublicCard({ children, after }: { children: ReactNode; after?: ReactNode }) {
  return (
    <div className="grid gap-6">
      <div className="grid gap-6 sm:rounded-xl sm:bg-kumo-base sm:p-10 sm:shadow-xs sm:ring sm:ring-kumo-line">
        {children}
      </div>
      {after && <div className="flex flex-wrap items-center justify-center gap-x-1.5 text-center">{after}</div>}
    </div>
  );
}

/** A line with "or" in the middle, between two ways of doing one thing. */
export function OrDivider() {
  return (
    <div className="flex items-center gap-3" aria-hidden>
      <span className="h-px flex-1 bg-kumo-line" />
      <Text as="span" variant="secondary">
        or
      </Text>
      <span className="h-px flex-1 bg-kumo-line" />
    </div>
  );
}

/** Classes for a button that reads as a link: the way between two forms. */
export const textButton =
  "cursor-pointer rounded-sm text-base font-medium text-kumo-link underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-kumo-focus focus-visible:outline-none";

/**
 * The card's heading, a step above the console's page headings (Kumo's
 * largest is 20px): it is the one thing on the page.
 */
export const headingClass = "text-2xl font-semibold tracking-tight text-kumo-default";
