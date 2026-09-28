import { Link, type RegisteredRouter, type ValidateLinkOptions } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";
import { WithTooltip } from "../components/tooltip";

const badgeClass = "rounded-full bg-kumo-tint px-2 py-0.5 text-[12px] text-kumo-subtle ring ring-kumo-line";

/**
 * A small state marker: revoked, disabled, off. `why` is the sentence a
 * word or two cannot say. A pointer finds it in a tooltip; a screen
 * reader hears it with the badge. A badge is no control, so it takes no
 * focus; the page the badge leads to says the same in its own words.
 * Positioned, so it sits above a card whose link is stretched over it.
 */
export function Badge({ children, why }: { children: React.ReactNode; why?: string }) {
  if (!why) return <span className={badgeClass}>{children}</span>;
  return (
    <>
      <WithTooltip tip={why} repeats className="cursor-help">
        <span className={`relative ${badgeClass}`}>{children}</span>
      </WithTooltip>
      {/* Beside the badge, not in it, so the badge's own text stays its word. */}
      <span className="sr-only">{why}</span>
    </>
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

interface NotFoundProps<TRouter extends RegisteredRouter = RegisteredRouter, TOptions = unknown> {
  /** What was looked for, as a heading: "Adapter not found". */
  heading: string;
  /** One sentence on what that means. */
  children: React.ReactNode;
  /** Where the list it should have been in lives. */
  back: ValidateLinkOptions<TRouter, TOptions>;
  /** The words on that link: "Back to the catalog". */
  backLabel: string;
}

/**
 * What a screen shows when the thing in its address does not exist, or
 * no longer does. A spinner would wait for ever; this says so and offers
 * the way back to the list it came from.
 */
export function NotFound<TRouter extends RegisteredRouter, TOptions>(props: NotFoundProps<TRouter, TOptions>): React.ReactNode;
export function NotFound({ heading, children, back, backLabel }: NotFoundProps) {
  return (
    <div className="grid gap-1.5">
      <Text as="h1" variant="heading" size="lg">
        {heading}
      </Text>
      <Text>{children}</Text>
      <Text>
        <Link {...back} className="underline">
          {backLabel}
        </Link>
      </Text>
    </div>
  );
}
