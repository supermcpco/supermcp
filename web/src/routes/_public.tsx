import { createFileRoute, Outlet } from "@tanstack/react-router";
import { Text } from "@cloudflare/kumo";
import { ClockCounterClockwise, Hexagon, Plugs, ShieldCheck, type Icon } from "@phosphor-icons/react";

/**
 * The frame for pages somebody reaches without a session, or on the way to
 * one: signing in, creating a workspace, accepting an invitation. The
 * console's navigation would only lead to pages that send them straight
 * back here, so what surrounds the card is the product saying what it is.
 *
 * From 1024px wide that is a panel of its own beside the card; narrower,
 * only the mark and the name, above the card.
 */
export const Route = createFileRoute("/_public")({
  component: PublicLayout,
});

const points: { icon: Icon; text: string }[] = [
  { icon: Plugs, text: "Connect an API from the catalog, or from its OpenAPI description." },
  { icon: ShieldCheck, text: "Choose which tools each server offers, and who may call them." },
  { icon: ClockCounterClockwise, text: "Every call is recorded, with approvals where you want a person to decide." },
];

function PublicLayout() {
  return (
    <div className="grid min-h-full bg-kumo-base text-kumo-default lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
      {/* A labelled region, not a complementary landmark, which would
          read as the console's sidebar (src/routes.test.ts). */}
      <section
        aria-label="About supermcp"
        className="hidden flex-col gap-12 border-r border-kumo-line bg-kumo-recessed px-12 py-12 lg:flex xl:px-16"
      >
        <Brand />
        <div className="grid max-w-md gap-10 lg:my-auto">
          <p className="text-3xl leading-tight font-semibold tracking-tight text-kumo-default">
            Turn the systems you already run into tools for Claude, ChatGPT and Copilot.
          </p>
          <ul className="grid gap-5">
            {points.map(({ icon: PointIcon, text }) => (
              <li key={text} className="flex items-start gap-3">
                <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-kumo-base ring ring-kumo-line">
                  <PointIcon size={18} weight="duotone" className="text-kumo-link" aria-hidden />
                </span>
                <Text as="span" variant="secondary">
                  {text}
                </Text>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <div className="flex flex-col items-center gap-8 px-5 py-10 sm:justify-center sm:px-8 sm:py-16">
        <div className="lg:hidden">
          <Brand />
        </div>
        <main className="w-full max-w-md">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

/** The mark and the name, as the console's sidebar shows them. */
function Brand() {
  return (
    <div className="flex items-center gap-2.5">
      <span className="grid size-9 place-items-center rounded-lg bg-kumo-base ring ring-kumo-line">
        <Hexagon size={22} weight="duotone" className="text-kumo-link" aria-hidden />
      </span>
      <span className="text-lg font-semibold tracking-tight text-kumo-default">supermcp</span>
    </div>
  );
}
