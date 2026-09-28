import type { ReactNode } from "react";
import { Button, Popover } from "@cloudflare/kumo";
import { Question } from "@phosphor-icons/react";

/**
 * The longer explanation behind a heading, opened from a "?" beside it.
 * The heading keeps its one sentence; whoever wants the detail asks for
 * it. The button is named for what it explains ("About data-loss rules"),
 * so a screen reader user hears which question it answers.
 */
export function Help({ about, children }: { about: string; children: ReactNode }) {
  return (
    <Popover>
      <Popover.Trigger render={<Button variant="ghost" size="sm" shape="square" icon={Question} aria-label={`About ${about}`} />} />
      <Popover.Content className="grid max-w-md gap-2">
        <Popover.Title>{`About ${about}`}</Popover.Title>
        <div className="grid gap-2 text-kumo-default">{children}</div>
      </Popover.Content>
    </Popover>
  );
}

/** A heading with its "?" beside it. */
export function HeadingWithHelp({ heading, help }: { heading: ReactNode; help?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      {heading}
      {help}
    </div>
  );
}
