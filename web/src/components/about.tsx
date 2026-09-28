import type { ReactNode } from "react";
import { Button, Popover } from "@cloudflare/kumo";
import { Question } from "@phosphor-icons/react";
import { WithTooltip } from "./tooltip";

/**
 * The longer explanation behind a heading's one sentence, kept one click
 * away so the screen reads at a glance. The "?" button is named by what
 * it explains ("About approvals"), and the popover carries the same name
 * as its title, so a screen reader hears where it has landed. A tooltip
 * shows the same name to whoever sees only the "?".
 *
 * Modal, like the dialogs: a non-modal popover leaves Base UI's focus
 * guards tabbable inside aria-hidden spans, which is a fault in itself.
 * Escape or a click outside closes it and focus returns to the "?".
 */
export function About({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Popover modal>
      <WithTooltip tip={label} repeats>
        <Popover.Trigger render={<Button variant="ghost" shape="square" size="sm" icon={Question} aria-label={label} />} />
      </WithTooltip>
      <Popover.Content side="bottom" align="start" className="max-w-sm gap-2">
        <Popover.Title>{label}</Popover.Title>
        <div className="grid gap-2 text-base leading-6 text-kumo-subtle">{children}</div>
      </Popover.Content>
    </Popover>
  );
}

/** A heading with its "?" beside it. */
export function HeadingWithAbout({ heading, about }: { heading: ReactNode; about: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-1">
      {heading}
      {about}
    </div>
  );
}
