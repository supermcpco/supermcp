import type { ReactNode } from "react";
import { Button, Popover, Text } from "@cloudflare/kumo";
import { Question } from "@phosphor-icons/react";
import { WithTooltip } from "./tooltip";

/**
 * A screen's one-line description, with the longer explanation folded
 * behind a "?" button next to it. The button is named for what it opens
 * ("About the calls"), so a screen reader says more than "question mark";
 * a tooltip shows the same name on hover and on focus.
 */
export function Described({ label, title, children, help }: { label: string; title: string; children: ReactNode; help: ReactNode }) {
  return (
    <div className="flex items-center gap-1">
      <Text>{children}</Text>
      <Popover>
        <WithTooltip tip={label} repeats>
          <Popover.Trigger render={<Button variant="ghost" shape="circle" size="sm" icon={Question} aria-label={label} />} />
        </WithTooltip>
        <Popover.Content side="bottom" align="start" className="grid max-w-sm gap-2 p-4">
          <Popover.Title className="font-semibold">{title}</Popover.Title>
          <Popover.Description render={<div className="grid gap-2" />}>{help}</Popover.Description>
        </Popover.Content>
      </Popover>
    </div>
  );
}
