import { cloneElement, useId, useState, type ComponentProps, type ReactElement } from "react";
import { Tooltip } from "@cloudflare/kumo";

/*
 * KUMO COPY: written against @cloudflare/kumo 2.14.0 (Base UI 1.8.0).
 *
 * Why it exists: Kumo's Tooltip draws its popup (Base UI's Tooltip.Popup)
 * with no role and takes no prop for one, so TooltipText puts the words in
 * a `role="tooltip"` span with an id that the trigger's `aria-describedby`
 * points at.
 *
 * Delete when: Kumo's Tooltip gives its popup the role `tooltip` and
 * describes its trigger. Then WithTooltip can be dropped in favour of Kumo's
 * Tooltip, as long as the tooltip browser tests and tooltip.test.tsx still
 * hold.
 *
 * src/components/kumo-copies.test.ts fails when the installed Kumo version
 * changes. When it does, re-check this, then update the version above.
 */

/** What the wrapper reads from, and adds to, the element it wraps. */
interface TriggerProps {
  "aria-label"?: string;
  "aria-describedby"?: string;
  "data-tooltip-trigger"?: string;
}

/**
 * The words of a tooltip, inside an element whose role is `tooltip`.
 * Kumo draws its popup with no role, so a screen reader would not know
 * the text is one; the text is also the element's accessible name.
 */
export function TooltipText({ id, children }: { id?: string; children: string }) {
  return (
    <span role="tooltip" id={id}>
      {children}
    </span>
  );
}

/**
 * Shows `tip` beside `children` on hover and on keyboard focus. The same
 * pattern the sidebar's rail uses, for the rest of the console: Kumo's
 * Tooltip around the control as it is, with the text in a `tooltip`.
 *
 * While the tip shows, the control is described by it, unless the tip
 * only repeats what a screen reader already hears: the control's
 * `aria-label` is those words, or `repeats` says so (a popover trigger
 * whose icon button carries the name, a badge whose sentence is in its
 * text for screen readers). `onlyWhenTruncated` shows it only when the
 * control's text is cut off, for a name or a URL too long for its place;
 * the full text is already the control's name, so it describes nothing.
 *
 * The control keeps every prop it was given, its ref included.
 */
export function WithTooltip({
  tip,
  children,
  side,
  repeats = false,
  onlyWhenTruncated = false,
  defaultOpen = false,
  className = "cursor-pointer",
}: {
  tip: string;
  children: ReactElement<TriggerProps>;
  side?: ComponentProps<typeof Tooltip>["side"];
  /** A screen reader already hears the tip's words from the control. */
  repeats?: boolean;
  onlyWhenTruncated?: boolean;
  defaultOpen?: boolean;
  /** Kumo marks its trigger cursor-default; a control that does something keeps the pointer. */
  className?: string;
}) {
  const id = useId();
  const [open, setOpen] = useState(defaultOpen);
  const describes = !repeats && !onlyWhenTruncated && tip !== children.props["aria-label"];
  const trigger = cloneElement(children, {
    // Found again by this when the tip is about to show, to measure it.
    "data-tooltip-trigger": id,
    "aria-describedby": open && describes ? id : children.props["aria-describedby"],
  });
  return (
    <Tooltip
      content={<TooltipText id={id}>{tip}</TooltipText>}
      side={side}
      open={open}
      onOpenChange={(next) => {
        if (next && onlyWhenTruncated) {
          const el = document.querySelector(`[data-tooltip-trigger="${CSS.escape(id)}"]`);
          if (el && el.scrollWidth <= el.clientWidth) return;
        }
        setOpen(next);
      }}
      className={className}
      render={trigger}
    />
  );
}
