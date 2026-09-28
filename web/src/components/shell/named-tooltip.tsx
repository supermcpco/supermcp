import { useRef, useState, type ComponentProps, type ReactNode } from "react";
import { Tooltip } from "@cloudflare/kumo";

type NamedTooltipProps = Omit<ComponentProps<typeof Tooltip>, "content" | "asChild"> & {
  /** What the tooltip says: the name of what it is attached to. */
  label: string;
};

/**
 * Kumo's Tooltip with its text inside an element whose role is `tooltip`,
 * so a screen reader user learns it is one; Kumo draws the popup with no
 * role. Kumo's Tooltip marks its trigger cursor-default, so a control
 * keeps the pointer unless `className` says otherwise.
 */
export function NamedTooltip({ label, className = "cursor-pointer", ...props }: NamedTooltipProps) {
  return <Tooltip content={<span role="tooltip">{label}</span>} className={className} {...props} />;
}

/**
 * A line of text cut short with an ellipsis where it does not fit, which
 * shows all of it in a tooltip, only when it was in fact cut short.
 */
export function TruncatedText({
  text,
  children,
  disabled,
}: {
  /** The whole text, as the tooltip says it. */
  text: string;
  /** What draws the text inside the truncating line. */
  children: ReactNode;
  /** Off where the text is not on screen, as on the icon rail. */
  disabled?: boolean;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  return (
    <NamedTooltip
      label={text}
      side="right"
      className="block min-w-0 truncate"
      disabled={disabled}
      open={open}
      // Asked to open, it only does when the text overflows its line.
      onOpenChange={(next) => {
        const el = ref.current;
        setOpen(next && el !== null && el.scrollWidth > el.clientWidth);
      }}
      render={<span ref={ref} />}
    >
      {children}
    </NamedTooltip>
  );
}
