import { useId, type ComponentProps, type ReactNode } from "react";
import { Input, Text } from "@cloudflare/kumo";

/**
 * A Kumo input under its visible label. The label wraps the input, as a
 * plain `<label>` would, and also names it through `aria-labelledby`:
 * Kumo checks for that prop (or `aria-label`, or its own `label`) on every
 * render and warns in the console when none is there, since it cannot see
 * the label around it. The accessible name is the label's text, as before.
 */
export function LabelledInput({
  label,
  labelClassName = "grid gap-1.5",
  children,
  ...input
}: Omit<ComponentProps<typeof Input>, "label"> & {
  /** What the label says, which is also the input's name. */
  label: ReactNode;
  /** The label's layout; the input's own `className` styles the input. */
  labelClassName?: string;
  /** What sits under the input inside the label, such as a hint it is described by; not part of its name. */
  children?: ReactNode;
}) {
  const id = useId();
  return (
    <label className={labelClassName}>
      <Text as="span" id={id}>
        {label}
      </Text>
      <Input aria-labelledby={id} {...input} />
      {children}
    </label>
  );
}
