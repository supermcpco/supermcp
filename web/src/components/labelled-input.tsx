import { useId, type ComponentProps, type ReactNode } from "react";
import { Input, Text } from "@cloudflare/kumo";

/*
 * KUMO COPY: written against @cloudflare/kumo 2.14.0 (Base UI 1.8.0).
 *
 * Why it exists: in development, Kumo's Input warns "Input must have an
 * accessible name" unless it gets `label`, `aria-label` or
 * `aria-labelledby`. It cannot see a <label> wrapped around it. Kumo's own
 * `label` prop draws a Field layout, not the wrapping label used across
 * these forms, so this names the input through `aria-labelledby`.
 *
 * Delete when: Kumo's Input stops warning for an input inside a wrapping
 * <label>. Then a plain `<label>` around `<Input>` does the job.
 *
 * src/components/kumo-copies.test.ts fails when the installed Kumo version
 * changes. When it does, re-check this, then update the version above.
 */

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
