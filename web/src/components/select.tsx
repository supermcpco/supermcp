import { useId, type ReactNode } from "react";
import { Select, Text } from "@cloudflare/kumo";

/*
 * KUMO COPY: written against @cloudflare/kumo 2.14.0 (Base UI 1.8.0).
 *
 * Why it exists: Kumo's Select, given its own `label`, draws a Field
 * layout unlike the label-over-control used across these forms, and it
 * forwards neither `aria-describedby` nor a hint's id to the button it
 * renders. This names the button through `aria-labelledby` (as
 * LabelledInput does for Input) and describes it through the trigger's
 * `render` prop, the one way in that Kumo leaves open.
 *
 * Delete when: Kumo's Select takes a visible label without the Field
 * layout and passes `aria-describedby` to its trigger.
 *
 * src/components/kumo-copies.test.ts fails when the installed Kumo version
 * changes. When it does, re-check this, then update the version above.
 */

/** What "" is called inside Base UI; a NUL cannot be typed or sent as a real value. */
const emptyValue = "\u0000";

/** One choice in a LabelledSelect: the value it sets and the words shown for it. */
export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

/**
 * A Kumo select under its visible label. The button it renders is a
 * combobox named by the label's text, so `getByLabel` and
 * `getByRole("combobox", { name })` find it by the words on screen.
 * Values are strings in and out, as a native select's were; "" is a
 * value like any other, for a choice such as "Everything".
 */
export function LabelledSelect({
  label,
  hideLabel = false,
  value,
  onChange,
  options,
  disabled,
  required,
  size,
  hint,
  describedBy,
  className = "grid gap-1.5",
  triggerClassName,
}: {
  /** What the label says, which is also the select's name. */
  label: ReactNode;
  /** Keeps the label for screen readers only, where the column or row already says what it is. */
  hideLabel?: boolean;
  value: string;
  onChange: (value: string) => void;
  options: readonly SelectOption[];
  disabled?: boolean;
  required?: boolean;
  size?: "xs" | "sm" | "base" | "lg";
  /** A line under the select that describes it. */
  hint?: ReactNode;
  /** The id of something elsewhere on the page that describes it too. */
  describedBy?: string;
  /** The layout around the label and the select. */
  className?: string;
  /** Classes for the select's button, such as a width. */
  triggerClassName?: string;
}) {
  const id = useId();
  const labelId = `${id}-label`;
  const hintId = `${id}-hint`;
  const described = [hint ? hintId : null, describedBy ?? null].filter(Boolean).join(" ") || undefined;
  // Base UI takes "" for "nothing chosen" and greys it as a placeholder,
  // but here "" is a choice like any other ("Everything", "Any time"), so
  // it travels under a stand-in the caller never sees.
  const inner = (v: string) => (v === "" ? emptyValue : v);
  const outer = (v: string) => (v === emptyValue ? "" : v);
  return (
    <div className={className}>
      <label htmlFor={id} id={labelId} className={hideLabel ? "sr-only" : undefined}>
        <Text as="span">{label}</Text>
      </label>
      <Select<string>
        id={id}
        aria-labelledby={labelId}
        value={inner(value)}
        onValueChange={(next) => {
          if (next !== null) onChange(outer(next));
        }}
        items={options.map((o) => ({ value: inner(o.value), label: o.label }))}
        disabled={disabled}
        required={required}
        size={size}
        className={triggerClassName}
        render={described ? (props) => <button {...props} aria-describedby={described} /> : undefined}
      >
        {options.map((o) => (
          <Select.Option key={o.value} value={inner(o.value)} disabled={o.disabled}>
            {o.label}
          </Select.Option>
        ))}
      </Select>
      {hint && (
        <Text as="span" variant="secondary" id={hintId}>
          {hint}
        </Text>
      )}
    </div>
  );
}
