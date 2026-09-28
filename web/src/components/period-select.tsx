import { rangeLabels, ranges, type Range } from "../lib/analytics";
import { LabelledSelect } from "./select";

/**
 * The period picker the activity screen's two tabs share. The analytics
 * always have a period; the list of calls may have none, which `anyLabel`
 * names as the first choice.
 */
export function PeriodSelect({
  value,
  onChange,
  anyLabel,
}: {
  value: Range | undefined;
  onChange: (range: Range | undefined) => void;
  anyLabel?: string;
}) {
  return (
    <LabelledSelect
      label="Period"
      className="grid w-fit gap-1.5"
      value={value ?? ""}
      onChange={(v) => onChange((ranges as readonly string[]).includes(v) ? (v as Range) : undefined)}
      options={[
        ...(anyLabel !== undefined ? [{ value: "", label: anyLabel }] : []),
        ...ranges.map((r) => ({ value: r, label: rangeLabels[r] })),
      ]}
    />
  );
}
