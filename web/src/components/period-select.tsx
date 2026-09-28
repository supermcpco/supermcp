import { Text } from "@cloudflare/kumo";
import { rangeLabels, ranges, type Range } from "../lib/analytics";

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

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
    <label className="grid w-fit gap-1.5">
      <Text as="span">Period</Text>
      <select
        className={selectClass}
        value={value ?? ""}
        onChange={(e) => {
          const v = e.target.value;
          onChange((ranges as readonly string[]).includes(v) ? (v as Range) : undefined);
        }}
      >
        {anyLabel !== undefined && <option value="">{anyLabel}</option>}
        {ranges.map((r) => (
          <option key={r} value={r}>
            {rangeLabels[r]}
          </option>
        ))}
      </select>
    </label>
  );
}
