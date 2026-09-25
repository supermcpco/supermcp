import type { ResyncDto, ResyncSkipDto } from "../api";

// Words for what a catalog re-sync does. The server decides what is
// skipped and why; these only say it.

/** Why a tool is left alone, as a sentence fragment after its name. */
export function skipReason(s: ResyncSkipDto): string {
  if (s.reason === "custom") return "a tool made here has this name, so the catalog's tool is not added";
  const would = s.change === "remove" ? "removed" : "updated";
  return `edited by hand, so it is kept as it is; the catalog would have ${would} it`;
}

/** What the connector's settings are called on the screen. */
export const fieldLabel: Record<ResyncDto["fields"][number]["field"], string> = {
  instructions: "Instructions",
  transport: "Transport",
  auth: "Authentication",
};

function count(n: number, one: string, many: string): string {
  return n === 1 ? `1 ${one}` : `${n} ${many}`;
}

/** One line saying what a re-sync changed, or will change. */
export function resyncSummary(r: ResyncDto): string {
  const parts: string[] = [];
  if (r.add.length) parts.push(`${count(r.add.length, "tool", "tools")} added`);
  if (r.update.length) parts.push(`${count(r.update.length, "tool", "tools")} updated`);
  if (r.remove.length) parts.push(`${count(r.remove.length, "tool", "tools")} removed`);
  if (r.fields.length) parts.push(`${count(r.fields.length, "setting", "settings")} replaced`);
  if (r.relabel.length) parts.push(`${count(r.relabel.length, "tool", "tools")} marked as the catalog's`);
  if (r.skipped.length) parts.push(`${count(r.skipped.length, "tool", "tools")} left alone`);
  return parts.length ? parts.join(", ") : "no tool or setting changed";
}

/** What a setting re-sync leaves alone would need, said to the operator. */
export function notAppliedNote(fields: string[]): string {
  const names = fields.map((f) => fieldLabel[f as keyof typeof fieldLabel]?.toLowerCase() ?? f).join(" and ");
  return (
    `The catalog's ${names} differ from this connector's. Re-sync never changes these, because the connector may ` +
    `point at your own host and its credentials would follow. Change them by hand if the catalog's are what you want.`
  );
}
