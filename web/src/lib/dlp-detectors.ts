/**
 * What the detectors screen needs to reason about without the network:
 * samples typed one per line, what the server's test answered about each
 * one, and the policies a refused delete names.
 */
import { details } from "./errors";

/** Samples as typed, one per line. Blank lines are not samples. */
export function parseSamples(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.replace(/\r$/, ""))
    .filter((line) => line.trim() !== "");
}

/** The inverse of parseSamples, for an editor opened on a stored detector. */
export function formatSamples(samples: readonly string[] | null | undefined): string {
  return (samples ?? []).join("\n");
}

/** What the test route said about one sample. */
export interface TestedSample {
  index: number;
  matched: boolean;
  matches: { start: number; end: number }[];
  more?: boolean;
}

/** One sample's outcome against what its list expects of it. */
export interface Verdict {
  list: "mustMatch" | "mustNotMatch";
  /** Position in its own list, from zero. */
  position: number;
  matched: boolean;
  /** Whether the outcome is the one its list asks for. */
  expected: boolean;
  /** Where it matched, in words: "matches at bytes 3–12", or "no match". */
  where: string;
}

/**
 * Pairs the test route's answers with the two lists they were sent from.
 * The samples go to the server as mustMatch followed by mustNotMatch, so
 * an index below mustMatchCount belongs to the first.
 */
export function verdicts(mustMatchCount: number, tested: readonly TestedSample[]): Verdict[] {
  return tested.map((r) => {
    const inFirst = r.index < mustMatchCount;
    const list = inFirst ? "mustMatch" : "mustNotMatch";
    const position = inFirst ? r.index : r.index - mustMatchCount;
    return { list, position, matched: r.matched, expected: inFirst === r.matched, where: describeMatches(r) };
  });
}

/**
 * Offsets in words: "matches at bytes 3–12", or "no match". They are the
 * server's byte offsets, start inclusive and end exclusive. The server
 * never sends the text, and neither does this.
 */
export function describeMatches(r: Pick<TestedSample, "matched" | "matches" | "more">): string {
  if (!r.matched || r.matches.length === 0) return "no match";
  const spans = r.matches.map((m) => `${m.start}–${m.end}`).join(", ");
  return `matches at bytes ${spans}${r.more ? " and more" : ""}`;
}

/** A policy a refused delete names. */
export interface PolicyReference {
  id: string;
  name: string;
}

/**
 * The policies a delete was refused over: the server lists each as a
 * detail at references.dlpPolicies, message its name and value its id.
 * Empty for any other error.
 */
export function referencingPolicies(e: unknown): PolicyReference[] {
  return details(e)
    .filter((d) => d.location === "references.dlpPolicies" && typeof d.value === "string")
    .map((d) => ({ id: d.value as string, name: d.message ?? (d.value as string) }));
}

/** Whether a failed write lost a race with somebody else's edit. */
export function isStale(e: unknown): boolean {
  return details(e).some((d) => d.value === "version_conflict");
}
