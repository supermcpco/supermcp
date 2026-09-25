import { describe, expect, it } from "vitest";
import { describeMatches, formatSamples, isStale, parseSamples, referencingPolicies, verdicts } from "./dlp-detectors";

describe("parseSamples", () => {
  it("takes one sample per line and drops blank ones", () => {
    expect(parseSamples("CN-123456\r\n\n  \nsee CN-000001\n")).toEqual(["CN-123456", "see CN-000001"]);
  });
  it("round-trips through formatSamples", () => {
    expect(parseSamples(formatSamples(["a", "b c"]))).toEqual(["a", "b c"]);
    expect(formatSamples(undefined)).toBe("");
  });
});

describe("verdicts", () => {
  it("splits the answers back into the two lists and says which surprised", () => {
    const got = verdicts(2, [
        { index: 0, matched: true, matches: [{ start: 0, end: 9 }] },
        { index: 1, matched: false, matches: [] },
      { index: 2, matched: true, matches: [{ start: 0, end: 9 }], more: true },
    ]);
    expect(got.map((v) => [v.list, v.position, v.expected])).toEqual([
      ["mustMatch", 0, true],
      ["mustMatch", 1, false],
      ["mustNotMatch", 0, false],
    ]);
    expect(got[2].where).toBe("matches at bytes 0–9 and more");
  });
  it("says no match in words", () => {
    expect(describeMatches({ matched: false, matches: [] })).toBe("no match");
    expect(describeMatches({ matched: true, matches: [{ start: 3, end: 12 }, { start: 20, end: 29 }] })).toBe(
      "matches at bytes 3–12, 20–29",
    );
  });
});

describe("referencingPolicies", () => {
  it("reads the policies a refused delete names", () => {
    const e = {
      detail: "data-loss policies use this detector",
      errors: [
        { location: "query.force", message: "in use", value: "in_use" },
        { location: "references.dlpPolicies", message: "Contracts", value: "p1" },
      ],
    };
    expect(referencingPolicies(e)).toEqual([{ id: "p1", name: "Contracts" }]);
    expect(referencingPolicies(new Error("x"))).toEqual([]);
  });
  it("tells a lost race from other refusals", () => {
    expect(isStale({ errors: [{ location: "body.expectedVersion", value: "version_conflict" }] })).toBe(true);
    expect(isStale({ errors: [{ location: "body.name", value: "name_taken" }] })).toBe(false);
  });
});
