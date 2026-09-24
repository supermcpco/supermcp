import { describe, expect, it } from "vitest";
import { asComparableText, changedLines, diffLines, readsSideBySide } from "./diff";

describe("diffLines", () => {
  it("lines identical text up with no changes", () => {
    const rows = diffLines("one\ntwo", "one\ntwo");
    expect(rows.map((r) => r.change)).toEqual(["same", "same"]);
    expect(changedLines(rows)).toBe(0);
  });

  it("puts a rewritten line beside the one it replaced", () => {
    const rows = diffLines("keep\nold\nkeep too", "keep\nnew\nkeep too");
    expect(rows.map((r) => r.change)).toEqual(["same", "changed", "same"]);
    expect(rows[1].left?.text).toBe("old");
    expect(rows[1].right?.text).toBe("new");
  });

  it("leaves the other side empty for a line only one version has", () => {
    const rows = diffLines("one\ntwo", "one\ntwo\nthree");
    expect(rows.at(-1)).toMatchObject({ change: "added", right: { text: "three" } });
    expect(rows.at(-1)?.left).toBeUndefined();
  });

  it("numbers each side by its own version", () => {
    const rows = diffLines("a\nb\nc", "a\nc");
    const removed = rows.find((r) => r.change === "removed");
    expect(removed?.left).toEqual({ number: 2, text: "b" });
    expect(rows.at(-1)?.right?.number).toBe(2);
  });

  it("treats empty text as no lines rather than one blank one", () => {
    expect(diffLines("", "")).toEqual([]);
    expect(diffLines("", "first line")).toHaveLength(1);
  });
});

describe("asComparableText", () => {
  it("prints an object over several lines so there is something to line up", () => {
    expect(asComparableText({ type: "object" }).split("\n")).toHaveLength(3);
  });

  it("shows nothing for a value that was never set", () => {
    expect(asComparableText(undefined)).toBe("");
    expect(asComparableText(null)).toBe("");
  });
});

describe("readsSideBySide", () => {
  it("leaves a short one-line change on one line", () => {
    expect(readsSideBySide("Accounts", "Accounts and ledgers")).toBe(false);
  });

  it("opens up instructions, schemas and anything else with lines in it", () => {
    expect(readsSideBySide("Ask first.\nThen act.", "Ask first.\nThen wait.")).toBe(true);
    expect(readsSideBySide({ type: "object" }, { type: "string" })).toBe(true);
  });

  it("says nothing changed when nothing did", () => {
    expect(readsSideBySide("same", "same")).toBe(false);
  });
});

describe("JSON held in a string", () => {
  it("is laid out a member per line, keys in the order written, so the change is one line", () => {
    const before = '{"name":"x","input":{"b":1,"200":2},"description":"old"}';
    const after = '{"name":"x","input":{"b":1,"200":2},"description":"new"}';
    expect(asComparableText(before).split("\n")).toContain('    "200": 2');
    expect(asComparableText(before).indexOf('"b"')).toBeLessThan(asComparableText(before).indexOf('"200"'));
    expect(changedLines(diffLines(asComparableText(before), asComparableText(after)))).toBe(1);
  });

  it("leaves text that only looks like JSON, or is already laid out, as it is", () => {
    expect(asComparableText("{not json")).toBe("{not json");
    expect(asComparableText('{\n  "a": 1\n}')).toBe('{\n  "a": 1\n}');
    expect(asComparableText("plain words")).toBe("plain words");
  });
});
