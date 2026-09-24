/**
 * A line-by-line comparison of two versions of the same text.
 *
 * The history screens used to print "before → after" on one line, which
 * answers the question for a name or a switch and answers nothing at all
 * for a page of instructions or a JSON schema: the two versions are
 * mostly identical, and finding the sentence that moved is the whole job.
 * These rows line the two versions up so the eye can do that in one pass.
 *
 * The comparison is a longest-common-subsequence over whole lines, which
 * is what every diff tool shows and what a reader already knows how to
 * read. It is deliberately small: the alternative was a diff library, and
 * a megabyte of one is a poor trade for a panel most people open twice.
 */

/** One side of a row: a line and the number it has in its own version. */
export interface DiffCell {
  number: number;
  text: string;
}

/**
 * One row of the comparison. A row with both sides holds the same line,
 * or a line that was rewritten; a row with one side holds a line that
 * only one version has.
 */
export interface DiffRow {
  left?: DiffCell;
  right?: DiffCell;
  change: "same" | "changed" | "removed" | "added";
}

/**
 * How much text is worth comparing line by line. The table behind the
 * comparison is one cell per pair of lines, so a pair of very long
 * versions is compared wholesale instead: nobody reads a thousand-line
 * diff on a settings screen, and an unresponsive page helps less than a
 * blunt answer.
 */
const maxCells = 250_000;

interface Op {
  kind: "same" | "removed" | "added";
  text: string;
}

/** Splits into lines without inventing a trailing empty one. */
function toLines(value: string): string[] {
  if (value === "") return [];
  return value.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
}

function longestCommon(a: string[], b: string[]): Op[] {
  const width = b.length + 1;
  const table = new Uint32Array((a.length + 1) * width);
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      table[i * width + j] =
        a[i] === b[j]
          ? table[(i + 1) * width + j + 1] + 1
          : Math.max(table[(i + 1) * width + j], table[i * width + j + 1]);
    }
  }
  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      ops.push({ kind: "same", text: a[i] });
      i++;
      j++;
    } else if (table[(i + 1) * width + j] >= table[i * width + j + 1]) {
      ops.push({ kind: "removed", text: a[i] });
      i++;
    } else {
      ops.push({ kind: "added", text: b[j] });
      j++;
    }
  }
  while (i < a.length) ops.push({ kind: "removed", text: a[i++] });
  while (j < b.length) ops.push({ kind: "added", text: b[j++] });
  return ops;
}

/** Compares two versions of a block of text, line by line. */
export function diffLines(before: string, after: string): DiffRow[] {
  const a = toLines(before);
  const b = toLines(after);
  const ops =
    a.length * b.length > maxCells
      ? [
          ...a.map((text): Op => ({ kind: "removed", text })),
          ...b.map((text): Op => ({ kind: "added", text })),
        ]
      : longestCommon(a, b);

  const rows: DiffRow[] = [];
  let leftNumber = 0;
  let rightNumber = 0;
  let removed: string[] = [];
  let added: string[] = [];

  // A run of removals followed by a run of additions is usually one
  // passage being rewritten, so the two runs are laid alongside each
  // other rather than stacked; what is left over on either side is a
  // line that genuinely only one version has.
  const flush = () => {
    for (let k = 0; k < Math.max(removed.length, added.length); k++) {
      const left = removed[k];
      const right = added[k];
      rows.push({
        left: left === undefined ? undefined : { number: ++leftNumber, text: left },
        right: right === undefined ? undefined : { number: ++rightNumber, text: right },
        change: left !== undefined && right !== undefined ? "changed" : left !== undefined ? "removed" : "added",
      });
    }
    removed = [];
    added = [];
  };

  for (const op of ops) {
    if (op.kind === "removed") {
      removed.push(op.text);
      continue;
    }
    if (op.kind === "added") {
      added.push(op.text);
      continue;
    }
    flush();
    rows.push({
      left: { number: ++leftNumber, text: op.text },
      right: { number: ++rightNumber, text: op.text },
      change: "same",
    });
  }
  flush();
  return rows;
}

/**
 * Renders a recorded value as the text to compare. A string is its own
 * text; anything else is printed as indented JSON, which puts each key on
 * its own line and so gives the comparison something to line up.
 */
export function asComparableText(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  return JSON.stringify(value, null, 2);
}

/**
 * Whether a change is worth the side-by-side view.
 *
 * A name, a switch or a number reads better on one line, and a table for
 * it is noise. Instructions, JSON schemas, SQL statements and templates
 * are the opposite: they are long, they are mostly unchanged, and the one
 * line that moved is the only thing anybody came to see.
 */
export function readsSideBySide(before: unknown, after: unknown): boolean {
  const a = asComparableText(before);
  const b = asComparableText(after);
  if (a === b) return false;
  const longest = Math.max(a.length, b.length);
  const lines = Math.max(toLines(a).length, toLines(b).length);
  return lines > 1 || longest > 120;
}

/** How many lines differ, for a summary somebody reads before opening it. */
export function changedLines(rows: DiffRow[]): number {
  return rows.filter((row) => row.change !== "same").length;
}
