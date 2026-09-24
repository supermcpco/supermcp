/**
 * A tool definition as the editor holds it.
 *
 * The server sends the definition as a JSON document in the order its keys
 * were stored, and the order is part of what a person wrote: the schema's
 * properties are shown to a model in that order, and a history that
 * reorders them on every save shows changes nobody made. A plain object
 * keeps insertion order for most keys, but not for keys that look like
 * array indices ("200", "01"), which JavaScript moves to the front. So an
 * object here is a Map, which keeps every key where it was.
 */
export type Json = null | boolean | number | string | Json[] | JsonObject;
export type JsonObject = Map<string, Json>;

/** A JSON document that did not parse, and where it went wrong. */
export class JsonSyntaxError extends Error {
  constructor(
    message: string,
    readonly position: number,
  ) {
    super(message);
    this.name = "JsonSyntaxError";
  }
}

/** Parses JSON text, keeping every object's keys in the order they appear. */
export function parseJson(text: string): Json {
  let i = 0;

  const fail = (what: string): never => {
    const before = text.slice(0, i);
    const line = before.split("\n").length;
    const column = i - before.lastIndexOf("\n");
    throw new JsonSyntaxError(`${what} at line ${line}, column ${column}`, i);
  };
  const space = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  };
  const expect = (ch: string) => {
    if (text[i] !== ch) fail(i >= text.length ? `Expected "${ch}" but the text ended` : `Expected "${ch}"`);
    i++;
  };

  const string = (): string => {
    const start = i;
    expect('"');
    while (i < text.length && text[i] !== '"') {
      if (text[i] === "\\") i++;
      else if (text.charCodeAt(i) < 0x20) fail("A line break or control character inside a string");
      i++;
    }
    if (i >= text.length) fail("A string that is never closed");
    i++;
    try {
      return JSON.parse(text.slice(start, i)) as string;
    } catch {
      i = start;
      return fail("A string with a broken escape");
    }
  };

  const number = (): number => {
    const match = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i));
    if (!match) return fail("Unexpected character");
    i += match[0].length;
    return Number(match[0]);
  };

  const literal = (word: string, value: Json): Json => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    return fail("Unexpected character");
  };

  const value = (): Json => {
    space();
    const ch = text[i];
    if (ch === undefined) return fail("The text ended where a value was expected");
    if (ch === "{") {
      i++;
      const out: JsonObject = new Map();
      space();
      if (text[i] === "}") {
        i++;
        return out;
      }
      for (;;) {
        space();
        const key = string();
        space();
        expect(":");
        out.set(key, value());
        space();
        if (text[i] === ",") {
          i++;
          continue;
        }
        expect("}");
        return out;
      }
    }
    if (ch === "[") {
      i++;
      const out: Json[] = [];
      space();
      if (text[i] === "]") {
        i++;
        return out;
      }
      for (;;) {
        out.push(value());
        space();
        if (text[i] === ",") {
          i++;
          continue;
        }
        expect("]");
        return out;
      }
    }
    if (ch === '"') return string();
    if (ch === "t") return literal("true", true);
    if (ch === "f") return literal("false", false);
    if (ch === "n") return literal("null", null);
    return number();
  };

  const result = value();
  space();
  if (i < text.length) fail("Unexpected text after the end of the document");
  return result;
}

/** Writes JSON back out with every object's keys in the order they are held. */
export function stringifyJson(v: Json, indent = 2): string {
  const pad = (depth: number) => " ".repeat(indent * depth);
  const write = (value: Json, depth: number): string => {
    if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      if (value.length === 0) return "[]";
      const items = value.map((item) => pad(depth + 1) + write(item, depth + 1));
      return `[\n${items.join(",\n")}\n${pad(depth)}]`;
    }
    if (value.size === 0) return "{}";
    const entries = [...value].map(([k, item]) => `${pad(depth + 1)}${JSON.stringify(k)}: ${write(item, depth + 1)}`);
    return `{\n${entries.join(",\n")}\n${pad(depth)}}`;
  };
  return write(v, 0);
}

export function isObject(v: Json | undefined): v is JsonObject {
  return v instanceof Map;
}

/** A tool definition: always an object at the top. */
export type ToolDraft = JsonObject;

export type ParseResult = { ok: true; draft: ToolDraft } | { ok: false; error: string };

/** Reads the definition the server sent, or the text somebody typed. */
export function parseDefinition(text: string): ParseResult {
  try {
    const v = parseJson(text);
    if (!isObject(v)) return { ok: false, error: "A tool definition is a JSON object, between { and }." };
    return { ok: true, draft: v };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** The definition as the server expects it: JSON, keys in the order held. */
export function serializeDefinition(draft: ToolDraft): string {
  return stringifyJson(draft);
}

/** A path into the definition, e.g. ["operation", "body", "encoding"]. */
export type FieldPath = readonly string[];

/** The value at a path, or undefined when any step is missing. */
export function getAt(draft: ToolDraft, path: FieldPath): Json | undefined {
  let current: Json | undefined = draft;
  for (const key of path) {
    if (!isObject(current)) return undefined;
    current = current.get(key);
  }
  return current;
}

/**
 * A copy of the draft with one value changed. Every object along the path
 * is copied so the old draft stays as it was. A key that already exists
 * keeps its place; a new one goes at the end. Setting undefined removes
 * the key, and an object emptied by that is removed too, so clearing a
 * field leaves the definition as though it had never been set.
 */
export function setAt(draft: ToolDraft, path: FieldPath, value: Json | undefined): ToolDraft {
  if (path.length === 0) return draft;
  const [head, ...rest] = path;
  const next: JsonObject = new Map(draft);
  if (rest.length === 0) {
    if (value === undefined) next.delete(head);
    else next.set(head, value);
    return next;
  }
  const child = draft.get(head);
  const base: JsonObject = isObject(child) ? child : new Map();
  if (value === undefined && !isObject(child)) return draft;
  const updated = setAt(base, rest, value);
  if (updated.size === 0 && value === undefined) next.delete(head);
  else next.set(head, updated);
  return next;
}

/** A text field's value: strings as they are, anything else as empty. */
export function getText(draft: ToolDraft, path: FieldPath): string {
  const v = getAt(draft, path);
  if (typeof v === "string") return v;
  if (typeof v === "number") return String(v);
  return "";
}

/**
 * Sets a text field. An optional field left empty is removed rather than
 * stored as "". A required one keeps "" so it holds its place: removing
 * it and typing it again would move it to the end of the object.
 */
export function setText(draft: ToolDraft, path: FieldPath, text: string, optional = true): ToolDraft {
  return setAt(draft, path, text === "" && optional ? undefined : text);
}

/** Sets a whole-number field; empty removes it, anything unreadable is kept as typed for the server to refuse. */
export function setNumber(draft: ToolDraft, path: FieldPath, text: string): ToolDraft {
  const trimmed = text.trim();
  if (trimmed === "") return setAt(draft, path, undefined);
  const n = Number(trimmed);
  return setAt(draft, path, Number.isFinite(n) ? n : trimmed);
}

/** A nested JSON value (a schema, headers, a body) as text to edit. */
export function getJsonText(draft: ToolDraft, path: FieldPath): string {
  const v = getAt(draft, path);
  return v === undefined ? "" : stringifyJson(v);
}

/**
 * Puts edited JSON text back. Returns the error instead when the text does
 * not parse, so the field can say so and the draft is left alone.
 */
export function setJsonText(
  draft: ToolDraft,
  path: FieldPath,
  text: string,
): { ok: true; draft: ToolDraft } | { ok: false; error: string } {
  if (text.trim() === "") return { ok: true, draft: setAt(draft, path, undefined) };
  try {
    return { ok: true, draft: setAt(draft, path, parseJson(text)) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export type Transport = "http" | "graphql" | "database" | "soap" | "mcp";

/** How one form field reads and writes the definition. */
export interface FormField {
  /** Dotted path, the same form the server uses for issue locations. */
  key: string;
  path: FieldPath;
  label: string;
  kind: "text" | "textarea" | "code" | "json" | "select" | "number";
  options?: readonly string[];
  hint?: string;
  rows?: number;
  /** Left empty, the key is removed. Required fields keep "" and their place. */
  optional?: boolean;
}

const field = (key: string, rest: Omit<FormField, "key" | "path">): FormField => ({
  key,
  path: key.split("."),
  ...rest,
});

/** The fields every tool has, whatever it calls. */
export const commonFields: readonly FormField[] = [
  field("name", { label: "Name", kind: "text", hint: "What a model calls it: lower case, words joined by underscores." }),
  field("description", {
    label: "Description",
    kind: "textarea",
    rows: 3,
    hint: "What the tool does, written for the model that decides whether to call it.",
  }),
  field("input", {
    label: "Input schema",
    kind: "json",
    rows: 10,
    hint: "The JSON Schema of the arguments a model sends. Refer to them in the operation as {{params.name}}.",
  }),
];

/**
 * The operation fields each transport understands. SOAP and MCP tools are
 * edited as JSON only: their operations are envelopes and argument maps
 * that a form would only get in the way of.
 */
export const operationFields: Record<Transport, readonly FormField[]> = {
  http: [
    field("operation.method", {
      label: "Method",
      kind: "select",
      options: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
    }),
    field("operation.path", {
      label: "Path",
      kind: "text",
      hint: "Added to the connector's base URL, e.g. /items/{{params.id}}.",
    }),
    field("operation.query", { label: "Query parameters", kind: "json", rows: 4, optional: true }),
    field("operation.headers", { label: "Headers", kind: "json", rows: 3, optional: true }),
    field("operation.body.encoding", {
      label: "Body encoding",
      kind: "select",
      options: ["", "json", "form", "multipart", "raw"],
      optional: true,
    }),
    field("operation.body.value", { label: "Body", kind: "json", rows: 6, optional: true }),
  ],
  graphql: [
    field("operation.kind", { label: "Kind", kind: "select", options: ["query", "mutation"] }),
    field("operation.document", { label: "Document", kind: "code", rows: 8 }),
    field("operation.variables", { label: "Variables", kind: "json", rows: 4, optional: true }),
  ],
  database: [
    field("operation.kind", { label: "Kind", kind: "select", options: ["sql", "schema"] }),
    field("operation.statement", {
      label: "Statement",
      kind: "code",
      rows: 6,
      hint: "Arguments are bound as parameters, never pasted into the text.",
    }),
    field("operation.maxRows", { label: "Most rows returned", kind: "number", optional: true }),
  ],
  soap: [],
  mcp: [],
};

/** Reshapes the answer before the model sees it. Applies to every transport. */
export const transformField: FormField = field("response.transform.jmespath", {
  label: "Response transform (JMESPath)",
  kind: "text",
  optional: true,
  hint: "Leave empty to hand the model the whole response.",
});

/** Whether a transport has a form at all. */
export function hasForm(transport: Transport): boolean {
  return operationFields[transport].length > 0;
}

export const hints = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const;
export type Hint = (typeof hints)[number];
export type TriState = "auto" | "true" | "false";

export const hintLabels: Record<Hint, string> = {
  readOnlyHint: "Only reads",
  destructiveHint: "Can destroy data",
  idempotentHint: "Safe to repeat",
  openWorldHint: "Reaches the outside world",
};

/** An annotation as set in the definition: left to derivation, or forced. */
export function getHint(draft: ToolDraft, hint: Hint): TriState {
  const v = getAt(draft, ["annotations", hint]);
  if (v === true) return "true";
  if (v === false) return "false";
  return "auto";
}

/** Forces an annotation, or hands it back to derivation from the operation. */
export function setHint(draft: ToolDraft, hint: Hint, value: TriState): ToolDraft {
  return setAt(draft, ["annotations", hint], value === "auto" ? undefined : value === "true");
}

/** A starting point for a new tool on a connector of this transport. */
export function blankDefinition(transport: Transport): ToolDraft {
  const input: JsonObject = new Map<string, Json>([
    ["type", "object"],
    ["properties", new Map()],
  ]);
  const operation: JsonObject = new Map<string, Json>(
    transport === "http"
      ? [
          ["method", "GET"],
          ["path", "/"],
        ]
      : transport === "graphql"
        ? [
            ["kind", "query"],
            ["document", ""],
          ]
        : transport === "database"
          ? [
              ["kind", "sql"],
              ["statement", ""],
            ]
          : transport === "mcp"
            ? [["tool", ""]]
            : [
                ["action", ""],
                ["envelope", ""],
              ],
  );
  return new Map<string, Json>([
    ["name", ""],
    ["description", ""],
    ["input", input],
    ["operation", operation],
  ]);
}

/** One thing wrong with a draft, as the editor shows it. */
export interface FieldIssue {
  field?: string;
  message: string;
  severity: "error" | "warning";
}

/**
 * Where a server issue belongs on the form. Issues come either from a
 * dry-run (field is already a dotted path) or from a 422 problem detail,
 * whose location reads "body.definition.operation.path". A location the
 * form has no field for is shown with the whole tool, under "".
 */
export function issueField(location: string | undefined, known: readonly string[]): string {
  if (!location) return "";
  let key = location.replace(/^body\.definition\.?/, "");
  if (key === location && location.startsWith("body.")) return "";
  // Array indices and deeper paths belong to the nearest field shown.
  key = key.replace(/\[\d+\]/g, "");
  while (key !== "") {
    if (known.includes(key)) return key;
    const dot = key.lastIndexOf(".");
    key = dot < 0 ? "" : key.slice(0, dot);
  }
  return "";
}

/** Groups issues by the field they belong to. */
export function groupIssues(issues: readonly FieldIssue[], known: readonly string[]): Map<string, FieldIssue[]> {
  const out = new Map<string, FieldIssue[]>();
  for (const issue of issues) {
    const key = issueField(issue.field, known);
    const list = out.get(key) ?? [];
    list.push(issue);
    out.set(key, list);
  }
  return out;
}

/** Every field key the form might show for a transport, including the hints. */
export function knownFields(transport: Transport): string[] {
  return [
    ...commonFields.map((f) => f.key),
    ...operationFields[transport].map((f) => f.key),
    transformField.key,
    ...hints.map((h) => `annotations.${h}`),
    "annotations.title",
    "annotations",
    "operation",
  ];
}
