import { describe, expect, it } from "vitest";
import {
  blankDefinition,
  getAt,
  getHint,
  getJsonText,
  getText,
  groupIssues,
  issueField,
  knownFields,
  parseDefinition,
  parseJson,
  serializeDefinition,
  setAt,
  setHint,
  setJsonText,
  setNumber,
  setText,
  stringifyJson,
  type ToolDraft,
} from "./tool-definition";
import {
  blockingPolicies,
  conflictCode,
  isReferencesConflict,
  isVersionConflict,
  readArguments,
  transportOf,
} from "./tool-api";

const stored = `{
  "name": "get_item",
  "description": "Reads one item",
  "input": {
    "type": "object",
    "properties": {
      "zeta": {
        "type": "string"
      },
      "200": {
        "type": "string"
      },
      "alpha": {
        "type": "string"
      }
    },
    "required": [
      "zeta"
    ]
  },
  "operation": {
    "method": "GET",
    "path": "/items/{{params.zeta}}",
    "headers": {
      "X-B": "2",
      "X-A": "1"
    }
  }
}`;

function draft(): ToolDraft {
  const parsed = parseDefinition(stored);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.draft;
}

describe("parse and serialize", () => {
  it("round-trips the stored definition byte for byte", () => {
    expect(serializeDefinition(draft())).toBe(stored);
  });

  it("keeps keys that look like numbers where they were", () => {
    const props = getAt(draft(), ["input", "properties"]);
    expect(props instanceof Map ? [...props.keys()] : null).toEqual(["zeta", "200", "alpha"]);
    // A plain object would have hoisted "200" to the front.
    expect(Object.keys(JSON.parse(stored).input.properties)).toEqual(["200", "zeta", "alpha"]);
  });

  it("reads compact JSON and every kind of value", () => {
    const v = parseJson('{"a":[1,-2.5e3,true,false,null,"x\\n\\u00e9"],"b":{}}');
    expect(stringifyJson(v, 0).replace(/\n/g, "")).toBe('{"a": [1,-2500,true,false,null,"x\\né"],"b": {}}');
  });

  it("says where the JSON went wrong", () => {
    const bad = parseDefinition('{\n  "name": "x",\n  "input": }');
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.error).toMatch(/line 3/);
    expect(parseDefinition('{"a": 1} trailing').ok).toBe(false);
    expect(parseDefinition('{"a": 1,}').ok).toBe(false);
    expect(parseDefinition('"just a string"').ok).toBe(false);
  });
});

describe("editing the draft", () => {
  it("changes a value in place without moving it", () => {
    const next = setText(draft(), ["operation", "method"], "POST");
    expect([...(getAt(next, ["operation"]) as Map<string, unknown>).keys()]).toEqual(["method", "path", "headers"]);
    expect(getText(next, ["operation", "method"])).toBe("POST");
    // The draft it came from is left alone.
    expect(getText(draft(), ["operation", "method"])).toBe("GET");
  });

  it("puts a new key at the end and creates the objects on the way", () => {
    const next = setText(draft(), ["response", "transform", "jmespath"], "items[0]");
    expect([...next.keys()].at(-1)).toBe("response");
    expect(getText(next, ["response", "transform", "jmespath"])).toBe("items[0]");
  });

  it("removes an optional field left empty, and the objects it emptied", () => {
    const withTransform = setText(draft(), ["response", "transform", "jmespath"], "items");
    const cleared = setText(withTransform, ["response", "transform", "jmespath"], "");
    expect(cleared.has("response")).toBe(false);
    expect(serializeDefinition(cleared)).toBe(stored);
  });

  it("keeps a required field that is emptied in its place", () => {
    const cleared = setText(draft(), ["name"], "", false);
    const again = setText(cleared, ["name"], "get_item", false);
    expect(serializeDefinition(again)).toBe(stored);
  });

  it("removing something that is not there changes nothing", () => {
    const d = draft();
    expect(setAt(d, ["response", "transform"], undefined)).toBe(d);
  });

  it("edits nested JSON as text and refuses text that does not parse", () => {
    const text = getJsonText(draft(), ["operation", "headers"]);
    expect(text).toBe('{\n  "X-B": "2",\n  "X-A": "1"\n}');
    const bad = setJsonText(draft(), ["operation", "headers"], '{"X-B": ');
    expect(bad.ok).toBe(false);
    const good = setJsonText(draft(), ["operation", "headers"], '{"X-A": "1"}');
    expect(good.ok && getJsonText(good.draft, ["operation", "headers"])).toBe('{\n  "X-A": "1"\n}');
    const gone = setJsonText(draft(), ["operation", "headers"], "  ");
    expect(gone.ok && getAt(gone.draft, ["operation", "headers"])).toBe(undefined);
  });

  it("stores a number as a number", () => {
    const d = setNumber(blankDefinition("database"), ["operation", "maxRows"], "50");
    expect(getAt(d, ["operation", "maxRows"])).toBe(50);
    expect(getAt(setNumber(d, ["operation", "maxRows"], ""), ["operation", "maxRows"])).toBe(undefined);
  });
});

describe("annotation hints", () => {
  it("are auto until set, and go back to auto without leaving an empty object", () => {
    const d = draft();
    expect(getHint(d, "destructiveHint")).toBe("auto");
    const off = setHint(d, "destructiveHint", "false");
    expect(getHint(off, "destructiveHint")).toBe("false");
    expect(getAt(off, ["annotations", "destructiveHint"])).toBe(false);
    const on = setHint(off, "readOnlyHint", "true");
    expect(getHint(on, "readOnlyHint")).toBe("true");
    const back = setHint(setHint(on, "readOnlyHint", "auto"), "destructiveHint", "auto");
    expect(back.has("annotations")).toBe(false);
    expect(serializeDefinition(back)).toBe(stored);
  });

  it("keep a title when the hints go back to auto", () => {
    const titled = setText(setHint(draft(), "openWorldHint", "true"), ["annotations", "title"], "Get item");
    const back = setHint(titled, "openWorldHint", "auto");
    expect(getText(back, ["annotations", "title"])).toBe("Get item");
  });
});

describe("blank definitions", () => {
  it("start each transport with the operation fields it needs", () => {
    expect(getText(blankDefinition("http"), ["operation", "method"])).toBe("GET");
    expect(getText(blankDefinition("graphql"), ["operation", "kind"])).toBe("query");
    expect(getText(blankDefinition("database"), ["operation", "kind"])).toBe("sql");
    expect([...blankDefinition("http").keys()]).toEqual(["name", "description", "input", "operation"]);
  });
});

describe("issues", () => {
  const known = knownFields("http");

  it("put a 422 location next to the field it names", () => {
    expect(issueField("body.definition.operation.path", known)).toBe("operation.path");
    expect(issueField("operation.method", known)).toBe("operation.method");
    expect(issueField("body.definition.name", known)).toBe("name");
  });

  it("belong to the nearest field shown when they point deeper", () => {
    expect(issueField("body.definition.input.properties.zeta.type", known)).toBe("input");
    expect(issueField("operation.body.value.items[2]", known)).toBe("operation.body.value");
    expect(issueField("body.definition.annotations.destructiveHint", known)).toBe("annotations.destructiveHint");
  });

  it("go with the whole tool when no field matches", () => {
    expect(issueField(undefined, known)).toBe("");
    expect(issueField("body.definition", known)).toBe("");
    expect(issueField("body.expectedVersion", known)).toBe("");
    expect(issueField("timeout", known)).toBe("");
  });

  it("are grouped by field", () => {
    const grouped = groupIssues(
      [
        { field: "operation.path", message: "a", severity: "error" },
        { field: "body.definition.operation.path", message: "b", severity: "error" },
        { message: "c", severity: "warning" },
      ],
      known,
    );
    expect(grouped.get("operation.path")?.map((i) => i.message)).toEqual(["a", "b"]);
    expect(grouped.get("")?.map((i) => i.message)).toEqual(["c"]);
  });
});

describe("tool api helpers", () => {
  it("tell the kinds of 409 apart by their code, not their wording", () => {
    const refs = {
      status: 409,
      detail: "whatever the server says",
      errors: [
        { location: "body.acknowledgeReferences", message: "acknowledge", value: "references_unacknowledged" },
        { location: "references.approvalPolicies", message: "Payments need a second pair of eyes", value: "pol_1" },
        { location: "references.approvalPolicies", message: "Night shift", value: "pol_2" },
      ],
    };
    const version = {
      status: 409,
      detail: "approval policies refer to this tool by name",
      errors: [{ location: "body.expectedVersion", value: "version_conflict" }],
    };
    expect(conflictCode(refs)).toBe("references_unacknowledged");
    expect(isReferencesConflict(refs)).toBe(true);
    expect(isVersionConflict(refs)).toBe(false);
    expect(isVersionConflict(version)).toBe(true);
    expect(isReferencesConflict(version)).toBe(false);
    expect(conflictCode({ status: 409, errors: [{ location: "body", value: "not_deletable" }] })).toBe("not_deletable");
    expect(conflictCode({ status: 409, errors: [{ location: "body.definition", value: "name_taken" }] })).toBe(
      "name_taken",
    );
    expect(conflictCode({ status: 422, errors: refs.errors })).toBe(undefined);
    expect(conflictCode({ status: 409, detail: "no details" })).toBe(undefined);
    expect(blockingPolicies(refs)).toEqual([
      { id: "pol_1", name: "Payments need a second pair of eyes" },
      { id: "pol_2", name: "Night shift" },
    ]);
    expect(blockingPolicies(version)).toEqual([]);
  });

  it("read the arguments the preview is worked out for", () => {
    expect(readArguments("")).toEqual({ ok: true, value: {} });
    expect(readArguments('{"a": {"b": [1]}}')).toEqual({ ok: true, value: { a: { b: [1] } } });
    expect(readArguments("[1]").ok).toBe(false);
    expect(readArguments("{").ok).toBe(false);
  });

  it("know the connector's transport", () => {
    expect(transportOf({ type: "graphql" })).toBe("graphql");
    expect(transportOf({ type: "carrier-pigeon" })).toBe("http");
    expect(transportOf(undefined)).toBe("http");
  });
});
