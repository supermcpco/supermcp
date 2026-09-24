import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text, Textarea } from "@cloudflare/kumo";
import type { ToolAnnotationsDto, ToolDetailDto, ToolWriteResult } from "../api";
import { toolsCreateMutation, toolsUpdateMutation } from "../api/@tanstack/react-query.gen";
import { details, message, status } from "../lib/errors";
import { useSession } from "../lib/session";
import {
  blankDefinition,
  commonFields,
  getAt,
  getHint,
  getJsonText,
  getText,
  groupIssues,
  hasForm,
  hintLabels,
  hints,
  knownFields,
  operationFields,
  parseDefinition,
  serializeDefinition,
  setHint,
  setJsonText,
  setNumber,
  setText,
  transformField,
  type FieldIssue,
  type FormField,
  type Hint,
  type ToolDraft,
  type Transport,
  type TriState,
} from "../lib/tool-definition";
import {
  blockingPolicies,
  invalidateTool,
  isReferencesConflict,
  isVersionConflict,
  useDraftDryRun,
  type BlockingPolicy,
} from "../lib/tool-api";
import { ToolPreview } from "./tool-preview";

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

/**
 * Creates a tool or changes one, with the request it would make shown
 * beside it as it is typed.
 *
 * The form and the JSON are two views of one draft. The form covers the
 * fields most edits touch; the JSON covers everything, including what the
 * form has no field for. Switching is refused while the side being left
 * does not parse, because a view that silently dropped what did not parse
 * would lose somebody's work.
 */
export function ToolEditor({
  connectorId,
  transport,
  tool,
  onSaved,
  onCancel,
  onReload,
}: {
  connectorId: string;
  transport: Transport;
  tool?: ToolDetailDto;
  onSaved: (result: ToolWriteResult) => Promise<void> | void;
  onCancel: () => void;
  /** Throws the draft away and reads the tool again, after a version conflict. */
  onReload?: () => void;
}) {
  const { can } = useSession();
  const qc = useQueryClient();
  const formAvailable = hasForm(transport);

  const initial = useMemo<{ draft: ToolDraft; text: string; error: string | null }>(() => {
    if (!tool) {
      const draft = blankDefinition(transport);
      return { draft, text: serializeDefinition(draft), error: null };
    }
    const parsed = parseDefinition(tool.definition);
    // A definition the server stored but this screen cannot read is shown
    // as the text it is, rather than replaced with an empty form.
    return parsed.ok
      ? { draft: parsed.draft, text: tool.definition, error: null }
      : { draft: blankDefinition(transport), text: tool.definition, error: parsed.error };
  }, [tool, transport]);

  const [view, setView] = useState<"form" | "json">(formAvailable && !initial.error ? "form" : "json");
  const [draft, setDraft] = useState<ToolDraft>(initial.draft);
  const [jsonText, setJsonTextState] = useState(initial.text);
  const [viewError, setViewError] = useState<string | null>(initial.error);
  // What somebody typed into a JSON field that does not parse yet. The
  // draft keeps the last version that did; the field keeps their text.
  const [fieldTexts, setFieldTexts] = useState<Record<string, string>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [args, setArgs] = useState("{}");
  const [error, setError] = useState<string | null>(null);
  const [serverIssues, setServerIssues] = useState<FieldIssue[]>([]);
  const [conflict, setConflict] = useState(false);
  const [ack, setAck] = useState<BlockingPolicy[] | null>(null);

  const jsonParsed = useMemo(() => parseDefinition(jsonText), [jsonText]);
  const definition: string | null = useMemo(() => {
    if (view === "json") return jsonParsed.ok ? jsonText : null;
    return serializeDefinition(draft);
  }, [view, jsonParsed, jsonText, draft]);
  const blocked = view === "json" ? !jsonParsed.ok : Object.keys(fieldErrors).length > 0;

  const canPreview = can("tools:invoke") && can("tools:update");
  const dryRun = useDraftDryRun({ connectorId, toolId: tool?.id, definition, args, enabled: canPreview });

  const known = useMemo(() => knownFields(transport), [transport]);
  const issues = useMemo(
    () => groupIssues([...serverIssues, ...(dryRun.data?.issues ?? [])], known),
    [serverIssues, dryRun.data, known],
  );
  const allIssues = [...serverIssues, ...(dryRun.data?.issues ?? [])];
  const inferred: ToolAnnotationsDto | undefined = dryRun.data?.inferredAnnotations ?? tool?.inferredAnnotations;

  const edited = () => {
    setServerIssues([]);
    setError(null);
    setAck(null);
  };
  const change = (next: ToolDraft) => {
    edited();
    setDraft(next);
  };

  const saved = async (result: ToolWriteResult) => {
    setError(null);
    setServerIssues([]);
    setAck(null);
    await invalidateTool(qc, connectorId, result.tool.id);
    await onSaved(result);
  };
  const failed = (e: unknown) => {
    setError(message(e));
    setServerIssues(
      status(e) === 422
        ? details(e).map((d) => ({ field: d.location ?? "", message: d.message ?? String(d.value ?? ""), severity: "error" }))
        : [],
    );
    if (tool && isReferencesConflict(e)) {
      setAck(blockingPolicies(e));
      return;
    }
    if (isVersionConflict(e)) setConflict(true);
  };
  const create = useMutation({ ...toolsCreateMutation(), onSuccess: saved, onError: failed });
  const update = useMutation({ ...toolsUpdateMutation(), onSuccess: saved, onError: failed });
  const saving = create.isPending || update.isPending;

  const save = (acknowledgeReferences = false) => {
    if (definition === null || blocked) {
      setError("The definition has JSON that does not parse. Put it right before saving.");
      return;
    }
    setError(null);
    if (tool) {
      update.mutate({
        path: { id: tool.id },
        body: { definition, expectedVersion: tool.version, acknowledgeReferences: acknowledgeReferences || undefined },
      });
      return;
    }
    create.mutate({ path: { id: connectorId }, body: { definition } });
  };

  const toJson = () => {
    const bad = Object.keys(fieldErrors);
    if (bad.length > 0) {
      setViewError(`${labelFor(bad[0])} is not valid JSON yet. Put it right before switching to the JSON view.`);
      return;
    }
    setViewError(null);
    setJsonTextState(serializeDefinition(draft));
    setView("json");
  };
  const toForm = () => {
    if (!jsonParsed.ok) {
      setViewError(`The JSON does not parse (${jsonParsed.error}). Put it right before switching to the form.`);
      return;
    }
    setViewError(null);
    setDraft(jsonParsed.draft);
    setFieldTexts({});
    setFieldErrors({});
    setView("form");
  };

  const fieldProps = (f: FormField) => ({
    field: f,
    draft,
    issues: issues.get(f.key) ?? [],
    text: fieldTexts[f.key],
    parseError: fieldErrors[f.key],
    onDraft: change,
    onText: (text: string, err: string | null) => {
      edited();
      setFieldTexts((t) => ({ ...t, [f.key]: text }));
      setFieldErrors((current) => {
        const next = { ...current };
        if (err) next[f.key] = err;
        else delete next[f.key];
        return next;
      });
    },
  });

  const wholeTool = issues.get("") ?? [];

  return (
    <form
      className="grid gap-5"
      onSubmit={(e) => {
        e.preventDefault();
        save(false);
      }}
    >
      {error && (
        <div role="alert" className="grid gap-2 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{error}</Text>
          {conflict && onReload && (
            <div>
              <Button type="button" onClick={onReload}>
                Reload the tool
              </Button>
            </div>
          )}
        </div>
      )}

      {ack && (
        <section
          aria-labelledby="tool-ack-heading"
          className="grid gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line"
        >
          <Text as="h3" bold id="tool-ack-heading">
            Approval policies match this tool by its current name
          </Text>
          <Text>
            After the rename they will no longer apply to it. They are not changed automatically, because a name can
            match tools on other connectors too.
          </Text>
          {ack.length > 0 && (
            <ul className="grid list-disc gap-1 pl-5">
              {ack.map((p) => (
                <li key={p.id}>
                  <Text as="span">{p.name}</Text>
                </li>
              ))}
            </ul>
          )}
          <div className="flex flex-wrap gap-3">
            <Button type="button" variant="primary" disabled={saving} onClick={() => save(true)}>
              Rename anyway
            </Button>
            <Button type="button" onClick={() => setAck(null)}>
              Keep editing
            </Button>
          </div>
        </section>
      )}

      <div className="flex flex-wrap items-center gap-3">
        {formAvailable ? (
          <div role="group" aria-label="How to edit" className="flex gap-2">
            <Button type="button" aria-pressed={view === "form"} onClick={view === "form" ? undefined : toForm}>
              Form
            </Button>
            <Button type="button" aria-pressed={view === "json"} onClick={view === "json" ? undefined : toJson}>
              JSON
            </Button>
          </div>
        ) : (
          <Text variant="secondary">
            A {transport.toUpperCase()} tool is edited as JSON. The request it would make cannot be previewed.
          </Text>
        )}
      </div>

      {viewError && (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{viewError}</Text>
        </div>
      )}

      {wholeTool.length > 0 && <IssueList id="tool-issues-whole" issues={wholeTool} />}

      <div className="grid gap-4 lg:grid-cols-[3fr_2fr]">
        <div className="grid content-start gap-4">
          {view === "form" ? (
            <>
              <fieldset className="grid gap-3 rounded-md px-4 py-3 ring ring-kumo-line">
                <legend className="px-1">
                  <Text as="span" bold>
                    The tool
                  </Text>
                </legend>
                {commonFields.map((f) => (
                  <Field key={f.key} {...fieldProps(f)} />
                ))}
              </fieldset>

              <fieldset className="grid gap-3 rounded-md px-4 py-3 ring ring-kumo-line">
                <legend className="px-1">
                  <Text as="span" bold>
                    What it calls
                  </Text>
                </legend>
                {operationFields[transport].map((f) => (
                  <Field key={f.key} {...fieldProps(f)} />
                ))}
                <Field {...fieldProps(transformField)} />
              </fieldset>

              <fieldset className="grid gap-3 rounded-md px-4 py-3 ring ring-kumo-line">
                <legend className="px-1">
                  <Text as="span" bold>
                    Hints clients see
                  </Text>
                </legend>
                <Text variant="secondary">
                  Left to work out, a hint follows from the operation: a GET only reads, a DELETE can destroy data.
                  Setting one overrides that.
                </Text>
                <label className="grid gap-1.5">
                  <Text as="span">Title shown to people</Text>
                  <Input
                    value={getText(draft, ["annotations", "title"])}
                    onChange={(e) => change(setText(draft, ["annotations", "title"], e.target.value))}
                  />
                </label>
                <div className="grid gap-3 sm:grid-cols-2">
                  {hints.map((h) => (
                    <HintSelect
                      key={h}
                      hint={h}
                      value={getHint(draft, h)}
                      inferred={inferred?.[h]}
                      issues={issues.get(`annotations.${h}`) ?? []}
                      onChange={(v) => change(setHint(draft, h, v))}
                    />
                  ))}
                </div>
              </fieldset>
            </>
          ) : (
            <div className="grid gap-3">
            <label className="grid gap-1.5">
              <Text as="span">Definition (JSON)</Text>
              <Textarea
                rows={28}
                className="font-mono text-[0.85em]"
                spellCheck={false}
                value={jsonText}
                onChange={(e) => {
                  edited();
                  setJsonTextState(e.target.value);
                }}
                aria-invalid={!jsonParsed.ok}
                aria-describedby={!jsonParsed.ok ? "tool-json-error" : undefined}
              />
              {!jsonParsed.ok && (
                <Text as="span" variant="secondary" id="tool-json-error">
                  {jsonParsed.error}
                </Text>
              )}
            </label>
              {allIssues.length > 0 && (
                <IssueList id="tool-issues-json" issues={allIssues} withField />
              )}
            </div>
          )}
        </div>

        <ToolPreview
          canPreview={canPreview}
          unsupported={!formAvailable}
          args={args}
          onArgs={setArgs}
          invalidDraft={definition === null}
          pending={dryRun.isFetching}
          error={dryRun.error}
          result={dryRun.data}
        />
      </div>

      <div className="flex flex-wrap gap-3">
        <Button type="submit" variant="primary" disabled={saving || blocked}>
          {saving ? "Saving…" : tool ? "Save changes" : "Create tool"}
        </Button>
        <Button type="button" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

/** The label a field key is shown under, for messages that name it. */
function labelFor(key: string): string {
  const all = [...commonFields, ...Object.values(operationFields).flat(), transformField];
  return all.find((f) => f.key === key)?.label ?? key;
}

/** One form field, its hint and whatever is wrong with it. */
function Field({
  field: f,
  draft,
  issues,
  text,
  parseError,
  onDraft,
  onText,
}: {
  field: FormField;
  draft: ToolDraft;
  issues: FieldIssue[];
  text: string | undefined;
  parseError: string | undefined;
  onDraft: (draft: ToolDraft) => void;
  onText: (text: string, error: string | null) => void;
}) {
  const id = `tool-field-${f.key.replace(/\./g, "-")}`;
  const hintId = f.hint ? `${id}-hint` : undefined;
  const issuesId = issues.length > 0 || parseError ? `${id}-issues` : undefined;
  const describedBy = [hintId, issuesId].filter(Boolean).join(" ") || undefined;
  const invalid = !!parseError || issues.some((i) => i.severity === "error");
  const common = { "aria-describedby": describedBy, "aria-invalid": invalid || undefined };

  let control: React.ReactNode;
  switch (f.kind) {
    case "select": {
      const current = getText(draft, f.path);
      const options = f.options ?? [];
      const all = current && !options.includes(current) ? [current, ...options] : options;
      control = (
        <select
          className={selectClass}
          value={current}
          onChange={(e) => onDraft(setText(draft, f.path, e.target.value, f.optional ?? false))}
          {...common}
        >
          {all.map((o) => (
            <option key={o} value={o}>
              {o === "" ? "Default" : o}
            </option>
          ))}
        </select>
      );
      break;
    }
    case "number":
      control = (
        <Input
          inputMode="numeric"
          value={getText(draft, f.path)}
          onChange={(e) => onDraft(setNumber(draft, f.path, e.target.value))}
          {...common}
        />
      );
      break;
    case "json":
      control = (
        <Textarea
          rows={f.rows ?? 4}
          className="font-mono text-[0.85em]"
          spellCheck={false}
          value={text ?? getJsonText(draft, f.path)}
          onChange={(e) => {
            const value = e.target.value;
            const result = setJsonText(draft, f.path, value);
            if (result.ok) onDraft(result.draft);
            onText(value, result.ok ? null : result.error);
          }}
          {...common}
        />
      );
      break;
    case "code":
    case "textarea":
      control = (
        <Textarea
          rows={f.rows ?? 3}
          className={f.kind === "code" ? "font-mono text-[0.85em]" : undefined}
          spellCheck={f.kind !== "code"}
          value={getText(draft, f.path)}
          onChange={(e) => onDraft(setText(draft, f.path, e.target.value, f.optional ?? false))}
          {...common}
        />
      );
      break;
    default:
      control = (
        <Input
          className={f.key === "name" || f.key.startsWith("operation.") || f.key.startsWith("response.") ? "font-mono" : undefined}
          value={getText(draft, f.path)}
          onChange={(e) => onDraft(setText(draft, f.path, e.target.value, f.optional ?? false))}
          {...common}
        />
      );
  }

  return (
    <div className="grid gap-1.5">
      <label className="grid gap-1.5">
        <Text as="span">{f.label}</Text>
        {control}
      </label>
      {f.hint && (
        <Text as="span" variant="secondary" id={hintId}>
          {f.hint}
        </Text>
      )}
      {issuesId && (
        <ul id={issuesId} className="grid gap-0.5">
          {parseError && (
            <li>
              <Text as="span">Not valid JSON: {parseError}</Text>
            </li>
          )}
          {issues.map((i, n) => (
            <li key={`${i.field}-${n}`}>
              <Text as="span">
                {i.severity === "warning" ? "Warning: " : ""}
                {i.message}
              </Text>
            </li>
          ))}
        </ul>
      )}
      {/* A value the form cannot show would otherwise look empty. */}
      {f.kind !== "json" && isStructured(getAt(draft, f.path)) && (
        <Text as="span" variant="secondary">
          This value is not plain text; edit it in the JSON view.
        </Text>
      )}
    </div>
  );
}

function isStructured(v: unknown): boolean {
  return v !== undefined && v !== null && typeof v === "object";
}

/** One annotation: left to derivation, or forced on or off. */
function HintSelect({
  hint,
  value,
  inferred,
  issues,
  onChange,
}: {
  hint: Hint;
  value: TriState;
  inferred: boolean | undefined;
  issues: FieldIssue[];
  onChange: (v: TriState) => void;
}) {
  const auto = inferred === undefined ? "Work it out" : `Work it out (now ${inferred ? "yes" : "no"})`;
  const issuesId = issues.length > 0 ? `tool-hint-${hint}-issues` : undefined;
  const declassifies = hint === "destructiveHint" && value === "false" && inferred === true;
  return (
    <div className="grid gap-1.5">
      <label className="grid gap-1.5">
        <Text as="span">{hintLabels[hint]}</Text>
        <select
          className={selectClass}
          value={value}
          onChange={(e) => onChange(e.target.value as TriState)}
          aria-describedby={issuesId}
        >
          <option value="auto">{auto}</option>
          <option value="true">Yes</option>
          <option value="false">No</option>
        </select>
      </label>
      {declassifies && (
        <Text as="span" variant="secondary">
          The operation looks destructive. Saying it is not needs permission to call destructive tools.
        </Text>
      )}
      {issuesId && <IssueList id={issuesId} issues={issues} />}
    </div>
  );
}

function IssueList({ id, issues, withField }: { id: string; issues: FieldIssue[]; withField?: boolean }) {
  return (
    <ul id={id} className="grid gap-1 rounded-md px-4 py-3 ring ring-kumo-line">
      {issues.map((i, n) => (
        <li key={`${i.field}-${n}`}>
          <Text as="span">
            {i.severity === "warning" ? "Warning: " : ""}
            {withField && i.field ? `${i.field.replace(/^body\.definition\.?/, "")}: ` : ""}
            {i.message}
          </Text>
        </li>
      ))}
    </ul>
  );
}
