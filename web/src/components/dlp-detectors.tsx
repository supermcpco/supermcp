import { useId, useState } from "react";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Input, Text, Textarea } from "@cloudflare/kumo";
import {
  dlpDetectorCreateMutation,
  dlpDetectorDeleteMutation,
  dlpDetectorGetOptions,
  dlpDetectorGetQueryKey,
  dlpDetectorsOptions,
  dlpDetectorsQueryKey,
  dlpDetectorsRevisionsListOptions,
  dlpDetectorsRevisionsListQueryKey,
  dlpDetectorsRevisionsRestoreMutation,
  dlpDetectorUpdateMutation,
  dlpPoliciesListQueryKey,
} from "../api/@tanstack/react-query.gen";
import { dlpDetectorTest } from "../api";
import type { CustomDetectorDto } from "../api";
import { useDebounced } from "../lib/debounce";
import { message } from "../lib/errors";
import { formatSamples, isStale, parseSamples, referencingPolicies, verdicts } from "../lib/dlp-detectors";
import { Badge, Loading } from "../lib/ui";
import { HistoryPanel } from "./revisions";

/** How long typing must pause before the pattern is tried again. */
const testTypingMs = 300;

const codeClass = "overflow-x-auto rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]";

/**
 * The workspace's own detectors: patterns for identifiers the built-ins
 * cannot know, such as customer numbers and contract ids. A rule uses one
 * when it names it, as custom:<name>, beside the built-ins it names.
 */
export function DetectorsPanel({ canManage, canRestore }: { canManage: boolean; canRestore: boolean }) {
  const qc = useQueryClient();
  const detectors = useQuery({ ...dlpDetectorsOptions(), retry: false });
  const [editing, setEditing] = useState<string | null>(null);
  const [history, setHistory] = useState<string | null>(null);

  // A delete can take a detector out of rules, so both lists are read again.
  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: dlpDetectorsQueryKey() });
    await qc.invalidateQueries({ queryKey: dlpPoliciesListQueryKey() });
  };
  const list = detectors.data?.custom ?? [];

  return (
    <div className="grid gap-6">
      <Text>
        Patterns for identifiers only this workspace knows, such as customer numbers or contract ids. A rule runs a
        detector when it names it, beside the built-in detectors it names. Each pattern is tried against its samples
        whenever it is saved. Use made-up samples: they are stored as written.
      </Text>

      {detectors.error && (
        <div role="alert">
          <Text>{message(detectors.error)}</Text>
        </div>
      )}

      <section className="grid gap-2">
        <Text as="h2" variant="heading3">
          Detectors
        </Text>
        {detectors.isPending && <Loading />}
        {!detectors.isPending && list.length === 0 && (
          <Text variant="secondary">No detectors of this workspace's own yet; rules use the built-in ones.</Text>
        )}
        <ul className="grid gap-2">
          {list.map((d) => (
            <li key={d.id} className="grid gap-4 rounded-lg px-5 py-4 ring ring-kumo-line">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="grid gap-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Text as="span" bold>
                      {d.name}
                    </Text>
                    <Badge>{d.detector}</Badge>
                    {d.flags === "i" && <Badge>any case</Badge>}
                    {!d.enabled && <Badge>off</Badge>}
                  </div>
                  {d.description && (
                    <Text as="span" variant="secondary">
                      {d.description}
                    </Text>
                  )}
                  {/* The server sends the pattern only to those who may
                      change it, and the samples to nobody in a list. */}
                  {d.pattern && <code className={codeClass}>{d.pattern}</code>}
                  <Text as="span" variant="secondary">
                    {d.mustMatchCount} {d.mustMatchCount === 1 ? "sample" : "samples"} it must match,{" "}
                    {d.mustNotMatchCount} it must not
                  </Text>
                </div>
                <div className="flex flex-wrap gap-2">
                  {canManage && editing !== d.id && (
                    <Button variant="secondary" onClick={() => setEditing(d.id)} aria-label={`Change ${d.name}`}>
                      Change
                    </Button>
                  )}
                  <Button
                    variant="secondary"
                    onClick={() => setHistory((current) => (current === d.id ? null : d.id))}
                    aria-expanded={history === d.id}
                    aria-label={`${history === d.id ? "Hide the history of" : "History of"} ${d.name}`}
                  >
                    {history === d.id ? "Hide history" : "History"}
                  </Button>
                </div>
              </div>
              {canManage && <DeleteDetector detector={d} onDeleted={refresh} />}
              {canManage && editing === d.id && (
                <EditDetector
                  id={d.id}
                  onDone={async () => {
                    setEditing(null);
                    await refresh();
                    await qc.invalidateQueries({ queryKey: dlpDetectorGetQueryKey({ path: { id: d.id } }) });
                    await qc.invalidateQueries({ queryKey: dlpDetectorsRevisionsListQueryKey({ path: { id: d.id } }) });
                  }}
                  onCancel={() => setEditing(null)}
                />
              )}
              {history === d.id && <DetectorHistory detector={d} canRestore={canRestore} onRestored={refresh} />}
            </li>
          ))}
        </ul>
      </section>

      {canManage && (
        <section className="grid gap-3">
          <Text as="h2" variant="heading3">
            Add a detector
          </Text>
          <DetectorForm onDone={refresh} />
        </section>
      )}
    </div>
  );
}

/**
 * The editor for one stored detector. The list carries no samples, so the
 * detector is read on its own first; the form opens on what came back.
 */
function EditDetector({ id, onDone, onCancel }: { id: string; onDone: () => Promise<void>; onCancel: () => void }) {
  const one = useQuery({ ...dlpDetectorGetOptions({ path: { id } }), retry: false });
  if (one.error) {
    return (
      <div role="alert">
        <Text>{message(one.error)}</Text>
      </div>
    );
  }
  if (!one.data) return <Loading />;
  return <DetectorForm key={one.data.version} detector={one.data} onDone={onDone} onCancel={onCancel} />;
}

/**
 * Deleting a detector a rule uses is refused, and the refusal names the
 * rules. Confirming deletes it anyway and takes it out of them; a rule
 * left with no detector is switched off rather than falling back to every
 * built-in.
 */
function DeleteDetector({ detector, onDeleted }: { detector: CustomDetectorDto; onDeleted: () => Promise<void> }) {
  const remove = useMutation({ ...dlpDetectorDeleteMutation(), onSuccess: onDeleted });
  const users = remove.error ? referencingPolicies(remove.error) : [];
  return (
    <div className="grid gap-2">
      {remove.error && (
        <div role="alert" className="grid gap-2">
          <Text>{message(remove.error)}</Text>
          {users.length > 0 && (
            <>
              <Text variant="secondary">
                Deleting it anyway takes it out of {users.length === 1 ? "that rule" : "those rules"}. A rule left with
                no detector is switched off.
              </Text>
              <div>
                <Button
                  variant="secondary"
                  onClick={() => remove.mutate({ path: { id: detector.id }, query: { force: true } })}
                  disabled={remove.isPending}
                >
                  Delete {detector.name} and take it out of the rules
                </Button>
              </div>
            </>
          )}
        </div>
      )}
      <div>
        <Button
          variant="secondary"
          onClick={() => remove.mutate({ path: { id: detector.id } })}
          disabled={remove.isPending}
          aria-label={`Delete ${detector.name}`}
        >
          Delete
        </Button>
      </div>
    </div>
  );
}

/**
 * Adds a detector, or changes one. The pattern is tried against the
 * samples as it is typed, by the same rules a save applies, and the
 * outcome is shown per sample; only offsets come back from the server.
 */
function DetectorForm({
  detector,
  onDone,
  onCancel,
}: {
  detector?: CustomDetectorDto;
  onDone: () => Promise<void>;
  onCancel?: () => void;
}) {
  const [name, setName] = useState(detector?.name ?? "");
  const [description, setDescription] = useState(detector?.description ?? "");
  const [pattern, setPattern] = useState(detector?.pattern ?? "");
  const [anyCase, setAnyCase] = useState(detector?.flags === "i");
  const [mustMatchText, setMustMatchText] = useState(formatSamples(detector?.mustMatch));
  const [mustNotMatchText, setMustNotMatchText] = useState(formatSamples(detector?.mustNotMatch));
  const [enabled, setEnabled] = useState(detector?.enabled ?? true);

  const reset = () => {
    setName("");
    setDescription("");
    setPattern("");
    setAnyCase(false);
    setMustMatchText("");
    setMustNotMatchText("");
    setEnabled(true);
  };
  const create = useMutation({
    ...dlpDetectorCreateMutation(),
    onSuccess: async () => {
      reset();
      await onDone();
    },
  });
  const update = useMutation({ ...dlpDetectorUpdateMutation(), onSuccess: onDone });
  const save = detector ? update : create;

  const flags = anyCase ? ("i" as const) : ("" as const);
  const mustMatch = parseSamples(mustMatchText);
  const mustNotMatch = parseSamples(mustNotMatchText);
  const tried = useTryPattern(pattern, flags, mustMatch, mustNotMatch);
  const label = detector ? detector.name : "the new detector";
  // Two forms can be open at once, the new one and an edit, so the help
  // text each points at needs an id of its own.
  const helpId = useId();

  return (
    <form
      className={detector ? "grid gap-3 border-t border-kumo-line pt-4" : "grid gap-3"}
      aria-label={detector ? `Change ${detector.name}` : "Add a detector"}
      onSubmit={(e) => {
        e.preventDefault();
        const body = { description, pattern, flags, mustMatch, mustNotMatch, enabled };
        if (detector) {
          update.mutate({ path: { id: detector.id }, body: { ...body, expectedVersion: detector.version } });
        } else {
          create.mutate({ body: { ...body, name } });
        }
      }}
    >
      {save.error && (
        <div role="alert" className="grid gap-2">
          <Text>{message(save.error)}</Text>
          {detector && isStale(save.error) && (
            <div>
              <Button variant="secondary" onClick={onDone}>
                Reload the detector
              </Button>
            </div>
          )}
        </div>
      )}
      {detector ? (
        <Text variant="secondary">
          Rules name this detector <code className={codeClass}>{detector.detector}</code>. Its name cannot change.
        </Text>
      ) : (
        <div className="grid gap-1">
          <label className="grid gap-1">
            <Text as="span">Detector name</Text>
            <Input
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
              required
              maxLength={63}
              aria-describedby="detector-name-help"
            />
          </label>
          <Text as="span" variant="secondary" id="detector-name-help">
            Lower-case letters, digits, - and _. Rules name it custom:{name || "<name>"}, and it cannot change later.
          </Text>
        </div>
      )}
      <label className="grid gap-1">
        <Text as="span">Description</Text>
        <Input value={description} onChange={(e) => setDescription(e.currentTarget.value)} maxLength={500} />
      </label>
      <div className="grid gap-1">
        <label className="grid gap-1">
          <Text as="span">Pattern</Text>
          <Input
            value={pattern}
            onChange={(e) => setPattern(e.currentTarget.value)}
            required
            maxLength={512}
            className="font-mono"
            spellCheck={false}
            aria-describedby={helpId}
          />
        </label>
        <Text as="span" variant="secondary" id={helpId}>
          An RE2 regular expression of 3 to 512 bytes that cannot match an empty string, such as {"\\bCN-\\d{6}\\b"}.
          Lookarounds and backreferences are not available, and very large repetition counts are refused because the
          pattern runs on every tool call.
        </Text>
      </div>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={anyCase} onChange={(e) => setAnyCase(e.currentTarget.checked)} />
        <Text as="span">Ignore upper and lower case</Text>
      </label>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="grid gap-1">
          <Text as="span">Samples it must match, one per line</Text>
          <Textarea
            rows={4}
            value={mustMatchText}
            onChange={(e) => setMustMatchText(e.currentTarget.value)}
            className="font-mono"
            spellCheck={false}
          />
        </label>
        <label className="grid gap-1">
          <Text as="span">Samples it must not match, one per line</Text>
          <Textarea
            rows={4}
            value={mustNotMatchText}
            onChange={(e) => setMustNotMatchText(e.currentTarget.value)}
            className="font-mono"
            spellCheck={false}
          />
        </label>
      </div>
      <section aria-label={`What the pattern of ${label} matches`} aria-live="polite" className="grid gap-1">
        {tried.error && <Text>The pattern cannot be used: {message(tried.error)}</Text>}
        {!tried.error && tried.data && tried.data.samples.length === 0 && (
          <Text variant="secondary">The pattern compiles. Add samples to see what it matches.</Text>
        )}
        {!tried.error && tried.data && tried.data.samples.length > 0 && (
          <ul className="grid gap-1">
            {verdicts(mustMatch.length, tried.data.samples).map((v) => {
              const samples = v.list === "mustMatch" ? mustMatch : mustNotMatch;
              return (
                <li key={`${v.list}-${v.position}`}>
                  <Text as="span">
                    {v.expected ? "As expected" : "Not as expected"}: <code className={codeClass}>{samples[v.position]}</code>{" "}
                    {v.where}
                    {v.list === "mustMatch" ? " (must match)" : " (must not match)"}
                  </Text>
                </li>
              );
            })}
          </ul>
        )}
      </section>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
        <Text as="span">The detector is on</Text>
      </label>
      <div className="flex flex-wrap gap-2">
        <Button
          type="submit"
          variant="primary"
          disabled={save.isPending || pattern.length < 3 || (!detector && name.trim() === "")}
        >
          {detector ? "Save the detector" : "Add the detector"}
        </Button>
        {onCancel && <Button onClick={onCancel}>Cancel</Button>}
      </div>
    </form>
  );
}

/**
 * Tries the pattern on both lists of samples once typing pauses. The test
 * writes nothing, so it is a query: it is asked again whenever what it
 * would be asked about changes, and the previous answer stays on screen
 * meanwhile.
 */
function useTryPattern(pattern: string, flags: "" | "i", mustMatch: string[], mustNotMatch: string[]) {
  // Each part settles on its own: a new array every render never would.
  const settledPattern = useDebounced(pattern, testTypingMs);
  const settledFlags = useDebounced(flags, testTypingMs);
  const settledSamples = useDebounced(JSON.stringify([...mustMatch, ...mustNotMatch]), testTypingMs);
  return useQuery({
    queryKey: ["dlp-detector-test", settledPattern, settledFlags, settledSamples],
    enabled: settledPattern.length >= 3,
    retry: false,
    placeholderData: keepPreviousData,
    queryFn: async ({ signal }) => {
      const samples = JSON.parse(settledSamples) as string[];
      const { data } = await dlpDetectorTest({
        body: { pattern: settledPattern, flags: settledFlags, samples },
        signal,
        throwOnError: true,
      });
      return data;
    },
  });
}

/**
 * Every change to one detector, and the version it can be put back to. A
 * restore takes effect on the next tool call on every replica, as an edit
 * does.
 */
function DetectorHistory({
  detector,
  canRestore,
  onRestored,
}: {
  detector: CustomDetectorDto;
  canRestore: boolean;
  onRestored: () => Promise<void>;
}) {
  const qc = useQueryClient();
  const key = { path: { id: detector.id } };
  const revisions = useQuery({ ...dlpDetectorsRevisionsListOptions(key), retry: false });
  const restore = useMutation({
    ...dlpDetectorsRevisionsRestoreMutation(),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: dlpDetectorsRevisionsListQueryKey(key) });
      await onRestored();
    },
  });
  return (
    <HistoryPanel
      label={`History of ${detector.name}`}
      intro="Every change to this detector, newest first. The history keeps how many samples there were, not the samples themselves, so a restore keeps the samples the detector has now and checks the restored pattern against them. It is recorded as a further change."
      loading={revisions.isPending}
      revisions={revisions.data?.revisions ?? []}
      error={restore.error ? message(restore.error) : revisions.error ? message(revisions.error) : null}
      canRestore={canRestore}
      restoring={restore.isPending}
      onRestore={(revision) => restore.mutate({ path: { id: detector.id, revision } })}
      empty="Nothing has changed about this detector since the history began."
    />
  );
}
