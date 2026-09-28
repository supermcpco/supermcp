import { useId, useState } from "react";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Checkbox, Text, Textarea } from "@cloudflare/kumo";
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
import { toast } from "./shell/toast";
import { ConfirmDialog } from "./confirm-dialog";
import { FormDialog } from "./form-dialog";
import { Help, HeadingWithHelp } from "./help";
import { LabelledInput } from "./labelled-input";

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
  // The detector being edited, kept while its dialog closes. Each opening
  // counts, so the dialog starts from the detector as it is now.
  const [edited, setEdited] = useState<CustomDetectorDto | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [editRound, setEditRound] = useState(0);
  const [history, setHistory] = useState<string | null>(null);

  // A delete can take a detector out of rules, so both lists are read again.
  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: dlpDetectorsQueryKey() });
    await qc.invalidateQueries({ queryKey: dlpPoliciesListQueryKey() });
  };
  const list = detectors.data?.custom ?? [];

  return (
    <div className="grid gap-6">
      {detectors.error && (
        <div role="alert">
          <Text>{message(detectors.error)}</Text>
        </div>
      )}

      <section className="grid gap-2">
        <HeadingWithHelp
          heading={
            <Text as="h3" variant="heading">
              Detectors
            </Text>
          }
          help={
            <Help about="detectors">
              <Text>
                A rule runs one of this workspace&rsquo;s detectors when it names it, beside the built-in detectors it
                names.
              </Text>
              <Text>
                Each pattern is tried against its samples whenever it is saved. Use made-up samples: they are stored as
                written.
              </Text>
            </Help>
          }
        />
        <Text variant="secondary">Patterns for identifiers only this workspace knows, such as contract ids.</Text>
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
                  {canManage && (
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setEdited(d);
                        setEditRound((n) => n + 1);
                        setEditOpen(true);
                      }}
                      aria-label={`Edit ${d.name}`}
                    >
                      Edit
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
              {history === d.id && <DetectorHistory detector={d} canRestore={canRestore} onRestored={refresh} />}
            </li>
          ))}
        </ul>
      </section>

      {canManage && (
        <section className="grid gap-3">
          <Text as="h3" variant="heading">
            Add a detector
          </Text>
          <AddDetector onDone={refresh} />
        </section>
      )}

      {canManage && edited && (
        <EditDetector
          key={editRound}
          open={editOpen}
          onOpenChange={setEditOpen}
          listed={edited}
          onSaved={async () => {
            setEditOpen(false);
            await refresh();
            await qc.invalidateQueries({ queryKey: dlpDetectorGetQueryKey({ path: { id: edited.id } }) });
            await qc.invalidateQueries({ queryKey: dlpDetectorsRevisionsListQueryKey({ path: { id: edited.id } }) });
          }}
        />
      )}
    </div>
  );
}

/**
 * The editor for one stored detector, in a dialog opened from its row.
 * The list carries no samples, so the detector is read on its own first;
 * the fields fill with what came back, and are filled afresh whenever a
 * newer version is read (after "Reload the detector").
 */
function EditDetector({
  listed,
  open,
  onOpenChange,
  onSaved,
}: {
  listed: CustomDetectorDto;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved: () => Promise<void>;
}) {
  const qc = useQueryClient();
  const key = { path: { id: listed.id } };
  const one = useQuery({ ...dlpDetectorGetOptions(key), retry: false });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [readVersion, setReadVersion] = useState<number | null>(null);
  if (one.data && one.data.version !== readVersion) {
    setReadVersion(one.data.version);
    setDraft(draftOf(one.data));
  }
  const update = useMutation({
    ...dlpDetectorUpdateMutation(),
    onSuccess: async () => {
      toast(`Detector ${listed.name} saved`);
      await onSaved();
    },
  });
  const reload = async () => {
    update.reset();
    await qc.invalidateQueries({ queryKey: dlpDetectorGetQueryKey(key) });
  };

  return (
    <FormDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Edit ${listed.name}`}
      submitLabel="Save the detector"
      pending={update.isPending}
      canSubmit={draft !== null && readVersion !== null && draft.pattern.length >= 3}
      error={update.error ? message(update.error) : one.error ? message(one.error) : null}
      errorAction={
        update.error && isStale(update.error) ? (
          <Button variant="secondary" onClick={reload}>
            Reload the detector
          </Button>
        ) : undefined
      }
      size="xl"
      onSubmit={() => {
        if (!draft || readVersion === null) return;
        update.mutate({ path: { id: listed.id }, body: { ...bodyOf(draft), expectedVersion: readVersion } });
      }}
    >
      {draft && one.data ? <DetectorFields draft={draft} onChange={setDraft} detector={one.data} /> : !one.error && <Loading />}
    </FormDialog>
  );
}

/**
 * Deleting a detector a rule uses is refused, and the refusal names the
 * rules. Confirming deletes it anyway and takes it out of them; a rule
 * left with no detector is switched off rather than falling back to every
 * built-in.
 */
function DeleteDetector({ detector, onDeleted }: { detector: CustomDetectorDto; onDeleted: () => Promise<void> }) {
  const [asking, setAsking] = useState(false);
  const remove = useMutation({
    ...dlpDetectorDeleteMutation(),
    onSuccess: async () => {
      setAsking(false);
      toast(`Detector ${detector.name} deleted`);
      await onDeleted();
    },
    // A refusal is said beside the detector, where the way past it (taking
    // it out of the rules that use it) is offered.
    onError: () => setAsking(false),
  });
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
          variant="secondary-destructive"
          onClick={() => {
            remove.reset();
            setAsking(true);
          }}
          disabled={remove.isPending}
          aria-label={`Delete ${detector.name}`}
        >
          Delete
        </Button>
      </div>
      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        resourceType="Detector"
        resourceName={detector.name}
        confirmLabel="Delete detector"
        pending={remove.isPending}
        onConfirm={() => remove.mutate({ path: { id: detector.id } })}
      />
    </div>
  );
}

/** What the detector form holds while it is being filled in. */
interface Draft {
  name: string;
  description: string;
  pattern: string;
  anyCase: boolean;
  mustMatchText: string;
  mustNotMatchText: string;
  enabled: boolean;
}

function draftOf(detector?: CustomDetectorDto): Draft {
  return {
    name: detector?.name ?? "",
    description: detector?.description ?? "",
    pattern: detector?.pattern ?? "",
    anyCase: detector?.flags === "i",
    mustMatchText: formatSamples(detector?.mustMatch),
    mustNotMatchText: formatSamples(detector?.mustNotMatch),
    enabled: detector?.enabled ?? true,
  };
}

/** What a save sends, the name aside: it is given once, when the detector is added. */
function bodyOf(d: Draft) {
  return {
    description: d.description,
    pattern: d.pattern,
    flags: d.anyCase ? ("i" as const) : ("" as const),
    mustMatch: parseSamples(d.mustMatchText),
    mustNotMatch: parseSamples(d.mustNotMatchText),
    enabled: d.enabled,
  };
}

/** Adds a detector, from the form under the list. */
function AddDetector({ onDone }: { onDone: () => Promise<void> }) {
  const [draft, setDraft] = useState<Draft>(() => draftOf());
  const create = useMutation({
    ...dlpDetectorCreateMutation(),
    onSuccess: async (_, vars) => {
      toast(`Detector ${vars.body.name} added`);
      setDraft(draftOf());
      await onDone();
    },
  });

  return (
    <form
      className="grid gap-3"
      aria-label="Add a detector"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate({ body: { ...bodyOf(draft), name: draft.name } });
      }}
    >
      {create.error && (
        <div role="alert">
          <Text>{message(create.error)}</Text>
        </div>
      )}
      <DetectorFields draft={draft} onChange={setDraft} />
      <div className="flex flex-wrap gap-2">
        <Button
          type="submit"
          variant="primary"
          disabled={create.isPending || draft.pattern.length < 3 || draft.name.trim() === ""}
        >
          Add the detector
        </Button>
      </div>
    </form>
  );
}

/**
 * The fields of a detector, for adding one or changing one. The pattern is
 * tried against the samples as it is typed, by the same rules a save
 * applies, and the outcome is shown per sample; only offsets come back
 * from the server.
 */
function DetectorFields({
  draft,
  onChange,
  detector,
}: {
  draft: Draft;
  onChange: (next: Draft) => void;
  /** The stored detector being changed; absent for a new one. */
  detector?: CustomDetectorDto;
}) {
  const set = (change: Partial<Draft>) => onChange({ ...draft, ...change });
  const flags = draft.anyCase ? ("i" as const) : ("" as const);
  const mustMatch = parseSamples(draft.mustMatchText);
  const mustNotMatch = parseSamples(draft.mustNotMatchText);
  const tried = useTryPattern(draft.pattern, flags, mustMatch, mustNotMatch);
  const label = detector ? detector.name : "the new detector";
  // The add form and an edit dialog can be on the page at once, so the
  // help text each points at needs an id of its own.
  const ids = useId();

  return (
    <>
      {detector ? (
        <Text variant="secondary">
          Rules name this detector <code className={codeClass}>{detector.detector}</code>. Its name cannot change.
        </Text>
      ) : (
        <div className="grid gap-1">
          <LabelledInput
            labelClassName="grid gap-1"
            label="Detector name"
            value={draft.name}
            onChange={(e) => set({ name: e.currentTarget.value })}
            required
            maxLength={63}
            aria-describedby={`${ids}-name-help`}
          />
          <Text as="span" variant="secondary" id={`${ids}-name-help`}>
            Lower-case letters, digits, - and _. Rules name it custom:{draft.name || "<name>"}, and it cannot change
            later.
          </Text>
        </div>
      )}
      <LabelledInput labelClassName="grid gap-1" label="Description" value={draft.description} onChange={(e) => set({ description: e.currentTarget.value })} maxLength={500} />
      <div className="grid gap-1">
        <LabelledInput
          labelClassName="grid gap-1"
          label="Pattern"
          value={draft.pattern}
          onChange={(e) => set({ pattern: e.currentTarget.value })}
          required
          maxLength={512}
          className="font-mono"
          spellCheck={false}
          aria-describedby={`${ids}-pattern-help`}
        />
        <Text as="span" variant="secondary" id={`${ids}-pattern-help`}>
          An RE2 regular expression of 3 to 512 bytes that cannot match an empty string, such as {"\\bCN-\\d{6}\\b"}.
          Lookarounds and backreferences are not available, and very large repetition counts are refused because the
          pattern runs on every tool call.
        </Text>
      </div>
      <Checkbox label="Ignore upper and lower case" checked={draft.anyCase} onCheckedChange={(anyCase) => set({ anyCase })} />
      <div className="grid gap-3 md:grid-cols-2">
        <label className="grid gap-1">
          <Text as="span">Samples it must match, one per line</Text>
          <Textarea
            rows={4}
            value={draft.mustMatchText}
            onChange={(e) => set({ mustMatchText: e.currentTarget.value })}
            className="font-mono"
            spellCheck={false}
          />
        </label>
        <label className="grid gap-1">
          <Text as="span">Samples it must not match, one per line</Text>
          <Textarea
            rows={4}
            value={draft.mustNotMatchText}
            onChange={(e) => set({ mustNotMatchText: e.currentTarget.value })}
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
      <Checkbox label="The detector is on" checked={draft.enabled} onCheckedChange={(enabled) => set({ enabled })} />
    </>
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
    onSuccess: async (_, vars) => {
      toast(`Detector ${detector.name} restored to version ${vars.path.revision}`);
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
