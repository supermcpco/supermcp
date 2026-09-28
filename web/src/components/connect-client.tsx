import { Fragment, useId, useState } from "react";
import { Button, Select, Text } from "@cloudflare/kumo";
import {
  clientGroups,
  clientSnippets,
  endpointURL,
  isClientId,
  readClient,
  storeClient,
  type ClientId,
} from "../lib/connect-client";
import { WithTooltip } from "./tooltip";

/** A line with `backticked` paths and commands set in code type. */
function WithCode({ text }: { text: string }) {
  return text.split("`").map((part, i) =>
    i % 2 === 1 ? (
      <span key={i} className="font-mono text-[0.9em]">
        {part}
      </span>
    ) : (
      <Fragment key={i}>{part}</Fragment>
    ),
  );
}

/**
 * Copies `text` and says so. `what` finishes the button's name for
 * somebody who cannot see what it sits next to: "Copy endpoint". The
 * tooltip says the same in a sentence for whoever sees only "Copy".
 */
export function CopyButton({ text, what }: { text: string; what: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  return (
    <WithTooltip tip={`Copy the ${what} to the clipboard`}>
      <Button
        onClick={() => {
          navigator.clipboard.writeText(text).then(
            () => {
              setState("copied");
              window.setTimeout(() => setState("idle"), 1500);
            },
            () => setState("failed"),
          );
        }}
      >
        {state === "copied" ? "Copied" : state === "failed" ? "Copy failed, select the text instead" : "Copy"}
        <span className="sr-only"> {what}</span>
      </Button>
    </WithTooltip>
  );
}

/**
 * The URL to give an AI client, labelled, with the copy button next to it.
 * `of` names the server for somebody who cannot see which card it is in.
 */
export function Endpoint({ serverId, of }: { serverId: string; of?: string }) {
  const url = endpointURL(window.location.origin, serverId);
  const id = useId();
  const suffix = of ? ` of ${of}` : "";
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id}>
        <Text as="span" variant="secondary">
          Endpoint
        </Text>
        {suffix && <span className="sr-only">{suffix}</span>}
      </label>
      <div className="flex items-center gap-2">
        {/* A URL longer than the field shows whole in a tooltip. */}
        <WithTooltip tip={url} onlyWhenTruncated className="cursor-text">
          <input
            id={id}
            readOnly
            value={url}
            onFocus={(e) => e.currentTarget.select()}
            className="min-w-0 flex-1 rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]"
          />
        </WithTooltip>
        <CopyButton text={url} what={`endpoint${suffix}`} />
      </div>
    </div>
  );
}

export interface ConnectTarget {
  id: string;
  slug: string;
  name: string;
}

/**
 * The config each client needs to reach `server`. With `secret` the
 * snippets carry it, ready to paste; without it they carry a placeholder,
 * because a secret is only in hand at the moment it was issued.
 */
export function ConnectClient({
  server,
  secret,
  showEndpoint = false,
}: {
  server: ConnectTarget;
  secret?: string;
  showEndpoint?: boolean;
}) {
  // The last client picked, on this browser; the key dialog and the
  // server cards share it, so a person picks their client once.
  const [client, setClient] = useState<ClientId>(() => readClient());
  const url = endpointURL(window.location.origin, server.id);
  const snippets = clientSnippets({ url, name: server.slug || server.name, secret });
  const shown = snippets.find((s) => s.id === client) ?? snippets[0];

  return (
    <div className="grid gap-3">
      {showEndpoint && <Endpoint serverId={server.id} of={server.name} />}
      <div className="w-fit min-w-64">
        <Select<ClientId>
          label="Client"
          value={shown.id}
          items={snippets.map((s) => ({ value: s.id, label: s.label }))}
          onValueChange={(v) => {
            if (!isClientId(v)) return;
            setClient(v);
            storeClient(v);
          }}
        >
          {clientGroups.map((group, i) => (
            <Fragment key={group}>
              {i > 0 && <Select.Separator />}
              <Select.Group>
                <Select.GroupLabel>{group}</Select.GroupLabel>
                {snippets
                  .filter((s) => s.group === group)
                  .map((s) => (
                    <Select.Option key={s.id} value={s.id}>
                      {s.label}
                    </Select.Option>
                  ))}
              </Select.Group>
            </Fragment>
          ))}
        </Select>
      </div>
      <section aria-label={`${shown.label} config`} className="grid gap-1.5">
        <Text variant="secondary">
          <WithCode text={shown.where} />
        </Text>
        {shown.note && <Text variant="secondary">{shown.note}</Text>}
        {!secret && !shown.keyFrom && (
          <Text variant="secondary">
            Replace <span className="font-mono text-[0.9em]">&lt;your API key&gt;</span> with a key from API keys.
          </Text>
        )}
        {shown.docs ? (
          <Text variant="secondary">
            {shown.unchecked ? "Check this against the vendor's docs: the " : "The format is from the "}
            <a href={shown.docs} className="underline" target="_blank" rel="noreferrer">
              {shown.label} documentation
            </a>
            .
          </Text>
        ) : (
          shown.unchecked && <Text variant="secondary">Check this against the vendor&apos;s docs.</Text>
        )}
        {/* Wrapped, not scrolled: a scrolling block would need its own tab stop. */}
        <pre className="rounded-md bg-kumo-tint px-3 py-2 font-mono text-[0.85em] break-all whitespace-pre-wrap">
          {shown.text}
        </pre>
        <div>
          <CopyButton text={shown.text} what={`${shown.label} config`} />
        </div>
      </section>
    </div>
  );
}
