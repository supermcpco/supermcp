import { useId, useState } from "react";
import { Button, Text } from "@cloudflare/kumo";
import { clientSnippets, endpointURL, type ClientId } from "../lib/connect-client";

const selectClass = "rounded-md border border-kumo-line bg-kumo-base px-3 py-2";

/**
 * Copies `text` and says so. `what` finishes the button's name for
 * somebody who cannot see what it sits next to: "Copy endpoint".
 */
export function CopyButton({ text, what }: { text: string; what: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  return (
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
        <input
          id={id}
          readOnly
          value={url}
          onFocus={(e) => e.currentTarget.select()}
          className="min-w-0 flex-1 rounded-md bg-kumo-tint px-2 py-1 font-mono text-[0.9em]"
        />
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
  const [client, setClient] = useState<ClientId>("claude-desktop");
  const clientId = useId();
  const url = endpointURL(window.location.origin, server.id);
  const snippets = clientSnippets({ url, name: server.slug || server.name, secret });
  const shown = snippets.find((s) => s.id === client) ?? snippets[0];

  return (
    <div className="grid gap-3">
      {showEndpoint && <Endpoint serverId={server.id} of={server.name} />}
      {/* Labelled by id, not by wrapping: a wrapping label would fold the options into the name. */}
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={clientId}>
          <Text as="span">Client</Text>
        </label>
        <select
          id={clientId}
          className={selectClass}
          value={client}
          onChange={(e) => setClient(e.currentTarget.value as ClientId)}
        >
          {snippets.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
            </option>
          ))}
        </select>
      </div>
      <section aria-label={`${shown.label} config`} className="grid gap-1.5">
        <Text variant="secondary">
          Paste into <span className="font-mono text-[0.9em]">{shown.where}</span>
          {shown.id === "curl" ? "; the answer names the server and its capabilities." : "."}
        </Text>
        {shown.note && <Text variant="secondary">{shown.note}</Text>}
        {!secret && (
          <Text variant="secondary">
            Replace <span className="font-mono text-[0.9em]">&lt;your API key&gt;</span> with a key from API keys.
          </Text>
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
