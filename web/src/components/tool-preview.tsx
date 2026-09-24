import { Text, Textarea } from "@cloudflare/kumo";
import type { ToolDraftResult } from "../api";
import { message } from "../lib/errors";
import { readArguments } from "../lib/tool-api";

/**
 * What the draft would send if a model called it with these arguments.
 * Nothing leaves the instance: the request is rendered and shown, never made.
 */
export function ToolPreview({
  canPreview,
  unsupported,
  args,
  onArgs,
  invalidDraft,
  pending,
  error,
  result,
}: {
  canPreview: boolean;
  /** SOAP and MCP tools cannot be rendered without calling them. */
  unsupported?: boolean;
  args: string;
  onArgs: (text: string) => void;
  invalidDraft: boolean;
  pending: boolean;
  error: unknown;
  result?: ToolDraftResult;
}) {
  const argsState = readArguments(args);
  const preview = result?.preview;

  return (
    <section
      aria-labelledby="tool-preview-heading"
      className="grid content-start gap-3 rounded-md bg-kumo-base px-4 py-3 ring ring-kumo-line"
    >
      <Text as="h3" bold id="tool-preview-heading">
        What it would send
      </Text>

      {unsupported ? (
        <Text variant="secondary">
          The request a SOAP or MCP tool makes cannot be shown without making it. Issues with the draft still appear
          beside it.
        </Text>
      ) : !canPreview ? (
        <Text variant="secondary">
          Seeing the request a draft would make needs permission to call tools. Save the tool to try it.
        </Text>
      ) : (
        <>
          <label className="grid gap-1.5">
            <Text as="span">Example arguments</Text>
            <Textarea
              rows={3}
              className="font-mono text-[0.9em]"
              value={args}
              onChange={(e) => onArgs(e.target.value)}
              placeholder='{"id": "42"}'
              aria-invalid={!argsState.ok}
              aria-describedby={!argsState.ok ? "tool-preview-args-error" : undefined}
            />
            {!argsState.ok && (
              <Text as="span" variant="secondary" id="tool-preview-args-error">
                {argsState.error}
              </Text>
            )}
          </label>

          <Text variant="secondary">
            Credentials and secret values are redacted. Nothing is sent to the upstream API.
          </Text>

          <div aria-live="polite" className="grid gap-3">
            {invalidDraft && <Text variant="secondary">The draft is not valid JSON yet, so there is nothing to show.</Text>}
            {pending && !result && <Text variant="secondary">Working it out…</Text>}
            {error != null && (
              <div role="alert">
                <Text>{message(error)}</Text>
              </div>
            )}
            {result?.previewError && (
              <div role="alert" className="rounded-md bg-kumo-tint px-3 py-2 ring ring-kumo-line">
                <Text>{result.previewError}</Text>
              </div>
            )}
            {preview && (
              <dl className="grid gap-2">
                {preview.method || preview.url ? (
                  <Row term="Request">
                    <code className="font-mono text-[0.9em] break-all">
                      {[preview.method, preview.url].filter(Boolean).join(" ")}
                    </code>
                  </Row>
                ) : null}
                {preview.headers && Object.keys(preview.headers).length > 0 && (
                  <Row term="Headers">
                    <pre className="font-mono text-[0.85em] whitespace-pre-wrap break-all">
                      {Object.entries(preview.headers)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join("\n")}
                    </pre>
                  </Row>
                )}
                {preview.body && (
                  <Row term="Body">
                    <pre className="font-mono text-[0.85em] whitespace-pre-wrap break-all">{preview.body}</pre>
                  </Row>
                )}
                {preview.sql && (
                  <Row term="Statement">
                    <pre className="font-mono text-[0.85em] whitespace-pre-wrap break-all">{preview.sql}</pre>
                  </Row>
                )}
                {preview.args && preview.args.length > 0 && (
                  <Row term="Bound values">
                    <pre className="font-mono text-[0.85em] whitespace-pre-wrap break-all">
                      {JSON.stringify(preview.args, null, 2)}
                    </pre>
                  </Row>
                )}
                {preview.note && (
                  <Row term="Note">
                    <Text as="span" variant="secondary">
                      {preview.note}
                    </Text>
                  </Row>
                )}
              </dl>
            )}
          </div>
        </>
      )}
    </section>
  );
}

function Row({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-0.5">
      <dt>
        <Text as="span" variant="secondary">
          {term}
        </Text>
      </dt>
      <dd>{children}</dd>
    </div>
  );
}
