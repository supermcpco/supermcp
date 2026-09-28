import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { TooltipText, WithTooltip } from "./tooltip";

// Rendered to markup in Node: the popup itself is portalled and only
// appears in a browser, where the Playwright suite hovers and focuses it.
// Here: the words carry the role, and the control arrives as it was given.

describe("TooltipText", () => {
  it("renders the text inside an element whose role is tooltip", () => {
    expect(renderToStaticMarkup(<TooltipText id="t1">Copy the endpoint to the clipboard</TooltipText>)).toBe(
      '<span role="tooltip" id="t1">Copy the endpoint to the clipboard</span>',
    );
  });
});

describe("WithTooltip", () => {
  it("forwards the trigger's own props and content", () => {
    const html = renderToStaticMarkup(
      <WithTooltip tip="Copy the secret to the clipboard">
        <button type="submit" aria-label="Copy secret" data-kind="copy" className="px-2" disabled>
          Copy
        </button>
      </WithTooltip>,
    );
    expect(html).toMatch(/^<button /);
    expect(html).toContain('type="submit"');
    expect(html).toContain('aria-label="Copy secret"');
    expect(html).toContain('data-kind="copy"');
    expect(html).toContain("px-2");
    expect(html).toContain("disabled");
    expect(html).toContain(">Copy</button>");
  });

  it("is not described by a tip that is not showing", () => {
    const html = renderToStaticMarkup(
      <WithTooltip tip="Copy the secret to the clipboard">
        <button type="button">Copy</button>
      </WithTooltip>,
    );
    expect(html).not.toContain("aria-describedby");
  });

  it("keeps a description the trigger brought while the tip is not showing", () => {
    const html = renderToStaticMarkup(
      <WithTooltip tip="Copy the secret to the clipboard">
        <button type="button" aria-describedby="hint">
          Copy
        </button>
      </WithTooltip>,
    );
    expect(html).toContain('aria-describedby="hint"');
  });

  it("is described by a showing tip that says more than its name", () => {
    const html = renderToStaticMarkup(
      <WithTooltip tip="Copy the secret to the clipboard" defaultOpen>
        <button type="button">Copy</button>
      </WithTooltip>,
    );
    expect(html).toMatch(/aria-describedby="[^"]+"/);
  });

  it("is not described by a showing tip that repeats its name", () => {
    const labelled = renderToStaticMarkup(
      <WithTooltip tip="About approvals" defaultOpen>
        <button type="button" aria-label="About approvals" />
      </WithTooltip>,
    );
    expect(labelled).not.toContain("aria-describedby");
    const repeated = renderToStaticMarkup(
      <WithTooltip tip="About approvals" repeats defaultOpen>
        <button type="button">?</button>
      </WithTooltip>,
    );
    expect(repeated).not.toContain("aria-describedby");
  });
});
