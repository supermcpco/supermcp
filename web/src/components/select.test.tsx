import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { LabelledSelect, type SelectOption } from "./select";

// Rendered to markup in Node: the list of options is portalled and only
// drawn when the select opens, in a browser, where controls.spec.ts opens
// it by keyboard. Here: the label names the button, and every option's
// words are the ones shown once it is the value.

const options: SelectOption[] = [
  { value: "", label: "Any time" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
];

function render(props: Partial<Parameters<typeof LabelledSelect>[0]> = {}) {
  return renderToStaticMarkup(
    <LabelledSelect label="Period" value="7d" onChange={() => {}} options={options} {...props} />,
  );
}

function attr(html: string, element: string, name: string) {
  const tag = new RegExp(`<${element}\\b[^>]*>`).exec(html)?.[0] ?? "";
  return new RegExp(`\\b${name}="([^"]*)"`).exec(tag)?.[1];
}

describe("LabelledSelect", () => {
  it("renders a combobox named by its visible label", () => {
    const html = render();
    expect(attr(html, "button", "role")).toBe("combobox");
    const labelId = attr(html, "label", "id");
    expect(labelId).toBeTruthy();
    expect(attr(html, "button", "aria-labelledby")).toBe(labelId);
    // The label points at the button too, so a click on the words opens it.
    expect(attr(html, "label", "for")).toBe(attr(html, "button", "id"));
    expect(html).toMatch(/<label[^>]*><span[^>]*>Period<\/span><\/label>/);
    expect(attr(html, "label", "class")).toBeUndefined();
  });

  it.each(options)("shows the words of the option %# once it is the value", (o) => {
    const html = render({ value: o.value });
    const button = /<button\b[^>]*>(.*?)<\/button>/.exec(html)?.[1] ?? "";
    expect(button).toContain(`>${o.label}</span>`);
  });

  it('treats "" as a choice, not as nothing chosen', () => {
    const html = render({ value: "" });
    const button = /<button\b[^>]*>(.*?)<\/button>/.exec(html)?.[1] ?? "";
    expect(button).toContain(">Any time</span>");
    // Base UI marks an empty select as showing a placeholder, and Kumo greys it.
    expect(button).not.toContain("data-placeholder");
  });

  it("keeps the value in the form as the string it was given", () => {
    expect(attr(render({ value: "24h" }), "input", "value")).toBe("24h");
  });

  it("is described by its hint and by whatever else is named", () => {
    const html = render({ hint: "Counted in UTC", describedBy: "elsewhere" });
    const hintId = /<span[^>]*id="([^"]*)"[^>]*>Counted in UTC<\/span>/.exec(html)?.[1];
    expect(hintId).toBeTruthy();
    expect(attr(html, "button", "aria-describedby")).toBe(`${hintId} elsewhere`);
  });

  it("is described by nothing when there is no hint", () => {
    expect(attr(render(), "button", "aria-describedby")).toBeUndefined();
  });

  it("keeps a hidden label for screen readers", () => {
    const html = render({ hideLabel: true });
    expect(attr(html, "label", "class")).toBe("sr-only");
    expect(attr(html, "button", "aria-labelledby")).toBe(attr(html, "label", "id"));
  });

  it("disables the button", () => {
    expect(render({ disabled: true })).toMatch(/<button\b[^>]*\bdisabled=""/);
  });

  it("sizes the button as Kumo's inputs and buttons are sized", () => {
    expect(attr(render(), "button", "class")).toContain("h-9");
    expect(attr(render({ size: "sm" }), "button", "class")).toContain("h-6.5");
  });
});
