import { describe, expect, it } from "vitest";
import { followColorScheme } from "./color-mode";

/** A stand-in for the system preference that can be changed from the test. */
function preference(dark: boolean) {
  const listeners = new Set<() => void>();
  return {
    matches: dark,
    addEventListener: (_: string, l: () => void) => listeners.add(l),
    removeEventListener: (_: string, l: () => void) => listeners.delete(l),
    change(to: boolean) {
      this.matches = to;
      listeners.forEach((l) => l());
    },
    get listening() {
      return listeners.size;
    },
  };
}

describe("followColorScheme", () => {
  it("starts in the scheme the system prefers", () => {
    const root = { dataset: {} as DOMStringMap };
    followColorScheme(root, preference(true));
    expect(root.dataset.mode).toBe("dark");
    followColorScheme(root, preference(false));
    expect(root.dataset.mode).toBe("light");
  });

  it("follows a change of preference until it is stopped", () => {
    const root = { dataset: {} as DOMStringMap };
    const pref = preference(false);
    const stop = followColorScheme(root, pref);
    pref.change(true);
    expect(root.dataset.mode).toBe("dark");
    stop();
    expect(pref.listening).toBe(0);
    pref.change(false);
    expect(root.dataset.mode).toBe("dark");
  });
});
