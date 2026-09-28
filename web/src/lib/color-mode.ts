import { useSyncExternalStore } from "react";


/** What the operating system answers when asked for its light or dark preference. */
export const darkSchemeQuery = "(prefers-color-scheme: dark)";

type Preference = Pick<MediaQueryList, "matches" | "addEventListener" | "removeEventListener">;

/**
 * Keeps the console in the colour scheme the person chose for their system,
 * and follows them when they change it. Kumo draws its dark theme under
 * `data-mode="dark"` and otherwise pins `color-scheme: light` on the root,
 * so the `color-scheme` meta tag alone is not enough. Returns what stops
 * the following.
 */
export function followColorScheme(
  root: { dataset: DOMStringMap } = document.documentElement,
  preference: Preference = window.matchMedia(darkSchemeQuery),
): () => void {
  const apply = () => {
    root.dataset.mode = preference.matches ? "dark" : "light";
  };
  apply();
  preference.addEventListener("change", apply);
  return () => preference.removeEventListener("change", apply);
}

function subscribe(onChange: () => void): () => void {
  const preference = window.matchMedia(darkSchemeQuery);
  preference.addEventListener("change", onChange);
  return () => preference.removeEventListener("change", onChange);
}

/**
 * The scheme the console is drawn in, for what cannot read Kumo's CSS
 * variables by itself (a chart's canvas) and has to be drawn again when
 * it changes.
 */
export function useColorScheme(): "dark" | "light" {
  return useSyncExternalStore(subscribe, () => (window.matchMedia(darkSchemeQuery).matches ? "dark" : "light"));
}
