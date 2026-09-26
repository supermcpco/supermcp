import { createKumoToastManager } from "@cloudflare/kumo";

/**
 * The one queue every confirmation goes through. It lives outside the
 * React tree so a mutation's onSuccess can say what happened even when
 * the screen that started it has already navigated away.
 */
export const toasts = createKumoToastManager();

export type ToastKind = "success" | "error" | "info";

/**
 * Says in one sentence what just happened ("Deutsche Bundesbank Statistics
 * installed"). Never pass a secret: a toast is read aloud by screen
 * readers and stays on screen for anyone looking over a shoulder.
 */
export function toast(message: string, { kind = "success" }: { kind?: ToastKind } = {}) {
  toasts.add({ title: message, variant: kind, priority: kind === "error" ? "high" : "low" });
}
