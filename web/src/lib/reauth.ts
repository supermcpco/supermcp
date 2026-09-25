/**
 * Asking a person to prove who they are again, from anywhere.
 *
 * The server refuses the operations that hand out credentials or change
 * who may do what when the session signed in too long ago: a 403 whose
 * errors[].value is `reauth_required`. Every such mutation goes through
 * the generated client, so this is handled once, in the client's
 * interceptors, rather than in each screen: the refused request waits
 * while a dialog asks for the password, and is sent once more if the
 * person confirms. Only once: a second refusal reaches the screen as
 * the error it is.
 */

/** The code the server puts in errors[].value. */
export const reauthCode = "reauth_required";

/** Whether a problem body is the refusal of a stale session. */
export function isReauthRequired(status: number, body: unknown): boolean {
  if (status !== 403 || typeof body !== "object" || body === null) return false;
  const errors = (body as { errors?: { value?: unknown }[] | null }).errors ?? [];
  return errors.some((e) => e?.value === reauthCode);
}

/**
 * The one question in flight. Several requests refused at the same moment
 * share it, so the person is asked once.
 */
export interface ReauthGate {
  /** Opens the question, or joins the one already open. True when confirmed. */
  ask(): Promise<boolean>;
  /** Closes the question with its answer. */
  answer(confirmed: boolean): void;
  /** Whether a question is open; for useSyncExternalStore. */
  open(): boolean;
  subscribe(listener: () => void): () => void;
}

export function createReauthGate(): ReauthGate {
  let pending: { promise: Promise<boolean>; resolve: (ok: boolean) => void } | null = null;
  const listeners = new Set<() => void>();
  const notify = () => listeners.forEach((l) => l());
  return {
    ask() {
      if (!pending) {
        let resolve: (ok: boolean) => void = () => {};
        const promise = new Promise<boolean>((r) => {
          resolve = r;
        });
        pending = { promise, resolve };
        notify();
      }
      return pending.promise;
    },
    answer(confirmed) {
      const p = pending;
      pending = null;
      p?.resolve(confirmed);
      notify();
    },
    open: () => pending !== null,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

type Fetch = (request: Request) => Promise<Response>;

/**
 * The two interceptors that put the gate between a refused request and
 * the screen that sent it. A request's body can be read once, so a copy
 * of every write is kept until its answer comes back, in case it has to
 * be sent again. Reads are never refused this way and are left alone.
 */
export function reauthInterceptors(gate: ReauthGate, send: Fetch) {
  const copies = new WeakMap<Request, Request>();
  return {
    request(request: Request): Request {
      if (request.method !== "GET" && request.method !== "HEAD") copies.set(request, request.clone());
      return request;
    },
    async response(response: Response, request: Request): Promise<Response> {
      const copy = copies.get(request);
      copies.delete(request);
      if (!copy || response.status !== 403) return response;
      let body: unknown;
      try {
        body = await response.clone().json();
      } catch {
        return response;
      }
      if (!isReauthRequired(response.status, body)) return response;
      if (!(await gate.ask())) return response;
      return send(copy);
    },
  };
}
