// How far a workspace is from its first tool call, worked out from what
// the server already reports. Nothing here is stored: a step is done
// because the thing it asks for exists, so the checklist cannot drift
// from the workspace it describes.

export type StepId = "connector" | "server" | "key" | "client";

export interface SetupStep {
  id: StepId;
  title: string;
  /** What doing it means, in one sentence. */
  description: string;
  /** The screen it is done on. */
  to: "/catalog" | "/servers" | "/api-keys";
  /** Where the link to that screen says it goes. */
  action: string;
  /** undefined while the answer is not in, or could not be had. */
  done: boolean | undefined;
}

/**
 * One read the checklist depends on: `readable` is false when the viewer
 * may not make it, which leaves its step out rather than showing a step
 * that can never tick; `data` is undefined while it loads or after it
 * failed.
 */
export interface Read<T> {
  readable: boolean;
  data: T | undefined;
}

export interface KeyLike {
  revokedAt?: string;
  expiresAt?: string;
  lastUsedAt?: string;
}

export interface SetupInput {
  connectors: Read<readonly unknown[]>;
  servers: Read<readonly unknown[]>;
  keys: Read<readonly KeyLike[]>;
  calls: Read<readonly unknown[]>;
}

/** Whether a key still opens anything: not revoked and not past its expiry. */
export function isLive(key: KeyLike, now: Date = new Date()): boolean {
  if (key.revokedAt) return false;
  return !key.expiresAt || new Date(key.expiresAt).getTime() > now.getTime();
}

function nonEmpty<T>(r: Read<readonly T[]>): boolean | undefined {
  return r.data === undefined ? undefined : r.data.length > 0;
}

/**
 * The steps, in order, with the ones the viewer cannot see left out.
 *
 * A client has connected once a tool call is on record or a key reports
 * a last use: either is the server saying a client reached it. Only when
 * neither can be read is there nothing to go on, and the step is left
 * out rather than guessed.
 */
export function setupSteps(input: SetupInput, now: Date = new Date()): SetupStep[] {
  const steps: SetupStep[] = [];
  if (input.connectors.readable) {
    steps.push({
      id: "connector",
      title: "Install a connector",
      description: "Pick an adapter from the catalog, or import your own API, so there are tools to offer.",
      to: "/catalog",
      action: "Open the catalog",
      done: nonEmpty(input.connectors),
    });
  }
  if (input.servers.readable) {
    steps.push({
      id: "server",
      title: "Create an MCP server",
      description: "A server is the one endpoint an AI client is given, offering the connectors you attach.",
      to: "/servers",
      action: "Go to MCP servers",
      done: nonEmpty(input.servers),
    });
  }
  if (input.keys.readable) {
    steps.push({
      id: "key",
      title: "Create an API key",
      description: "A key is how a client proves it may use your servers.",
      to: "/api-keys",
      action: "Go to API keys",
      done: input.keys.data === undefined ? undefined : input.keys.data.some((k) => isLive(k, now)),
    });
  }
  if (input.calls.readable || input.keys.readable) {
    const called = input.calls.readable ? nonEmpty(input.calls) : false;
    const used = !input.keys.readable
      ? false
      : input.keys.data === undefined
        ? undefined
        : input.keys.data.some((k) => !!k.lastUsedAt);
    steps.push({
      id: "client",
      title: "Connect a client",
      description: "Paste the server's config into Claude Desktop, Cursor or any MCP client, with your key.",
      to: "/servers",
      action: "See how to connect",
      done: called === true || used === true ? true : called === undefined || used === undefined ? undefined : false,
    });
  }
  return steps;
}

/** Set up: every step the viewer can see is done. */
export function isSetUp(steps: readonly SetupStep[]): boolean {
  return steps.every((s) => s.done === true);
}

/** Whether any step is still waiting on its read. */
export function isUndecided(steps: readonly SetupStep[]): boolean {
  return steps.some((s) => s.done === undefined);
}
