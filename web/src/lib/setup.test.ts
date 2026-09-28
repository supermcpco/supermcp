import { describe, expect, it } from "vitest";
import { isLive, isSetUp, isUndecided, setupSteps, type SetupInput } from "./setup";

const now = new Date("2026-09-28T12:00:00Z");
const known = <T,>(data: T) => ({ readable: true, data });

function input(over: Partial<SetupInput> = {}): SetupInput {
  return {
    connectors: known([]),
    servers: known([]),
    keys: known([]),
    calls: known([]),
    ...over,
  };
}

const done = (steps: ReturnType<typeof setupSteps>) => Object.fromEntries(steps.map((s) => [s.id, s.done]));

describe("setupSteps", () => {
  it("starts a fresh workspace with nothing done, in order", () => {
    const steps = setupSteps(input(), now);
    expect(steps.map((s) => s.id)).toEqual(["connector", "server", "key", "client"]);
    expect(steps.every((s) => s.done === false)).toBe(true);
    expect(isSetUp(steps)).toBe(false);
  });

  it("ticks each step from the thing it asks for", () => {
    const steps = setupSteps(input({ connectors: known([{}]), servers: known([{}]), keys: known([{}]) }), now);
    expect(done(steps)).toEqual({ connector: true, server: true, key: true, client: false });
  });

  it("does not count a key that is revoked or expired", () => {
    const keys = known([{ revokedAt: "2026-09-27T00:00:00Z" }, { expiresAt: "2026-09-28T11:59:00Z" }]);
    expect(done(setupSteps(input({ keys }), now)).key).toBe(false);
  });

  it("counts a client as connected from a call on record or a key's last use", () => {
    expect(done(setupSteps(input({ calls: known([{}]) }), now)).client).toBe(true);
    const used = known([{ lastUsedAt: "2026-09-28T11:00:00Z", revokedAt: "2026-09-28T11:30:00Z" }]);
    expect(done(setupSteps(input({ keys: used }), now)).client).toBe(true);
  });

  it("leaves a step undecided while its read is out, and the whole list with it", () => {
    const steps = setupSteps(input({ servers: { readable: true, data: undefined } }), now);
    expect(done(steps).server).toBeUndefined();
    expect(isUndecided(steps)).toBe(true);
    const client = setupSteps(input({ calls: { readable: true, data: undefined } }), now);
    expect(done(client).client).toBeUndefined();
  });

  it("leaves out a step the viewer may not read, and finishes without it", () => {
    const steps = setupSteps(
      input({
        connectors: known([{}]),
        servers: known([{}]),
        keys: { readable: false, data: undefined },
        calls: known([{}]),
      }),
      now,
    );
    expect(steps.map((s) => s.id)).toEqual(["connector", "server", "client"]);
    expect(isSetUp(steps)).toBe(true);
  });

  it("drops the client step only when neither calls nor keys can be read", () => {
    const steps = setupSteps(
      input({ keys: { readable: false, data: undefined }, calls: { readable: false, data: undefined } }),
      now,
    );
    expect(steps.map((s) => s.id)).toEqual(["connector", "server"]);
  });
});

describe("isLive", () => {
  it("is false once revoked or past expiry", () => {
    expect(isLive({}, now)).toBe(true);
    expect(isLive({ expiresAt: "2026-09-29T00:00:00Z" }, now)).toBe(true);
    expect(isLive({ expiresAt: "2026-09-28T00:00:00Z" }, now)).toBe(false);
    expect(isLive({ revokedAt: "2026-09-28T00:00:00Z" }, now)).toBe(false);
  });
});
