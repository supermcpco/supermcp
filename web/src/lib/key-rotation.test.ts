import { describe, expect, it } from "vitest";
import { canRotate, defaultGraceSeconds, graceChoices, maxGraceSeconds, stopsWorking } from "./key-rotation";

describe("graceChoices", () => {
  it("stays inside what the server accepts", () => {
    for (const c of graceChoices) {
      expect(c.seconds).toBeGreaterThanOrEqual(0);
      expect(c.seconds).toBeLessThanOrEqual(maxGraceSeconds);
    }
  });

  it("offers stopping the old key at once and the default", () => {
    const seconds = graceChoices.map((c) => c.seconds);
    expect(seconds).toContain(0);
    expect(seconds).toContain(defaultGraceSeconds);
  });
});

describe("canRotate", () => {
  const now = new Date("2026-09-25T12:00:00Z");
  it.each([
    [{}, true],
    [{ expiresAt: "2026-09-26T12:00:00Z" }, true],
    [{ expiresAt: "2026-09-25T11:59:59Z" }, false],
    [{ revokedAt: "2026-09-24T00:00:00Z" }, false],
  ])("%o -> %s", (key, want) => {
    expect(canRotate(key, now)).toBe(want);
  });
});

describe("stopsWorking", () => {
  const now = new Date("2026-09-25T12:00:00Z");

  it("names the time when it is still ahead", () => {
    expect(stopsWorking("2026-09-25T13:00:00Z", now)).toMatch(/^It stops working at /);
  });

  it("says it has stopped when the time has passed", () => {
    expect(stopsWorking("2026-09-25T12:00:00Z", now)).toBe("It has stopped working.");
  });
});
