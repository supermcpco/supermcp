import { describe, expect, it } from "vitest";
import { asSentence } from "./errors";

describe("asSentence", () => {
  it("capitalises a terse detail and closes it", () => {
    expect(asSentence("invalid email or password")).toBe("Invalid email or password.");
  });

  it("leaves a detail that is already a sentence alone", () => {
    expect(asSentence("Too many attempts. Try again in a minute.")).toBe("Too many attempts. Try again in a minute.");
    expect(asSentence("Is that right?")).toBe("Is that right?");
  });

  it("trims and leaves an empty detail empty", () => {
    expect(asSentence("  locked  ")).toBe("Locked.");
    expect(asSentence("   ")).toBe("");
  });
});
