import { describe, expect, it } from "vitest";
import { initials } from "./initials";

describe("initials", () => {
  it("takes the first and last word of a name", () => {
    expect(initials("Ada King Lovelace", "ada@example.test")).toBe("AL");
    expect(initials("  grace  ", "g@example.test")).toBe("G");
  });
  it("falls back to the parts of the address", () => {
    expect(initials(undefined, "margarethe.van-der-berg@example.test")).toBe("MB");
    expect(initials("", "ops@example.test")).toBe("O");
  });
  it("skips parts that do not start with a letter", () => {
    expect(initials(undefined, "browser-1759-0-12@example.test")).toBe("B");
    expect(initials(undefined, "1234@example.test")).toBe("?");
  });
  it("keeps letters outside ASCII", () => {
    expect(initials("Łukasz Żak", "l@example.test")).toBe("ŁŻ");
  });
});
