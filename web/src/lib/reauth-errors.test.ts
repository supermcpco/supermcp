import { describe, expect, it } from "vitest";
import { reauthError } from "./reauth-errors";

describe("reauthError", () => {
  it.each(["reauth_mismatch", "reauth_unconfirmed", "reauth_not_recent"])("explains %s", (code) => {
    expect(reauthError(code)?.length).toBeGreaterThan(20);
  });
  it("has a sentence for a code it does not know, and nothing for none", () => {
    expect(reauthError("something_new")).toMatch(/did not complete/);
    expect(reauthError(undefined)).toBeUndefined();
  });
});
