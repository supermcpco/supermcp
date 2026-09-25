import { describe, expect, it } from "vitest";
import {
  acceptError,
  conflictCode,
  expiryDays,
  invitedBy,
  inviteInvalid,
  lookupError,
  memberError,
  notReady,
  passwordHint,
  passwordMinLength,
  relativeTime,
  safeNext,
  sameEmail,
  sourceLabel,
  tooManyAttempts,
} from "./members";

const conflict = (value: string) => ({
  status: 409,
  detail: "server prose",
  errors: [{ location: "body", message: "server prose", value }],
});

describe("memberError", () => {
  it.each(["self", "last_owner", "scim_managed", "invite_exists", "already_member", "invite_limit"])("explains %s without the server's prose", (code) => {
    expect(conflictCode(conflict(code))).toBe(code);
    const text = memberError(conflict(code));
    expect(text).not.toBe("server prose");
    expect(text.length).toBeGreaterThan(10);
  });

  it("says who to ask about an identity provider", () => {
    expect(memberError(conflict("scim_managed"))).toMatch(/identity provider/);
  });

  it("falls back to the server's detail for an unknown code", () => {
    expect(conflictCode(conflict("something_new"))).toBeUndefined();
    expect(memberError(conflict("something_new"))).toBe("server prose");
  });

  it("says to wait on a lockout", () => {
    expect(memberError({ status: 429, detail: "too many requests" })).toBe(tooManyAttempts);
  });

  it("says the feature is not there yet on a 501", () => {
    expect(memberError({ status: 501, detail: "not implemented" })).toBe(notReady);
  });
});

describe("acceptError", () => {
  it("says the same thing for every invalid link", () => {
    expect(acceptError({ status: 404, detail: "revoked" }).text).toBe(inviteInvalid);
  });

  it("sends an existing account to sign in, matching on the code", () => {
    const got = acceptError(conflict("account_exists"));
    expect(got.signInFirst).toBe(true);
    expect(got.text).toMatch(/sign in first/i);
    expect(got.text).not.toBe("server prose");
  });

  it("does not send an unrecognised conflict to sign in", () => {
    expect(acceptError(conflict("something_new"))).toEqual({ text: "server prose", signInFirst: false });
    expect(acceptError({ status: 409, detail: "exists" }).signInFirst).toBe(false);
  });

  it("explains an existing membership", () => {
    expect(acceptError(conflict("already_member"))).toEqual({
      text: expect.stringMatching(/already a member/),
      signInFirst: false,
    });
  });

  it("says to wait on a lockout", () => {
    expect(acceptError({ status: 429, detail: "locked" })).toEqual({ text: tooManyAttempts, signInFirst: false });
  });

  it("explains a different email", () => {
    expect(acceptError({ status: 403 }).text).toMatch(/different email/);
  });
});

describe("lookupError", () => {
  it("reads the same for every refusal but a lockout or a missing feature", () => {
    expect(lookupError({ status: 404 })).toBe(inviteInvalid);
    expect(lookupError({ status: 410 })).toBe(inviteInvalid);
    expect(lookupError(new Error("network"))).toBe(inviteInvalid);
    expect(lookupError({ status: 429 })).toBe(tooManyAttempts);
    expect(lookupError({ status: 501 })).toMatch(/not available/);
  });
});

describe("passwordHint", () => {
  it.each([
    [undefined, "At least 12 characters, using at least 2 of lower case, upper case, digits and symbols."],
    [{ minLength: 16, requireClasses: 3 }, "At least 16 characters, using at least 3 of lower case, upper case, digits and symbols."],
    [{ minLength: 10, requireClasses: 1 }, "At least 10 characters."],
    [{ minLength: 20, requireClasses: 4 }, "At least 20 characters, using lower case, upper case, digits and symbols."],
    [{ minLength: 0, requireClasses: 0 }, "At least 12 characters, using at least 2 of lower case, upper case, digits and symbols."],
  ])("%j", (policy, want) => {
    expect(passwordHint(policy)).toBe(want);
  });

  it("enforces the policy's length in the field", () => {
    expect(passwordMinLength({ minLength: 16 })).toBe(16);
    expect(passwordMinLength(undefined)).toBe(12);
  });
});

describe("invitedBy", () => {
  it("names the sender, or says nothing", () => {
    expect(invitedBy("Ada Lovelace")).toBe("sent by Ada Lovelace");
    expect(invitedBy("  ")).toBeUndefined();
    expect(invitedBy(undefined)).toBeUndefined();
  });
});

describe("relativeTime", () => {
  const now = new Date("2026-09-25T12:00:00Z");
  it.each([
    [undefined, "Never"],
    ["not a date", "Never"],
    ["2026-09-25T11:59:30Z", "just now"],
    ["2026-09-25T11:55:00Z", "5 minutes ago"],
    ["2026-09-25T09:00:00Z", "3 hours ago"],
    ["2026-09-24T12:00:00Z", "yesterday"],
    ["2026-09-22T12:00:00Z", "3 days ago"],
    ["2026-09-11T12:00:00Z", "2 weeks ago"],
    ["2026-06-25T12:00:00Z", "3 months ago"],
    ["2024-09-25T12:00:00Z", "2 years ago"],
    ["2026-09-27T12:00:00Z", "in 2 days"],
  ])("%s -> %s", (iso, want) => {
    expect(relativeTime(iso, now)).toBe(want);
  });
});

describe("expiryDays", () => {
  it.each([
    ["7", 7],
    ["", 7],
    ["abc", 7],
    ["0", 1],
    ["-4", 1],
    ["31", 30],
    [12.7, 12],
  ])("%s -> %d", (input, want) => {
    expect(expiryDays(input)).toBe(want);
  });
});

describe("safeNext", () => {
  it.each([
    [undefined, "/"],
    ["", "/"],
    ["/invite/abc", "/invite/abc"],
    ["https://evil.example/", "/"],
    ["//evil.example/", "/"],
    ["/\\evil.example/", "/"],
    ["invite/abc", "/"],
  ])("%s -> %s", (next, want) => {
    expect(safeNext(next)).toBe(want);
  });
});

describe("sameEmail", () => {
  it("ignores case and surrounding space", () => {
    expect(sameEmail("Ada@Example.test ", "ada@example.test")).toBe(true);
    expect(sameEmail("ada@example.test", "bob@example.test")).toBe(false);
    expect(sameEmail(undefined, "ada@example.test")).toBe(false);
  });
});

describe("sourceLabel", () => {
  it("names each source", () => {
    expect(sourceLabel("password")).toBe("Password");
    expect(sourceLabel("sso")).toBe("SSO");
    expect(sourceLabel("scim")).toBe("SCIM");
  });
});
