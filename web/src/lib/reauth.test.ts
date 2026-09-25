import { describe, expect, it } from "vitest";
import { createReauthGate, isReauthRequired, reauthInterceptors, type ReauthGate } from "./reauth";

/** Resolves when the gate asks its question. */
function asked(gate: ReauthGate): Promise<void> {
  return new Promise((resolve) => {
    if (gate.open()) return resolve();
    const stop = gate.subscribe(() => {
      if (gate.open()) {
        stop();
        resolve();
      }
    });
  });
}

const refusal = {
  status: 403,
  detail: "reauth_required: sign in again to continue",
  errors: [{ location: "session", message: "sign in again", value: "reauth_required" }],
};

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("isReauthRequired", () => {
  it("reads the code, not the prose", () => {
    expect(isReauthRequired(403, refusal)).toBe(true);
    expect(isReauthRequired(403, { detail: "reauth_required: but no code" })).toBe(false);
    expect(isReauthRequired(403, { errors: [{ value: "last_owner" }] })).toBe(false);
    expect(isReauthRequired(409, refusal)).toBe(false);
    expect(isReauthRequired(403, null)).toBe(false);
  });
});

describe("createReauthGate", () => {
  it("asks once for requests refused together", async () => {
    const gate = createReauthGate();
    let opened = 0;
    gate.subscribe(() => {
      if (gate.open()) opened++;
    });
    const a = gate.ask();
    const b = gate.ask();
    expect(gate.open()).toBe(true);
    gate.answer(true);
    await expect(a).resolves.toBe(true);
    await expect(b).resolves.toBe(true);
    expect(opened).toBe(1);
    expect(gate.open()).toBe(false);
  });
});

describe("reauthInterceptors", () => {
  const post = () =>
    new Request("http://app.test/api/v1/api-keys", { method: "POST", body: JSON.stringify({ name: "k" }) });

  it("sends a refused write again, body and all, once the person confirms", async () => {
    const gate = createReauthGate();
    const sent: string[] = [];
    const i = reauthInterceptors(gate, async (r) => {
      sent.push(await r.text());
      return json(200, { secret: "s" });
    });
    const request = i.request(post());
    await request.text(); // what fetch does to the original
    const pending = i.response(json(403, refusal), request);
    await asked(gate);
    gate.answer(true);
    const res = await pending;
    expect(res.status).toBe(200);
    expect(sent).toEqual([JSON.stringify({ name: "k" })]);
  });

  it("hands the refusal back when the person cancels", async () => {
    const gate = createReauthGate();
    let sends = 0;
    const i = reauthInterceptors(gate, async () => {
      sends++;
      return json(200, {});
    });
    const request = i.request(post());
    const pending = i.response(json(403, refusal), request);
    await asked(gate);
    gate.answer(false);
    expect((await pending).status).toBe(403);
    expect(sends).toBe(0);
  });

  it("leaves every other answer alone", async () => {
    const gate = createReauthGate();
    const i = reauthInterceptors(gate, async () => json(200, {}));
    const other = i.request(post());
    expect((await i.response(json(403, { errors: [{ value: "last_owner" }] }), other)).status).toBe(403);
    const read = i.request(new Request("http://app.test/api/v1/api-keys"));
    expect((await i.response(json(403, refusal), read)).status).toBe(403);
    expect(gate.open()).toBe(false);
  });
});
