import { describe, it, expect } from "vitest";
import { issueChallenge, verifyPowChallenge, challengeId } from "./provision-pow.js";
import { solvePow } from "./pow.js";

const KEY = "server-pow-hmac-key";
let clock = 1_700_000_000_000;
const now = () => clock;
let counter = 0;
const randomId = () => `cid${counter++}`;

function freshSolved(difficulty = 12) {
  const c = issueChallenge({ now, hmacKey: KEY, difficulty, randomId });
  const nonce = solvePow(c.challenge, difficulty)!;
  return { ...c, nonce };
}

describe("issueChallenge / verifyPowChallenge (A4 PW1+PW3)", () => {
  it("issue → solve → verify round-trips (ok, returns challengeId + difficulty)", () => {
    const s = freshSolved(12);
    const r = verifyPowChallenge({ challenge: s.challenge, sig: s.sig, nonce: s.nonce }, { now, hmacKey: KEY });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.difficulty).toBe(12);
      expect(r.challengeId).toBe(challengeId(s.challenge));
    }
  });

  it("rejects a tampered challenge (sig no longer matches) → bad_sig", () => {
    const s = freshSolved();
    const r = verifyPowChallenge({ challenge: s.challenge + "x", sig: s.sig, nonce: s.nonce }, { now, hmacKey: KEY });
    expect(r).toEqual({ ok: false, reason: "bad_sig" });
  });

  it("rejects a forged sig / a different server key → bad_sig", () => {
    const s = freshSolved();
    expect(verifyPowChallenge({ ...s }, { now, hmacKey: "WRONG-KEY" }).ok).toBe(false);
  });

  it("rejects a DIFFICULTY DOWNGRADE — difficulty is sig-authenticated", () => {
    // attacker rewrites the embedded difficulty to 1 and solves that; sig won't match the tampered string.
    const s = issueChallenge({ now, hmacKey: KEY, difficulty: 20, randomId });
    const downgraded = s.challenge.replace(/\.20$/, ".1");
    const easyNonce = solvePow(downgraded, 1)!;
    const r = verifyPowChallenge({ challenge: downgraded, sig: s.sig, nonce: easyNonce }, { now, hmacKey: KEY });
    expect(r).toEqual({ ok: false, reason: "bad_sig" });
  });

  it("rejects an EXPIRED challenge → expired", () => {
    const s = freshSolved();
    clock += 130_000; // past the 2-min TTL
    const r = verifyPowChallenge({ challenge: s.challenge, sig: s.sig, nonce: s.nonce }, { now, hmacKey: KEY });
    expect(r).toEqual({ ok: false, reason: "expired" });
    clock = 1_700_000_000_000; // reset
  });

  it("rejects a wrong nonce (valid sig, unsolved) → bad_solution", () => {
    const c = issueChallenge({ now, hmacKey: KEY, difficulty: 16, randomId });
    const r = verifyPowChallenge({ challenge: c.challenge, sig: c.sig, nonce: "not-a-solution" }, { now, hmacKey: KEY });
    expect(r).toEqual({ ok: false, reason: "bad_solution" });
  });

  it("each issued challenge has a distinct id (single-use key for PW2)", () => {
    const a = issueChallenge({ now, hmacKey: KEY, difficulty: 8, randomId });
    const b = issueChallenge({ now, hmacKey: KEY, difficulty: 8, randomId });
    expect(challengeId(a.challenge)).not.toBe(challengeId(b.challenge));
  });
});
