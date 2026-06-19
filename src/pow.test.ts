import { describe, it, expect } from "vitest";
import { countLeadingZeroBits, powHash, verifyPowSolution, solvePow } from "./pow.js";

describe("countLeadingZeroBits", () => {
  it("counts across zero bytes and into a partial byte", () => {
    expect(countLeadingZeroBits(Buffer.from([0x00, 0x00, 0xff]))).toBe(16);
    expect(countLeadingZeroBits(Buffer.from([0x00, 0x0f]))).toBe(12); // 8 + 4
    expect(countLeadingZeroBits(Buffer.from([0xff]))).toBe(0);
    expect(countLeadingZeroBits(Buffer.from([0x01]))).toBe(7);
    expect(countLeadingZeroBits(Buffer.from([0x00, 0x00]))).toBe(16);
  });
});

describe("proof-of-work verify/solve (A4 — proposed)", () => {
  it("solve then verify round-trips at a modest difficulty", () => {
    const challenge = "chal-abc-123";
    const nonce = solvePow(challenge, 12);
    expect(nonce).not.toBeNull();
    expect(verifyPowSolution(challenge, nonce!, 12)).toBe(true);
  });

  it("a valid solution for one challenge does NOT verify for another (challenge-bound)", () => {
    const nonce = solvePow("challenge-A", 10)!;
    expect(verifyPowSolution("challenge-A", nonce, 10)).toBe(true);
    expect(verifyPowSolution("challenge-B", nonce, 10)).toBe(false);
  });

  it("a solution at difficulty N also satisfies any lower difficulty, and usually fails a much higher one", () => {
    const challenge = "chal-xyz";
    const nonce = solvePow(challenge, 12)!;
    expect(verifyPowSolution(challenge, nonce, 8)).toBe(true);   // ≥8 leading zeros holds
    expect(verifyPowSolution(challenge, nonce, 24)).toBe(false); // 12-bit solution can't meet 24
  });

  it("rejects a wrong/empty nonce and a non-positive difficulty", () => {
    expect(verifyPowSolution("c", "definitely-not-a-solution", 16)).toBe(false);
    expect(verifyPowSolution("c", "x", 0)).toBe(false);
    expect(verifyPowSolution("c", "x", -1)).toBe(false);
  });

  it("powHash is deterministic and challenge:nonce separated", () => {
    expect(powHash("a", "b").equals(powHash("a", "b"))).toBe(true);
    expect(powHash("a", "b").equals(powHash("a:b", ""))).toBe(false); // separator isn't ambiguous
  });
});
