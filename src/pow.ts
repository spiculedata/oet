/**
 * A4 (audit #2) — proof-of-work primitive for the desktop first-run proof (PROPOSED; SEC design gate).
 *
 * App Check is a strong attestation on mobile (Play Integrity / DeviceCheck) but **weak on desktop** — a
 * desktop EXE has no equivalent device attestation, so `/provision` minting can be scripted. A modest,
 * server-issued **proof-of-work** raises the cost of *mass* minting without coupling OET to any store:
 * the client must find a `nonce` whose `SHA-256(challenge:nonce)` has ≥ `difficulty` leading zero bits.
 * One real first-run pays it once (sub-second at modest difficulty); farming N keys costs ~N·2^difficulty
 * hashes. The mint ceiling (RP4) stays the HARD bound; PoW is the bar-raiser, App Check the strong gate
 * where the platform supports it.
 *
 * Pure (`node:crypto` only). The challenge issuance/verification wrapper (stateless, HMAC-signed) and the
 * wiring into `handleProvision` are deferred to SEC ratification — this is just the verifiable core.
 */
import { createHash } from "node:crypto";

/** Count leading zero BITS of a byte buffer (the PoW target metric). */
export function countLeadingZeroBits(buf: Buffer): number {
  let bits = 0;
  for (const byte of buf) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    // leading zeros within this byte: clz32 of an 8-bit value is 24..31 → subtract 24.
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

/** The PoW hash: `SHA-256(challenge ":" nonce)`. Challenge and nonce are opaque strings. */
export function powHash(challenge: string, nonce: string): Buffer {
  return createHash("sha256").update(`${challenge}:${nonce}`).digest();
}

/** True iff `nonce` solves `challenge` at `difficulty` leading-zero bits. Cheap: one hash. */
export function verifyPowSolution(challenge: string, nonce: string, difficulty: number): boolean {
  if (!Number.isInteger(difficulty) || difficulty <= 0) return false;
  return countLeadingZeroBits(powHash(challenge, nonce)) >= difficulty;
}

/**
 * Reference solver — find a nonce solving `challenge` at `difficulty`, or null if none within `maxIter`.
 * For tests + as the canonical client algorithm; the server never solves, only verifies.
 */
export function solvePow(challenge: string, difficulty: number, maxIter = 5_000_000): string | null {
  for (let i = 0; i < maxIter; i++) {
    const nonce = i.toString(36);
    if (verifyPowSolution(challenge, nonce, difficulty)) return nonce;
  }
  return null;
}
