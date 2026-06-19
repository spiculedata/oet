/**
 * A4 / PW1+PW3 — stateless, HMAC-signed, time-bound proof-of-work CHALLENGE (Owner-approved; SEC gate).
 *
 * `/provision` issues a challenge the client must solve (PoW) before minting. The challenge is
 * **self-authenticating and stateless**: it encodes a random id, an expiry, and the difficulty, and is
 * signed with a server key — so the verifier confirms "this is a real, unexpired, untampered challenge I
 * issued" with NO server storage (`HMAC(serverKey, challenge)`, constant-time compared). PW3: difficulty
 * is a parameter (tuned via env at the call site); a modest value (~20–22 bits) is sub-second for one
 * legit first run but multiplies a farmer's cost. The RP4 mint ceiling stays the hard cap.
 *
 * Pure — `node:crypto` + the injected clock/key/CSPRNG. Reuses the `pow.ts` solution check. The single-use
 * binding (PW2, consume `challengeId` in the shared store) and the `handleProvision` integration (PW4) are
 * the next slice; this is the challenge primitive they build on.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { verifyPowSolution } from "./pow.js";

export interface ChallengeIssueOptions {
  now: () => number;
  /** Server key that authenticates challenges (real: Secret Manager). Never sent to the client. */
  hmacKey: string;
  /** PW3 — leading-zero-bit target. Tuned via env at the call site. */
  difficulty: number;
  /** Challenge lifetime; default 2 min (enough to solve + submit, short enough to bound replay). */
  ttlMs?: number;
  /** CSPRNG unique id per challenge (real: randomBytes); also the single-use key for PW2. */
  randomId: () => string;
}

export interface PowChallenge {
  /** `<randomId>.<exp>.<difficulty>` — opaque to the client except as the PoW input. */
  challenge: string;
  /** `base64(HMAC(hmacKey, challenge))` — authenticates issuance + the embedded exp/difficulty. */
  sig: string;
  difficulty: number;
  /** Absolute expiry (epoch ms). */
  exp: number;
}

export interface PowSolution {
  challenge: string;
  sig: string;
  /** The nonce the client found so `SHA-256(challenge:nonce)` meets the embedded difficulty. */
  nonce: string;
}

export interface PowVerifyOptions {
  now: () => number;
  hmacKey: string;
}

export type PowVerifyResult =
  | { ok: true; challengeId: string; difficulty: number }
  | { ok: false; reason: "bad_sig" | "malformed" | "expired" | "bad_solution" };

const sign = (hmacKey: string, challenge: string): string =>
  createHmac("sha256", hmacKey).update(challenge).digest("base64");

/** PW1 — issue a fresh signed, time-bound challenge. Stateless: nothing is stored server-side. */
export function issueChallenge(opts: ChallengeIssueOptions): PowChallenge {
  const exp = opts.now() + (opts.ttlMs ?? 120_000);
  const challenge = `${opts.randomId()}.${exp}.${opts.difficulty}`;
  return { challenge, sig: sign(opts.hmacKey, challenge), difficulty: opts.difficulty, exp };
}

/** The challenge's unique id — the single-use key to consume in the shared store (PW2). */
export function challengeId(challenge: string): string {
  return challenge.split(".")[0] ?? challenge;
}

/**
 * PW1 verify — confirm a solution: (1) the `sig` is ours (constant-time), (2) the challenge is
 * well-formed, (3) not expired, (4) the `nonce` actually solves it at the embedded difficulty. Fail
 * closed with a coarse reason; the embedded difficulty is authenticated by the sig, so a client can't
 * downgrade it.
 */
export function verifyPowChallenge(sol: PowSolution, opts: PowVerifyOptions): PowVerifyResult {
  // 1. signature — authenticates the whole challenge (incl. exp + difficulty). Constant-time.
  const want = Buffer.from(sign(opts.hmacKey, sol.challenge), "utf8");
  const got = Buffer.from(sol.sig, "utf8");
  if (got.length !== want.length || !timingSafeEqual(got, want)) return { ok: false, reason: "bad_sig" };
  // 2. shape: `<id>.<exp>.<difficulty>`
  const parts = sol.challenge.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed" };
  const exp = Number(parts[1]);
  const difficulty = Number(parts[2]);
  if (!Number.isFinite(exp) || !Number.isInteger(difficulty) || difficulty <= 0) {
    return { ok: false, reason: "malformed" };
  }
  // 3. expiry
  if (opts.now() > exp) return { ok: false, reason: "expired" };
  // 4. proof-of-work (difficulty is sig-authenticated → no client downgrade)
  if (!verifyPowSolution(sol.challenge, sol.nonce, difficulty)) return { ok: false, reason: "bad_solution" };
  return { ok: true, challengeId: challengeId(sol.challenge), difficulty };
}
