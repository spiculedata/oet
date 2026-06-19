/**
 * QA e2e pin (AGENT QA) — A4 PW2+PW4 provisioning PoW gate through the REAL crypto seam.
 *
 * DEV's `provision.test.ts` proves handleProvision's control flow with a MOCKED `verifyProofOfWork`
 * (`{ok:true, challengeId:"cid1"}`). This pin instead wires the real `issueChallenge` / `verifyPowChallenge`
 * / `solvePow` primitives plus a real single-use consume set, so the actual crypto wiring is what gates the
 * mint. It proves end-to-end: (1) a genuinely solved, server-signed challenge mints once; (2) replaying the
 * same solved challenge is rejected single-use (PW2); (3) a client cannot downgrade the embedded difficulty
 * (PW3) — the sig authenticates it, so a tampered challenge fails closed and never mints.
 */
import { describe, it, expect, vi } from "vitest";
import {
  handleProvision,
  type ProvisionDeps,
  type ProvisionRequest,
  type ProvisionPersistResult,
} from "./provision.js";
import type { SecurityEvent } from "./ingest.js";
import { issueChallenge, verifyPowChallenge } from "./provision-pow.js";
import { solvePow } from "./pow.js";

const NOW = 1_700_000_000_000;
const HMAC_KEY = "server-side-pow-key-never-shipped";
const DIFFICULTY = 8; // small enough that solvePow is fast in CI, > 0 so the gate is real

/** All-allow deps with the REAL PoW seam wired (verify = verifyPowChallenge, consume = a single-use set). */
function makeDeps(consumed: Set<string>, overrides: Partial<ProvisionDeps> = {}): ProvisionDeps {
  let n = 0;
  return {
    now: () => NOW,
    verifyAttestation: () => true,
    gate: { allow: () => true },
    generateClientId: () => `inst_${(n++).toString().padStart(4, "0")}`,
    generateKey: () => "k_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    keyProvisioner: { create: async () => "created" as ProvisionPersistResult },
    // The real verify — difficulty/expiry are sig-authenticated inside this call, no mock shortcut.
    verifyProofOfWork: (sol) => verifyPowChallenge(sol, { now: () => NOW, hmacKey: HMAC_KEY }),
    // Real atomic single-use: newly-consumed → true, already-seen → false (PW2 shared-store semantics).
    consumeChallenge: (id) => {
      if (consumed.has(id)) return false;
      consumed.add(id);
      return true;
    },
    ...overrides,
  };
}

/** Issue a server-signed challenge and actually solve it — returns the body a real client would POST. */
function solve(id: string): ProvisionRequest["pow"] {
  const ch = issueChallenge({ now: () => NOW, hmacKey: HMAC_KEY, difficulty: DIFFICULTY, randomId: () => id });
  const nonce = solvePow(ch.challenge, ch.difficulty);
  expect(nonce).not.toBeNull();
  return { challenge: ch.challenge, sig: ch.sig, nonce: nonce as string };
}

function req(pow: ProvisionRequest["pow"]): ProvisionRequest {
  return { rawBody: "{}", ip: "203.0.113.7", attestationToken: "att-tok", pow };
}

describe("QA e2e — provisioning PoW gate over the real crypto (A4 PW2+PW4)", () => {
  it("mints (201) for a genuinely solved, server-signed challenge and consumes its id once", async () => {
    const consumed = new Set<string>();
    const create = vi.fn(async () => "created" as ProvisionPersistResult);
    const pow = solve("cid_mint");
    const r = await handleProvision(req(pow), makeDeps(consumed, { keyProvisioner: { create } }));
    expect(r.status).toBe(201);
    expect(consumed.has("cid_mint")).toBe(true); // the verified challengeId, single-use
    expect(create).toHaveBeenCalledTimes(1);
  });

  it("rejects a REPLAY of the same solved challenge — 401 proof_replay, no second mint (PW2)", async () => {
    const consumed = new Set<string>();
    const events: SecurityEvent[] = [];
    const create = vi.fn(async () => "created" as ProvisionPersistResult);
    const pow = solve("cid_replay");
    const deps = makeDeps(consumed, { keyProvisioner: { create }, onSecurityEvent: (e) => events.push(e) });
    const first = await handleProvision(req(pow), deps);
    const second = await handleProvision(req(pow), deps); // identical body, real consume already burned it
    expect(first.status).toBe(201);
    expect(second.status).toBe(401);
    expect(events.at(-1)?.reason).toBe("proof_replay"); // coarse reason on the PII-free event sink
    expect(create).toHaveBeenCalledTimes(1); // minted exactly once
  });

  it("cannot DOWNGRADE difficulty — a tampered challenge fails the sig → 401, never mints (PW3)", async () => {
    const consumed = new Set<string>();
    const events: SecurityEvent[] = [];
    const create = vi.fn(async () => "created" as ProvisionPersistResult);
    // Issue at difficulty 8, then rewrite the embedded difficulty to 1 while keeping the original sig.
    const ch = issueChallenge({ now: () => NOW, hmacKey: HMAC_KEY, difficulty: DIFFICULTY, randomId: () => "cid_down" });
    const [randomId, exp] = ch.challenge.split(".");
    const downgraded = `${randomId}.${exp}.1`;
    const nonce = solvePow(downgraded, 1) as string; // trivially solvable at the lowered bar
    const r = await handleProvision(
      req({ challenge: downgraded, sig: ch.sig, nonce }),
      makeDeps(consumed, { keyProvisioner: { create }, onSecurityEvent: (e) => events.push(e) }),
    );
    expect(r.status).toBe(401);
    expect(events.at(-1)?.reason).toBe("proof_bad_sig"); // sig was over difficulty 8 → tamper detected
    expect(create).not.toHaveBeenCalled();
    expect(consumed.size).toBe(0); // a bad proof never reaches consume
  });

  it("rejects an attacker-forged challenge signed with the wrong key — 401 proof_bad_sig", async () => {
    const consumed = new Set<string>();
    const events: SecurityEvent[] = [];
    const forged = issueChallenge({ now: () => NOW, hmacKey: "attacker-key", difficulty: DIFFICULTY, randomId: () => "cid_forge" });
    const nonce = solvePow(forged.challenge, forged.difficulty) as string;
    const r = await handleProvision(req({ challenge: forged.challenge, sig: forged.sig, nonce }), makeDeps(consumed, { onSecurityEvent: (e) => events.push(e) }));
    expect(r.status).toBe(401);
    expect(events.at(-1)?.reason).toBe("proof_bad_sig");
    expect(consumed.size).toBe(0);
  });
});
