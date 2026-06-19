/**
 * QA e2e pin (AGENT QA) — A4 Steam entitlement × PoW consume-ordering through the REAL crypto seam.
 *
 * DEV reordered `handleProvision` so PW2 single-use consume happens at step 3d (AFTER the entitlement check
 * at 3c), not right after PoW verify. The point: a failed/transient entitlement result must NOT burn the
 * single-use PoW challenge, or a legitimate user whose ownership check blips would be forced to re-solve a
 * fresh PoW. This pin wires the real `issueChallenge`/`verifyPowChallenge`/`solvePow` + a real consume set
 * and a controllable entitlement verifier, and proves the interaction end-to-end:
 *   1. PoW-valid + entitlement-FAILS → 401 entitlement_failed, challenge NOT consumed → a retry with a
 *      passing entitlement on the SAME challenge still mints (no burn).
 *   2. replay protection STILL holds after a successful mint (consume did run on success).
 *   3. entitlement is required when configured; a throwing verifier fails closed without consuming.
 */
import { describe, it, expect } from "vitest";
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
const DIFFICULTY = 8;

/** A controllable entitlement verifier whose verdict can be flipped between calls. */
function entitlementSwitch(initial: boolean) {
  const state = { ok: initial, throws: false };
  const verify = async (_token: string): Promise<boolean> => {
    if (state.throws) throw new Error("steam api down");
    return state.ok;
  };
  return { state, verify };
}

function makeDeps(
  consumed: Set<string>,
  verifyEntitlement: ProvisionDeps["verifyEntitlement"],
  overrides: Partial<ProvisionDeps> = {},
): ProvisionDeps {
  let n = 0;
  return {
    now: () => NOW,
    verifyAttestation: () => true,
    gate: { allow: () => true },
    generateClientId: () => `inst_${(n++).toString().padStart(4, "0")}`,
    generateKey: () => "k_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    keyProvisioner: { create: async () => "created" as ProvisionPersistResult },
    verifyProofOfWork: (sol) => verifyPowChallenge(sol, { now: () => NOW, hmacKey: HMAC_KEY }),
    consumeChallenge: (id) => {
      if (consumed.has(id)) return false;
      consumed.add(id);
      return true;
    },
    verifyEntitlement,
    ...overrides,
  };
}

function solve(id: string): ProvisionRequest["pow"] {
  const ch = issueChallenge({ now: () => NOW, hmacKey: HMAC_KEY, difficulty: DIFFICULTY, randomId: () => id });
  const nonce = solvePow(ch.challenge, ch.difficulty);
  expect(nonce).not.toBeNull();
  return { challenge: ch.challenge, sig: ch.sig, nonce: nonce as string };
}

function req(pow: ProvisionRequest["pow"], entitlementToken: string | undefined): ProvisionRequest {
  return { rawBody: "{}", ip: "203.0.113.7", attestationToken: "att-tok", pow, entitlementToken };
}

describe("QA e2e — Steam entitlement × PoW consume-ordering (A4, step 3c/3d)", () => {
  it("a FAILED entitlement does NOT burn the challenge — a retry with passing entitlement still mints", async () => {
    const consumed = new Set<string>();
    const ent = entitlementSwitch(false); // first attempt: ownership check fails
    const deps = makeDeps(consumed, ent.verify);
    const pow = solve("cid_noburn");

    const first = await handleProvision(req(pow, "tok"), deps);
    expect(first.status).toBe(401);
    expect(consumed.size).toBe(0); // entitlement failed BEFORE consume → challenge intact

    ent.state.ok = true; // ownership now resolves (e.g. the transient blip cleared)
    const retry = await handleProvision(req(pow, "tok"), deps); // SAME solved challenge
    expect(retry.status).toBe(201); // mints — the challenge was never burned
    expect(consumed.has("cid_noburn")).toBe(true);
  });

  it("replay protection STILL holds after a successful mint — second identical request → proof_replay", async () => {
    const consumed = new Set<string>();
    const ent = entitlementSwitch(true);
    const events: SecurityEvent[] = [];
    const deps = makeDeps(consumed, ent.verify, { onSecurityEvent: (e) => events.push(e) });
    const pow = solve("cid_replay");

    const first = await handleProvision(req(pow, "tok"), deps);
    const second = await handleProvision(req(pow, "tok"), deps);
    expect(first.status).toBe(201);
    expect(second.status).toBe(401);
    expect(events.at(-1)?.reason).toBe("proof_replay"); // consume DID run on the successful mint
  });

  it("entitlement is REQUIRED when configured — a missing token → 401 entitlement_required, no consume", async () => {
    const consumed = new Set<string>();
    const events: SecurityEvent[] = [];
    const r = await handleProvision(
      req(solve("cid_req"), undefined), // no entitlement token
      makeDeps(consumed, entitlementSwitch(true).verify, { onSecurityEvent: (e) => events.push(e) }),
    );
    expect(r.status).toBe(401);
    expect(events.at(-1)?.reason).toBe("entitlement_required");
    expect(consumed.size).toBe(0);
  });

  it("a THROWING entitlement verifier fails CLOSED — 401 entitlement_failed, challenge not consumed", async () => {
    const consumed = new Set<string>();
    const ent = entitlementSwitch(true);
    ent.state.throws = true;
    const events: SecurityEvent[] = [];
    const r = await handleProvision(
      req(solve("cid_throw"), "tok"),
      makeDeps(consumed, ent.verify, { onSecurityEvent: (e) => events.push(e) }),
    );
    expect(r.status).toBe(401);
    expect(events.at(-1)?.reason).toBe("entitlement_failed");
    expect(consumed.size).toBe(0); // never consumed on a verifier error
  });
});
