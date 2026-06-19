import { describe, it, expect, vi } from "vitest";
import {
  createCryptoProvisionGen,
  createProvisionHttpHandler,
  PROVISION_CLIENT_ID_PATTERN,
  createSharedProvisionGate,
  type ProvisionAdapterDeps,
  type SharedStore,
} from "./index.js";
import { KeyStoreUnavailableError } from "./ingest.js";
import { MAX_PROVISION_BODY_BYTES, type ProvisionPersistResult } from "./provision.js";

describe("createCryptoProvisionGen (RP1 — CSPRNG)", () => {
  const { generateClientId, generateKey } = createCryptoProvisionGen();
  it("generates client_ids that always satisfy the ingest charset", () => {
    for (let i = 0; i < 200; i++) {
      expect(PROVISION_CLIENT_ID_PATTERN.test(generateClientId())).toBe(true);
    }
  });
  it("generates unique ids and high-entropy keys", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => generateClientId()));
    expect(ids.size).toBe(1000); // no collisions over 1k draws (128-bit)
    expect(generateKey().length).toBeGreaterThanOrEqual(40); // 256-bit base64 ≈ 44 chars
    expect(generateKey()).not.toBe(generateKey());
  });
});

describe("createProvisionHttpHandler — HTTP mapping", () => {
  function deps(over: Partial<ProvisionAdapterDeps> = {}): ProvisionAdapterDeps {
    return {
      now: () => 1_700_000_000_000,
      verifyAttestation: () => true,
      gate: { allow: () => true },
      keyProvisioner: { create: async () => "created" as ProvisionPersistResult },
      ...createCryptoProvisionGen(),
      ...over,
    };
  }
  const http = (body: string, headers: Record<string, string | undefined> = {}, ip = "203.0.113.7") => ({ rawBody: body, headers, ip });

  it("201 returns a minted client_id + key, JSON content-type", async () => {
    const h = createProvisionHttpHandler(deps());
    const r = await h(http("{}", { "x-firebase-appcheck": "tok" }));
    expect(r.status).toBe(201);
    expect(r.headers["content-type"]).toBe("application/json");
    const body = JSON.parse(r.body);
    expect(PROVISION_CLIENT_ID_PATTERN.test(body.client_id)).toBe(true);
    expect(typeof body.key).toBe("string");
  });

  it("PW: parses {challenge, sig, nonce} from the body into the PoW solution passed to the core", async () => {
    const verifyProofOfWork = vi.fn(() => ({ ok: true as const, challengeId: "cid1", difficulty: 20 }));
    const h = createProvisionHttpHandler(deps({ verifyProofOfWork, consumeChallenge: () => true }));
    const r = await h(http(JSON.stringify({ challenge: "cid1.9.20", sig: "sig", nonce: "nn" }), { "x-firebase-appcheck": "tok" }));
    expect(r.status).toBe(201);
    expect(verifyProofOfWork).toHaveBeenCalledWith({ challenge: "cid1.9.20", sig: "sig", nonce: "nn" });
  });

  it("PW: a body with no solution under a PoW-required handler → 401 (proof_required, opaque)", async () => {
    const h = createProvisionHttpHandler(deps({ verifyProofOfWork: () => ({ ok: true, challengeId: "c", difficulty: 1 }) }));
    const r = await h(http("{}", { "x-firebase-appcheck": "tok" }));
    expect(r.status).toBe(401);
  });

  it("lifts the attestation token from the x-firebase-appcheck header into the core", async () => {
    const verifyAttestation = vi.fn(() => true);
    const h = createProvisionHttpHandler(deps({ verifyAttestation }));
    await h(http("{}", { "x-firebase-appcheck": "the-token" }));
    expect(verifyAttestation).toHaveBeenCalledWith("the-token");
  });

  it("401 when no attestation header is present (fail closed)", async () => {
    const h = createProvisionHttpHandler(deps());
    const r = await h(http("{}", {}));
    expect(r.status).toBe(401);
  });

  it("413 on an oversized body at the transport (before the core)", async () => {
    const verifyAttestation = vi.fn(() => true);
    const h = createProvisionHttpHandler(deps({ verifyAttestation }));
    const r = await h(http("x".repeat(MAX_PROVISION_BODY_BYTES + 1), { "x-firebase-appcheck": "tok" }));
    expect(r.status).toBe(413);
    expect(verifyAttestation).not.toHaveBeenCalled();
  });

  it("429 (mint ceiling) carries Retry-After", async () => {
    const h = createProvisionHttpHandler(deps({ gate: { allow: () => false } }));
    const r = await h(http("{}", { "x-firebase-appcheck": "tok" }));
    expect(r.status).toBe(429);
    expect(r.headers["retry-after"]).toBe("3600");
  });

  it("503 (transient store fault) carries Retry-After and an opaque body", async () => {
    const create = async () => { throw new KeyStoreUnavailableError(); };
    const h = createProvisionHttpHandler(deps({ keyProvisioner: { create } }));
    const r = await h(http("{}", { "x-firebase-appcheck": "tok" }));
    expect(r.status).toBe(503);
    expect(r.headers["retry-after"]).toBe("5");
    expect(JSON.parse(r.body)).toEqual({ error: "unavailable" });
  });

  it("an unexpected throw becomes an opaque 500 (no detail leaked)", async () => {
    const create = async () => { throw new Error("boom"); };
    const h = createProvisionHttpHandler(deps({ keyProvisioner: { create } }));
    const r = await h(http("{}", { "x-firebase-appcheck": "tok" }));
    expect(r.status).toBe(500);
    expect(JSON.parse(r.body)).toEqual({ error: "internal" });
  });
});

describe("createSharedProvisionGate (RP4 — cross-instance mint ceiling, fail closed)", () => {
  function fakeStore(): SharedStore & { fail: boolean } {
    const counters = new Map<string, number>();
    return {
      fail: false,
      async increment(key: string) {
        if (this.fail) throw new Error("store down");
        const n = (counters.get(key) ?? 0) + 1;
        counters.set(key, n);
        return n;
      },
      async claim() { return true; },
    };
  }

  it("allows up to perIp, then denies that IP", async () => {
    const store = fakeStore();
    const gate = createSharedProvisionGate(store, { now: () => 0, perIp: 2, globalCeiling: 100 });
    expect(await gate.allow("1.1.1.1")).toBe(true);
    expect(await gate.allow("1.1.1.1")).toBe(true);
    expect(await gate.allow("1.1.1.1")).toBe(false); // 3rd over perIp=2
    expect(await gate.allow("2.2.2.2")).toBe(true); // a different IP still has budget
  });

  it("denies once the GLOBAL ceiling is crossed (even a fresh IP)", async () => {
    const store = fakeStore();
    const gate = createSharedProvisionGate(store, { now: () => 0, perIp: 100, globalCeiling: 2 });
    expect(await gate.allow("a")).toBe(true);
    expect(await gate.allow("b")).toBe(true);
    expect(await gate.allow("c")).toBe(false); // global ceiling hit
  });

  it("fails CLOSED (deny) on a store outage", async () => {
    const store = fakeStore();
    store.fail = true;
    const gate = createSharedProvisionGate(store, { now: () => 0 });
    expect(await gate.allow("1.1.1.1")).toBe(false);
  });

  it("PW-GET-FLOOD: a distinct keyPrefix gives an INDEPENDENT budget (challenge gate ≠ mint gate)", async () => {
    const store = fakeStore();
    const mint = createSharedProvisionGate(store, { now: () => 0, perIp: 1, keyPrefix: "pv" });
    const challenge = createSharedProvisionGate(store, { now: () => 0, perIp: 1, keyPrefix: "pvc" });
    expect(await mint.allow("1.1.1.1")).toBe(true);
    expect(await mint.allow("1.1.1.1")).toBe(false); // mint budget spent
    expect(await challenge.allow("1.1.1.1")).toBe(true); // challenge budget untouched by the mint gate
    expect(await challenge.allow("1.1.1.1")).toBe(false); // then its own budget is enforced
  });
});
