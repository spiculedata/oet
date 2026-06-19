import { describe, it, expect, vi } from "vitest";
import {
  handleProvision,
  MAX_PROVISION_BODY_BYTES,
  type ProvisionDeps,
  type ProvisionRequest,
  type ProvisionPersistResult,
} from "./provision.js";
import { KeyStoreUnavailableError } from "./ingest.js";
import { CLIENT_ID_KEY_PATTERN } from "./ingest-adapter.js";

/** A deterministic, all-allow set of deps; override per test. */
function makeDeps(overrides: Partial<ProvisionDeps> = {}): ProvisionDeps {
  let n = 0;
  return {
    now: () => 1_700_000_000_000,
    verifyAttestation: () => true,
    gate: { allow: () => true },
    generateClientId: () => `inst_${(n++).toString().padStart(4, "0")}`,
    generateKey: () => "k_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    keyProvisioner: { create: async () => "created" as ProvisionPersistResult },
    ...overrides,
  };
}
function req(extra: Partial<ProvisionRequest> = {}): ProvisionRequest {
  return { rawBody: "{}", ip: "203.0.113.7", attestationToken: "att-tok", ...extra };
}

describe("handleProvision — happy path", () => {
  it("201 returns a fresh client_id + key (charset-valid), persisted create-if-absent", async () => {
    const create = vi.fn(async () => "created" as ProvisionPersistResult);
    const r = await handleProvision(req(), makeDeps({ keyProvisioner: { create } }));
    expect(r.status).toBe(201);
    const body = r.body as { client_id: string; key: string };
    expect(CLIENT_ID_KEY_PATTERN.test(body.client_id)).toBe(true);
    expect(body.key.length).toBeGreaterThan(20);
    expect(create).toHaveBeenCalledWith(body.client_id, body.key);
  });
});

describe("handleProvision — attestation gate (fail closed)", () => {
  it("401 when no attestation token is present", async () => {
    const r = await handleProvision(req({ attestationToken: undefined }), makeDeps());
    expect(r.status).toBe(401);
  });
  it("401 when attestation fails", async () => {
    const r = await handleProvision(req(), makeDeps({ verifyAttestation: () => false }));
    expect(r.status).toBe(401);
  });
  it("401 (fail closed) when the attestation verifier THROWS — never mints on a verifier error", async () => {
    const create = vi.fn();
    const r = await handleProvision(req(), makeDeps({
      verifyAttestation: () => { throw new Error("appcheck down"); },
      keyProvisioner: { create },
    }));
    expect(r.status).toBe(401);
    expect(create).not.toHaveBeenCalled(); // attestation precedes any mint
  });
  it("attestation is checked BEFORE the gate or any key generation", async () => {
    const allow = vi.fn(() => true);
    const generateKey = vi.fn(() => "k");
    await handleProvision(req(), makeDeps({ verifyAttestation: () => false, gate: { allow }, generateKey }));
    expect(allow).not.toHaveBeenCalled();
    expect(generateKey).not.toHaveBeenCalled();
  });
});

describe("handleProvision — abuse gate (cost/flood ceiling, fail closed)", () => {
  it("429 when the mint ceiling is hit", async () => {
    const create = vi.fn();
    const r = await handleProvision(req(), makeDeps({ gate: { allow: () => false }, keyProvisioner: { create } }));
    expect(r.status).toBe(429);
    expect(create).not.toHaveBeenCalled();
  });
  it("429 (fail closed) when the gate store is unavailable (throws)", async () => {
    const r = await handleProvision(req(), makeDeps({ gate: { allow: () => { throw new Error("store down"); } } }));
    expect(r.status).toBe(429);
  });
});

describe("handleProvision — proof-of-work gate (A4 PW2+PW4)", () => {
  const okPow = () => ({ ok: true as const, challengeId: "cid1", difficulty: 20 });
  const powReq = () => req({ pow: { challenge: "cid1.9.20", sig: "s", nonce: "n" } });

  it("mints (201) with a valid solution + a fresh (consumable) challenge", async () => {
    const consumeChallenge = vi.fn(() => true);
    const r = await handleProvision(powReq(), makeDeps({ verifyProofOfWork: okPow, consumeChallenge }));
    expect(r.status).toBe(201);
    expect(consumeChallenge).toHaveBeenCalledWith("cid1");
  });

  it("401 proof_required when PoW is configured but the request carries no solution", async () => {
    const r = await handleProvision(req(), makeDeps({ verifyProofOfWork: okPow }));
    expect(r.status).toBe(401);
    expect((r.body as { error: string }).error).toBe("unauthorized");
  });

  it("401 when the solution is invalid (verify ok:false)", async () => {
    const events: { reason: string }[] = [];
    const r = await handleProvision(
      powReq(),
      makeDeps({ verifyProofOfWork: () => ({ ok: false, reason: "bad_solution" }), onSecurityEvent: (e) => events.push(e) }),
    );
    expect(r.status).toBe(401);
    expect(events[0]!.reason).toBe("proof_bad_solution"); // coarse reason carries the PoW failure class
  });

  it("401 proof_replay when the challenge was already consumed (single-use, PW2)", async () => {
    const events: { reason: string }[] = [];
    const r = await handleProvision(
      powReq(),
      makeDeps({ verifyProofOfWork: okPow, consumeChallenge: () => false, onSecurityEvent: (e) => events.push(e) }),
    );
    expect(r.status).toBe(401);
    expect(events[0]!.reason).toBe("proof_replay");
  });

  it("checks PoW AFTER the ceiling — a 429 short-circuits before verifyProofOfWork", async () => {
    const verifyProofOfWork = vi.fn(okPow);
    const r = await handleProvision(powReq(), makeDeps({ gate: { allow: () => false }, verifyProofOfWork }));
    expect(r.status).toBe(429);
    expect(verifyProofOfWork).not.toHaveBeenCalled();
  });

  it("PoW is OFF when unconfigured — mints without any solution (mobile/App-Check path unchanged)", async () => {
    const r = await handleProvision(req(), makeDeps()); // no verifyProofOfWork
    expect(r.status).toBe(201);
  });
});

describe("handleProvision — size cap", () => {
  it("413 on an oversized body before anything else (no attestation/gen)", async () => {
    const verifyAttestation = vi.fn(() => true);
    const r = await handleProvision(
      req({ rawBody: "x".repeat(MAX_PROVISION_BODY_BYTES + 1) }),
      makeDeps({ verifyAttestation }),
    );
    expect(r.status).toBe(413);
    expect(verifyAttestation).not.toHaveBeenCalled();
  });
});

describe("handleProvision — persistence", () => {
  it("regenerates a fresh id on collision ('exists'), then succeeds", async () => {
    const create = vi.fn()
      .mockResolvedValueOnce("exists" as ProvisionPersistResult)
      .mockResolvedValueOnce("created" as ProvisionPersistResult);
    const ids = ["inst_dup0", "inst_new1"];
    let i = 0;
    const r = await handleProvision(req(), makeDeps({
      generateClientId: () => ids[i++]!,
      keyProvisioner: { create },
    }));
    expect(r.status).toBe(201);
    expect((r.body as { client_id: string }).client_id).toBe("inst_new1");
    expect(create).toHaveBeenCalledTimes(2);
  });

  it("500 after exhausting id attempts (collision storm / broken generator)", async () => {
    const create = vi.fn(async () => "exists" as ProvisionPersistResult);
    const r = await handleProvision(req(), makeDeps({ keyProvisioner: { create }, maxIdAttempts: 3 }));
    expect(r.status).toBe(500);
    expect(create).toHaveBeenCalledTimes(3);
  });

  it("skips a generator that emits a malformed id, never persisting it (no bad key issued)", async () => {
    const create = vi.fn(async () => "created" as ProvisionPersistResult);
    const ids = ["bad id with spaces", "../evil", "inst_good"];
    let i = 0;
    const r = await handleProvision(req(), makeDeps({
      generateClientId: () => ids[i++]!,
      keyProvisioner: { create },
    }));
    expect(r.status).toBe(201);
    expect(create).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenCalledWith("inst_good", expect.any(String));
  });

  it("503 (retryable) when the provisioner reports a TRANSIENT fault — never an opaque/duplicate mint", async () => {
    const create = vi.fn(async () => { throw new KeyStoreUnavailableError(); });
    const r = await handleProvision(req(), makeDeps({ keyProvisioner: { create } }));
    expect(r.status).toBe(503);
    expect(r.body).toEqual({ error: "unavailable" });
  });

  it("an UNEXPECTED persist error bubbles out (→ wrapper opaque 500), not a 503", async () => {
    const create = vi.fn(async () => { throw new Error("boom"); });
    await expect(handleProvision(req(), makeDeps({ keyProvisioner: { create } }))).rejects.toThrow("boom");
  });
});

describe("handleProvision — DERIVED key model (DK4 / A3)", () => {
  // derived deps: NO keyProvisioner; deriveKey returns the per-client_id derived key.
  function derivedDeps(over: Partial<ProvisionDeps> = {}): ProvisionDeps {
    let n = 0;
    return {
      now: () => 1_700_000_000_000,
      verifyAttestation: () => true,
      gate: { allow: () => true },
      generateClientId: () => `inst_${(n++).toString().padStart(4, "0")}`,
      generateKey: () => "UNUSED",
      deriveKey: (id) => `derived(${id})`,
      ...over,
    };
  }

  it("returns the DERIVED key for the issued client_id and stores nothing (no keyProvisioner)", async () => {
    const deriveKey = vi.fn((id: string) => `derived(${id})`);
    const r = await handleProvision(req(), derivedDeps({ deriveKey }));
    expect(r.status).toBe(201);
    const body = r.body as { client_id: string; key: string };
    expect(CLIENT_ID_KEY_PATTERN.test(body.client_id)).toBe(true);
    expect(body.key).toBe(`derived(${body.client_id})`);
    expect(deriveKey).toHaveBeenCalledWith(body.client_id);
  });

  it("emits the A2 mint audit event (PII-free) and never generateKey/createSecret", async () => {
    const generateKey = vi.fn(() => "x");
    const events: { outcome: string }[] = [];
    const r = await handleProvision(req(), derivedDeps({ generateKey, onSecurityEvent: (e) => events.push(e) }));
    expect(r.status).toBe(201);
    expect(generateKey).not.toHaveBeenCalled(); // derived model doesn't generate a random key
    expect(events.some((e) => e.outcome === "minted")).toBe(true);
  });

  it("503 (retryable) when deriveKey throws KeyStoreUnavailableError (root-key fault)", async () => {
    const r = await handleProvision(req(), derivedDeps({ deriveKey: () => { throw new KeyStoreUnavailableError(); } }));
    expect(r.status).toBe(503);
    expect(r.body).toEqual({ error: "unavailable" });
  });

  it("still enforces attestation + ceiling before deriving", async () => {
    const deriveKey = vi.fn((id: string) => `derived(${id})`);
    expect((await handleProvision(req(), derivedDeps({ deriveKey, verifyAttestation: () => false }))).status).toBe(401);
    expect((await handleProvision(req(), derivedDeps({ deriveKey, gate: { allow: () => false } }))).status).toBe(429);
    expect(deriveKey).not.toHaveBeenCalled();
  });

  it("500 (misconfig) when NEITHER deriveKey nor keyProvisioner is set", async () => {
    const deps = derivedDeps();
    delete (deps as { deriveKey?: unknown }).deriveKey;
    const r = await handleProvision(req(), deps);
    expect(r.status).toBe(500);
  });
});

describe("handleProvision — hygiene", () => {
  it("never leaks the minted key into a security event (PII/secret-free F5)", async () => {
    const events: unknown[] = [];
    const onSecurityEvent = (e: unknown) => events.push(e);
    // force a rejected path that emits an event
    await handleProvision(req(), makeDeps({ gate: { allow: () => false }, onSecurityEvent }));
    const serialized = JSON.stringify(events);
    expect(serialized).not.toMatch(/k_AAAA/); // the fixture key must not appear
    expect(serialized).not.toContain("203.0.113.7"); // nor the IP
    expect(events[0]).toEqual({ outcome: "rejected", status: 429, reason: "mint_ceiling" });
  });

  it("A2: emits a PII-free mint-success audit event on the 201 path (no client_id/key/ip/token)", async () => {
    const events: { outcome: string; status: number; reason: string }[] = [];
    const r = await handleProvision(req(), makeDeps({ onSecurityEvent: (e) => events.push(e) }));
    expect(r.status).toBe(201);
    const minted = events.find((e) => e.outcome === "minted");
    expect(minted).toEqual({ outcome: "minted", status: 201, reason: "key_minted" });
    // the event must carry ONLY those three coarse fields — no leaked credential / IP / token.
    expect(Object.keys(minted!).sort()).toEqual(["outcome", "reason", "status"]);
    const serialized = JSON.stringify(events);
    const body = r.body as { client_id: string; key: string };
    expect(serialized).not.toContain(body.client_id);
    expect(serialized).not.toContain(body.key);
    expect(serialized).not.toContain("203.0.113.7"); // ip
    expect(serialized).not.toContain("att-tok"); // attestation token
  });

  it("A2: does NOT emit a mint event when no key is issued (e.g. a 429 reject)", async () => {
    const events: { outcome: string }[] = [];
    await handleProvision(req(), makeDeps({ gate: { allow: () => false }, onSecurityEvent: (e) => events.push(e) }));
    expect(events.some((e) => e.outcome === "minted")).toBe(false);
  });
});

describe("handleProvision — Steam entitlement gate (A4)", () => {
  it("mints (201) with a valid entitlement token", async () => {
    const verifyEntitlement = vi.fn(() => true);
    const r = await handleProvision(req({ entitlementToken: "ticket" }), makeDeps({ verifyEntitlement }));
    expect(r.status).toBe(201);
    expect(verifyEntitlement).toHaveBeenCalledWith("ticket");
  });

  it("401 entitlement_required when configured but no token is present", async () => {
    const events: { reason: string }[] = [];
    const r = await handleProvision(req(), makeDeps({ verifyEntitlement: () => true, onSecurityEvent: (e) => events.push(e) }));
    expect(r.status).toBe(401);
    expect(events[0]!.reason).toBe("entitlement_required");
  });

  it("401 entitlement_failed when ownership is not confirmed", async () => {
    const r = await handleProvision(req({ entitlementToken: "t" }), makeDeps({ verifyEntitlement: () => false }));
    expect(r.status).toBe(401);
  });

  it("401 (fail closed) when the entitlement verifier THROWS — never mints on a Steam API error", async () => {
    const create = vi.fn(async () => "created" as ProvisionPersistResult);
    const r = await handleProvision(
      req({ entitlementToken: "t" }),
      makeDeps({ verifyEntitlement: () => { throw new Error("steam down"); }, keyProvisioner: { create } }),
    );
    expect(r.status).toBe(401);
    expect(create).not.toHaveBeenCalled();
  });

  it("a FAILED entitlement does NOT consume the PoW challenge (consume only after every proof passes)", async () => {
    const consumeChallenge = vi.fn(() => true);
    const r = await handleProvision(
      req({ pow: { challenge: "cid1.9.20", sig: "s", nonce: "n" }, entitlementToken: "t" }),
      makeDeps({
        verifyProofOfWork: () => ({ ok: true, challengeId: "cid1", difficulty: 20 }),
        consumeChallenge,
        verifyEntitlement: () => false,
      }),
    );
    expect(r.status).toBe(401);
    expect(consumeChallenge).not.toHaveBeenCalled(); // challenge not burned by an entitlement failure
  });

  it("entitlement is OFF when unconfigured (mints without a token)", async () => {
    const r = await handleProvision(req(), makeDeps());
    expect(r.status).toBe(201);
  });
});
