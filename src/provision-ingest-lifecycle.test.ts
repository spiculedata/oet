/**
 * QA — C9 lifecycle: a PROVISIONED per-install key actually works for ingestion (end-to-end).
 *
 * DEV's provision.test.ts exhaustively covers the /provision endpoint in isolation. This suite closes the
 * loop that is the whole point of GL3+PROVISION: a client with NO embedded secret calls /provision, gets a
 * fresh `{client_id, key}`, and that credential then verifies at /ingest — while a non-provisioned key does
 * NOT. Provisioner and ingest key store are backed by ONE map (models Secret Manager), so this proves the
 * mint→sign→verify chain hangs together. Mocks only; real minting/SM wiring is the deferred RP1–RP6 gate.
 */
import { describe, it, expect } from "vitest";
import {
  handleProvision,
  makeHmacVerifier,
  makeHmacSigner,
  createIngestHttpHandler,
  createInMemoryRateLimiter,
  createInMemoryReplayCache,
  makeBqInsert,
  type ProvisionDeps,
  type Ga4Row,
} from "./index.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;

/** One in-memory key map = the shared Secret-Manager stand-in: /provision writes it, /ingest reads it. */
function keyMap() {
  const m = new Map<string, string>();
  return {
    provisioner: { async create(id: string, key: string) { if (m.has(id)) return "exists" as const; m.set(id, key); return "created" as const; } },
    getSecret: (body: Record<string, unknown>) => (typeof body.client_id === "string" ? m.get(body.client_id) : undefined),
  };
}

function provisionDeps(over: Partial<ProvisionDeps>): ProvisionDeps {
  return {
    now: () => NOW,
    verifyAttestation: () => true,
    gate: { allow: () => true },
    generateClientId: () => "prov-abc123",
    generateKey: () => "provisioned-secret-256bit",
    keyProvisioner: { async create() { return "created"; } },
    ...over,
  };
}

/** An ingest handler whose HMAC secret is resolved per-client_id from the same map. */
function ingestHandler(getSecret: (b: Record<string, unknown>) => string | undefined, written: Ga4Row[]) {
  return createIngestHttpHandler({
    now: () => NOW,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: makeHmacVerifier(getSecret),
    rateLimiter: createInMemoryRateLimiter({ now: () => NOW }),
    replayCache: createInMemoryReplayCache(() => NOW),
    deriveGeo: () => null,
    bqInsert: makeBqInsert({ insertRows: async (rows) => { written.push(...rows); } }),
  });
}

function envelope(clientId: string) {
  return { client_id: clientId, user_id: null, platform: "windows", app_version: "2.0.0", consent: true, sent_at: new Date(NOW).toISOString(), events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }] };
}

describe("C9 lifecycle — provision → sign → ingest", () => {
  it("a freshly-provisioned key verifies at /ingest (the whole point of per-install keying)", async () => {
    const ks = keyMap();
    // 1) provision: no embedded secret → mint a per-install credential.
    const prov = await handleProvision({ rawBody: "{}", ip: "1.2.3.4", attestationToken: "good" }, provisionDeps({ keyProvisioner: ks.provisioner }));
    expect(prov.status).toBe(201);
    const cred = prov.body as { client_id: string; key: string };
    expect(cred.client_id).toBe("prov-abc123");

    // 2) sign an envelope with the PROVISIONED key + id, 3) POST to /ingest → verified, written.
    const written: Ga4Row[] = [];
    const env = { ...envelope(cred.client_id), sig: makeHmacSigner(cred.key)(envelope(cred.client_id)) };
    const r = await ingestHandler(ks.getSecret, written)({ headers: {}, rawBody: JSON.stringify(env), ip: "1.2.3.4" });
    expect(r.status).toBe(202);
    expect(written).toHaveLength(1);
    expect(written[0]!.user_pseudo_id).toBe("prov-abc123");
  });

  it("a NON-provisioned client_id is rejected 401 at /ingest (no key in the store)", async () => {
    const ks = keyMap(); // empty — nothing provisioned
    const written: Ga4Row[] = [];
    const env = { ...envelope("prov-never-minted"), sig: makeHmacSigner("some-key")(envelope("prov-never-minted")) };
    const r = await ingestHandler(ks.getSecret, written)({ headers: {}, rawBody: JSON.stringify(env), ip: "1.2.3.4" });
    expect(r.status).toBe(401); // getSecret → undefined → fail closed
    expect(written).toHaveLength(0);
  });

  it("a provisioned id but WRONG key fails 401 (the stored key must match the signature)", async () => {
    const ks = keyMap();
    await handleProvision({ rawBody: "{}", ip: "1.2.3.4", attestationToken: "good" }, provisionDeps({ keyProvisioner: ks.provisioner }));
    const written: Ga4Row[] = [];
    // sign with a different key than the one provisioned for prov-abc123
    const env = { ...envelope("prov-abc123"), sig: makeHmacSigner("attacker-guess")(envelope("prov-abc123")) };
    const r = await ingestHandler(ks.getSecret, written)({ headers: {}, rawBody: JSON.stringify(env), ip: "1.2.3.4" });
    expect(r.status).toBe(401);
    expect(written).toHaveLength(0);
  });
});
