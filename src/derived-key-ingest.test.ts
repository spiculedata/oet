/**
 * QA — A3 derived keys drop into the existing verifier seam (the design's central claim).
 *
 * DEV's derived-key.test.ts proves the HKDF primitive's crypto properties in isolation. This suite proves
 * the thing A3 is FOR: a key derived via `deriveClientKey(rootKey, client_id)` works as the per-install
 * secret in the unchanged `makeHmacVerifier`/`handleIngest` seam — so the verifier re-derives on the fly
 * with ZERO per-install storage. And it validates the two security pillars SEC named:
 *   · the ROOT key is the crown jewel — a signature made under a different root is rejected (no root ⇒ no forgery);
 *   · keys are per-client (info-bound) — client B can't be authenticated with client A's derived key.
 *
 * Mocks only. The real root-key custody (DK1), deny-list revocation (DK2), rotation (DK3) are deferred —
 * this proves only that the derivation is verifier-compatible, not that the production wiring is built.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  deriveClientKey,
  makeHmacVerifier,
  makeHmacSigner,
  createIngestHttpHandler,
  createInMemoryRateLimiter,
  createInMemoryReplayCache,
  makeBqInsert,
  type Ga4Row,
} from "./index.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;
const ROOT = randomBytes(32); // the single server root key (crown jewel)

/** Ingest handler whose per-install secret is DERIVED on the fly from the root — no key store. */
function server(root: Buffer) {
  const written: Ga4Row[] = [];
  const handler = createIngestHttpHandler({
    now: () => NOW,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: makeHmacVerifier((body) =>
      typeof body.client_id === "string" ? deriveClientKey(body.client_id, root) : undefined,
    ),
    rateLimiter: createInMemoryRateLimiter({ now: () => NOW }),
    replayCache: createInMemoryReplayCache(() => NOW),
    deriveGeo: () => null,
    bqInsert: makeBqInsert({ insertRows: async (rows) => { written.push(...rows); } }),
  });
  return { handler, written };
}

function envelope(clientId: string) {
  return { client_id: clientId, user_id: null, platform: "windows", app_version: "2.0.0", consent: true, sent_at: new Date(NOW).toISOString(), events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }] };
}
const signedWith = (key: string, clientId: string) => ({ ...envelope(clientId), sig: makeHmacSigner(key)(envelope(clientId)) });

describe("A3 derived keys — verifier-compatible, zero per-install storage", () => {
  it("an envelope signed with the install's DERIVED key verifies at /ingest (server re-derives, no store)", async () => {
    const srv = server(ROOT);
    const clientId = "derived-client-1";
    const installKey = deriveClientKey(clientId, ROOT); // provisioned to the install once
    const r = await srv.handler({ headers: {}, rawBody: JSON.stringify(signedWith(installKey, clientId)), ip: "1.2.3.4" });
    expect(r.status).toBe(202);
    expect(srv.written).toHaveLength(1);
    expect(srv.written[0]!.user_pseudo_id).toBe(clientId);
  });

  it("the ROOT is the crown jewel — a key derived from a DIFFERENT root is rejected 401", async () => {
    const srv = server(ROOT);
    const clientId = "derived-client-1";
    const forgedKey = deriveClientKey(clientId, randomBytes(32)); // attacker without the real root
    const r = await srv.handler({ headers: {}, rawBody: JSON.stringify(signedWith(forgedKey, clientId)), ip: "1.2.3.4" });
    expect(r.status).toBe(401);
    expect(srv.written).toHaveLength(0);
  });

  it("keys are per-client (info-bound) — client A's key cannot authenticate client B → 401", async () => {
    const srv = server(ROOT);
    const aKey = deriveClientKey("client-A", ROOT);
    // client-B presents an envelope signed with A's key; the server derives B's (different) key → mismatch.
    const r = await srv.handler({ headers: {}, rawBody: JSON.stringify(signedWith(aKey, "client-B")), ip: "1.2.3.4" });
    expect(r.status).toBe(401);
    expect(srv.written).toHaveLength(0);
  });
});
