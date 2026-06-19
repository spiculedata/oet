/**
 * QA — DK2 revocation enforced END-TO-END at /ingest (the pin I held at the A3 gate).
 *
 * DEV's derived-key.test.ts proves the store-level deny-list (revoked→undefined, outage→503). This suite
 * proves the security guarantee that actually matters: a derived key is RECOMPUTABLE (can't be deleted), so
 * revocation MUST work at verify — a revoked install presenting a perfectly valid derived-key signature is
 * still rejected 401, and a deny-list OUTAGE fails closed (503), never accepts an unconfirmable install.
 *
 * Wires the real `createDerivedKeyStore` (DK1 injected root + DK2 deny-list) into the unchanged
 * `makeHmacVerifier`/`handleIngest` seam. Mocks only; real root/Firestore are deploy (Owner-GO).
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  createDerivedKeyStore,
  createInMemoryRevocationList,
  deriveClientKey,
  makeHmacVerifier,
  makeHmacSigner,
  createIngestHttpHandler,
  createInMemoryRateLimiter,
  createInMemoryReplayCache,
  makeBqInsert,
  KeyStoreUnavailableError,
  type RevocationList,
  type Ga4Row,
} from "./index.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;
const ROOT = randomBytes(32);
const CLIENT = "derived-client-1";

function server(revocationList: RevocationList) {
  const written: Ga4Row[] = [];
  const store = createDerivedKeyStore({ getRootKey: async () => ROOT, revocationList });
  const handler = createIngestHttpHandler({
    now: () => NOW,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: makeHmacVerifier((body) => (typeof body.client_id === "string" ? store.getKey(body.client_id) : undefined)),
    rateLimiter: createInMemoryRateLimiter({ now: () => NOW }),
    replayCache: createInMemoryReplayCache(() => NOW),
    deriveGeo: () => null,
    bqInsert: makeBqInsert({ insertRows: async (rows) => { written.push(...rows); } }),
  });
  return { handler, written };
}

// `nonce` varies the envelope per post so distinct sends aren't replay-rejected (isolating the DK2 check).
function signed(clientId: string, nonce: number) {
  const env = { client_id: clientId, user_id: null, platform: "windows", app_version: "2.0.0", consent: true, sent_at: new Date(NOW).toISOString(), events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z", params: { n: nonce } }] };
  return JSON.stringify({ ...env, sig: makeHmacSigner(deriveClientKey(clientId, ROOT))(env) });
}
let n = 0;
const post = (h: ReturnType<typeof server>["handler"], clientId: string) => h({ headers: {}, rawBody: signed(clientId, n++), ip: "1.2.3.4" });

describe("DK2 — revocation enforced end-to-end at /ingest", () => {
  it("revoking a client makes its OWN valid derived signature → 401; restoring re-accepts it", async () => {
    const deny = createInMemoryRevocationList();
    const srv = server(deny);

    expect((await post(srv.handler, CLIENT)).status).toBe(202); // active install verifies

    deny.revoke(CLIENT); // revoked — but the derived key is unchanged/recomputable
    const revoked = await post(srv.handler, CLIENT);
    expect(revoked.status).toBe(401); // …still rejected: revocation works at verify (the DK2 point)
    expect(srv.written).toHaveLength(1); // nothing new written

    deny.restore(CLIENT);
    expect((await post(srv.handler, CLIENT)).status).toBe(202); // re-accepted after restore
  });

  it("a deny-list OUTAGE fails CLOSED → 503 (never accepts an install whose revocation can't be confirmed)", async () => {
    const flaky: RevocationList = { isRevoked: () => { throw new KeyStoreUnavailableError("denylist_down"); } };
    const srv = server(flaky);
    const r = await post(srv.handler, CLIENT);
    expect(r.status).toBe(503); // retryable, not a 202 and not a 401
    expect(srv.written).toHaveLength(0);
  });
});
