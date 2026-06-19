/**
 * QA — D-STORE cross-instance correctness THROUGH the real endpoint (Spec §5.4; D-STORE + D-STORE-CAS).
 *
 * DEV's ingest-store.test.ts proves the shared limiter/cache (and the atomic `checkAndRecord`) at the
 * unit level. This suite proves it in situ: wired into the REAL `handleIngest`, a replay that lands on a
 * DIFFERENT instance is caught, the rate budget is shared, and — with HARDEN-PUBLIC s1's atomic
 * `checkAndRecord` — two CONCURRENT identical-sig requests across instances resolve to exactly one accept
 * (the F-DSTORE-RACE TOCTOU is closed, not just bounded). Mocks only; real GCP waits for Owner-GO.
 */
import { describe, it, expect } from "vitest";
import {
  handleIngest,
  makeHmacVerifier,
  makeHmacSigner,
  createSharedRateLimiter,
  createSharedReplayCache,
  createInMemoryRateLimiter,
  makeBqInsert,
  type SharedStore,
  type IngestDeps,
  type Ga4Row,
} from "./index.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;
const SECRET = "shared-app-secret";

/** In-memory fake of a shared Firestore/Redis store with a controllable clock. `claim` is atomic. */
function fakeStore(now: () => number): SharedStore {
  const counters = new Map<string, { n: number; exp: number }>();
  const claims = new Map<string, number>();
  return {
    async increment(key, ttlMs) {
      const t = now();
      let c = counters.get(key);
      if (!c || c.exp <= t) c = { n: 0, exp: t + ttlMs };
      c.n += 1; counters.set(key, c); return c.n;
    },
    // Atomic create-if-absent (models Firestore doc create fail-if-exists): true iff newly claimed.
    async claim(key, expiresAtMs) {
      const e = claims.get(key);
      if (e !== undefined && e > now()) return false;
      claims.set(key, expiresAtMs);
      return true;
    },
  };
}

const sign = makeHmacSigner(SECRET);
function signedBody(): string {
  const env: Record<string, unknown> = {
    client_id: "win-1", user_id: null, platform: "windows", app_version: "2.0.0",
    consent: true, sent_at: new Date(NOW).toISOString(),
    events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }],
  };
  env.sig = sign(env);
  return JSON.stringify(env);
}

/** Deps for one "Cloud Function instance" sharing `store`; collects written rows. */
function instance(store: SharedStore, written: Ga4Row[]): IngestDeps {
  return {
    now: () => NOW,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: makeHmacVerifier(() => SECRET),
    rateLimiter: createSharedRateLimiter(store, { now: () => NOW }),
    replayCache: createSharedReplayCache(store),
    deriveGeo: () => null,
    bqInsert: makeBqInsert({ insertRows: async (rows) => { written.push(...rows); } }),
  };
}

describe("D-STORE end-to-end — cross-instance replay caught via handleIngest", () => {
  it("a replay landing on a DIFFERENT instance is rejected 401 (shared nonce), no double-write", async () => {
    const store = fakeStore(() => NOW);
    const written: Ga4Row[] = [];
    const body = signedBody();
    const a = await handleIngest({ rawBody: body, ip: "1.2.3.4" }, instance(store, written));
    expect(a.status).toBe(202);
    expect(written).toHaveLength(1);
    // Same signed bytes replayed to instance B → caught via the shared atomic claim (per-instance couldn't).
    const b = await handleIngest({ rawBody: body, ip: "1.2.3.4" }, instance(store, written));
    expect(b.status).toBe(401);
    expect(written).toHaveLength(1);
  });

  it("the rate budget is shared across instances (not inflated per instance)", async () => {
    const store = fakeStore(() => NOW);
    const written: Ga4Row[] = [];
    const mk = () => createSharedRateLimiter(store, { now: () => NOW, perClient: 2 });
    const dep = (rl: ReturnType<typeof mk>): IngestDeps => ({ ...instance(store, written), rateLimiter: rl, replayCache: { checkAndRecord: async () => true } });
    expect((await handleIngest({ rawBody: signedBody(), ip: "a" }, dep(mk()))).status).toBe(202); // 1
    expect((await handleIngest({ rawBody: signedBody(), ip: "b" }, dep(mk()))).status).toBe(202); // 2
    expect((await handleIngest({ rawBody: signedBody(), ip: "c" }, dep(mk()))).status).toBe(429); // 3rd → over SHARED budget
  });
});

describe("D-STORE — sanity: in-mem (per-instance) nonce does NOT catch the cross-instance replay", () => {
  it("two per-instance caches each accept the same sig (why the shared store is needed)", async () => {
    const written: Ga4Row[] = [];
    const body = signedBody();
    const perInstance = (): IngestDeps => ({
      now: () => NOW, allowlist: DEFAULT_ALLOWLIST, verifyHmac: makeHmacVerifier(() => SECRET),
      rateLimiter: createInMemoryRateLimiter({ now: () => NOW }),
      replayCache: { checkAndRecord: () => true }, // fresh per-instance cache always accepts
      deriveGeo: () => null, bqInsert: makeBqInsert({ insertRows: async (r) => { written.push(...r); } }),
    });
    expect((await handleIngest({ rawBody: body, ip: "x" }, perInstance())).status).toBe(202);
    expect((await handleIngest({ rawBody: body, ip: "x" }, perInstance())).status).toBe(202); // replay slips → the gap the shared store closes
    expect(written).toHaveLength(2);
  });
});

describe("D-STORE-CAS — [F-DSTORE-RACE CLOSED] atomic checkAndRecord, no double-accept under concurrency", () => {
  it("two instances concurrently claiming the same fresh sig → EXACTLY ONE true (was: both miss)", async () => {
    const store = fakeStore(() => NOW);
    const a = createSharedReplayCache(store);
    const b = createSharedReplayCache(store);
    const [ra, rb] = await Promise.all([
      a.checkAndRecord("sig-z", NOW + 5 * 60_000),
      b.checkAndRecord("sig-z", NOW + 5 * 60_000),
    ]);
    expect([ra, rb].filter(Boolean)).toHaveLength(1); // the TOCTOU is gone — one accept, one replay-reject
  });

  it("end-to-end: two concurrent identical-sig requests across instances → exactly one 202, one 401, one row", async () => {
    const store = fakeStore(() => NOW);
    const written: Ga4Row[] = [];
    const body = signedBody();
    const [ra, rb] = await Promise.all([
      handleIngest({ rawBody: body, ip: "1.2.3.4" }, instance(store, written)),
      handleIngest({ rawBody: body, ip: "1.2.3.4" }, instance(store, written)),
    ]);
    expect([ra.status, rb.status].sort()).toEqual([202, 401]); // exactly one accepted
    expect(written).toHaveLength(1); // no cross-instance double-write
  });
});
