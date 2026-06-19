import { describe, it, expect } from "vitest";
import {
  createSharedRateLimiter,
  createSharedReplayCache,
  type SharedStore,
} from "./ingest-store.js";

/**
 * A fake of a shared store (Firestore/Redis) backed by one in-memory map, with a controllable clock.
 * Two limiters/caches built over the SAME fake model two Cloud Function instances sharing one store.
 */
function fakeStore(now: () => number): SharedStore {
  const counters = new Map<string, { n: number; exp: number }>();
  const nonces = new Map<string, number>();
  return {
    async increment(key, ttlMs) {
      const t = now();
      let c = counters.get(key);
      if (!c || c.exp <= t) c = { n: 0, exp: t + ttlMs };
      c.n += 1;
      counters.set(key, c);
      return c.n;
    },
    async claim(key, expiresAtMs) {
      const exp = nonces.get(key);
      if (exp !== undefined && exp > now()) return false; // already claimed (present) → not fresh
      nonces.set(key, expiresAtMs);
      return true; // newly claimed
    },
  };
}

describe("createSharedRateLimiter — one budget across instances (D-STORE)", () => {
  it("two instances sharing a store jointly enforce the per-client limit", async () => {
    const store = fakeStore(() => 0);
    const a = createSharedRateLimiter(store, { now: () => 0, perClient: 2, perIp: 100 });
    const b = createSharedRateLimiter(store, { now: () => 0, perClient: 2, perIp: 100 });
    expect(await a.allow("c1", "ip1", true)).toBe(true); // 1 (via instance A)
    expect(await b.allow("c1", "ip2", true)).toBe(true); // 2 (via instance B, same client)
    expect(await a.allow("c1", "ip3", true)).toBe(false); // 3rd across instances → over
  });

  it("resets in the next window", async () => {
    let t = 0;
    const store = fakeStore(() => t);
    const rl = createSharedRateLimiter(store, { now: () => t, perClient: 1, windowMs: 1000 });
    expect(await rl.allow("c1", "ip1", true)).toBe(true);
    expect(await rl.allow("c1", "ip1", true)).toBe(false);
    t += 1000; // new window
    expect(await rl.allow("c1", "ip1", true)).toBe(true);
  });

  it("on store outage: unauth fails CLOSED, auth fails OPEN", async () => {
    const broken: SharedStore = {
      increment: async () => { throw new Error("firestore down"); },
      claim: async () => true,
    };
    const rl = createSharedRateLimiter(broken, { now: () => 0 });
    expect(await rl.allow("c1", "ip1", false)).toBe(false); // unauth → closed
    expect(await rl.allow("c1", "ip1", true)).toBe(true); // auth → open
  });
});

describe("createSharedReplayCache — atomic + cross-instance (D-STORE / D-STORE-CAS)", () => {
  it("a sig claimed by one instance is a replay for another (cross-instance), and expires", async () => {
    let t = 1000;
    const store = fakeStore(() => t);
    const a = createSharedReplayCache(store);
    const b = createSharedReplayCache(store);
    expect(await a.checkAndRecord("sig-1", t + 5 * 60 * 1000)).toBe(true); // instance A: fresh
    expect(await b.checkAndRecord("sig-1", t + 5 * 60 * 1000)).toBe(false); // instance B: replay
    t += 5 * 60 * 1000 + 1; // past the anchored expiry
    expect(await b.checkAndRecord("sig-1", t + 5 * 60 * 1000)).toBe(true); // forgotten → fresh again
  });

  it("D-STORE-CAS: two concurrent identical-sig claims across instances ⇒ EXACTLY ONE accepted", async () => {
    const store = fakeStore(() => 0);
    const a = createSharedReplayCache(store);
    const b = createSharedReplayCache(store);
    const [ra, rb] = await Promise.all([
      a.checkAndRecord("sig-X", 5 * 60 * 1000),
      b.checkAndRecord("sig-X", 5 * 60 * 1000),
    ]);
    expect([ra, rb].filter(Boolean)).toHaveLength(1); // no double-accept (closes F-DSTORE-RACE)
  });
});
