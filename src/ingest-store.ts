/**
 * Shared-store rate limiter + replay nonce cache (D-STORE).
 *
 * The in-memory limiter/nonce in `ingest-adapter.ts` are per-instance — at >1 Cloud Function instance
 * they enforce the rate limit ~N× too weakly and a nonce recorded on instance A is invisible to B
 * (replay protection breaks across instances). SEC's pre-public-traffic condition: back both with a
 * SHARED store before opening to `allUsers`. These impls satisfy the async `RateLimiter`/`ReplayCache`
 * interfaces over an injected `SharedStore` — a thin Firestore/Redis adapter (real GCP only at deploy,
 * Owner-GO); the pure core imports no SDK and is tested against an in-memory fake.
 */

import type { RateLimiter, ReplayCache } from "./ingest.js";

/**
 * The minimal atomic operations a shared store must provide. A Firestore adapter implements
 * `increment` via a transaction (read-add-write) and `claim`/`has` via document existence with a TTL
 * field (Firestore TTL policy reaps expired docs). Keys are opaque strings; values are short-lived.
 */
export interface SharedStore {
  /** Atomically +1 the counter at `key` (creating it; the slot expires after `ttlMs`) → the new total. */
  increment(key: string, ttlMs: number): Promise<number>;
  /** True if `key` is currently present (not past its expiry). */
  has(key: string): Promise<boolean>;
  /** Set `key`, expiring at `expiresAtMs` (epoch ms). */
  set(key: string, expiresAtMs: number): Promise<void>;
}

export interface SharedRateLimitOptions {
  now: () => number;
  windowMs?: number; // default 5 min
  perClient?: number; // default 60
  perIp?: number; // default 600
  globalCeiling?: number; // default 6000 — caps even authenticated traffic (AD4)
}

/**
 * Fixed-window limiter over a SHARED counter store, so all instances enforce ONE budget. The window
 * bucket is encoded in the key (`…:<windowStart>`) and each slot self-expires after `windowMs`, so no
 * eviction sweep is needed. On a store outage (an `increment` rejects), unauth fails CLOSED and auth
 * fails OPEN (§5.4) — an outage can't drop real data, and can't be ridden into unbounded cost beyond
 * its duration.
 */
export function createSharedRateLimiter(
  store: SharedStore,
  opts: SharedRateLimitOptions,
): RateLimiter {
  const windowMs = opts.windowMs ?? 5 * 60 * 1000;
  const perClient = opts.perClient ?? 60;
  const perIp = opts.perIp ?? 600;
  const ceiling = opts.globalCeiling ?? 6000;
  return {
    async allow(clientId, ip, authenticated) {
      const w = Math.floor(opts.now() / windowMs) * windowMs;
      try {
        const [g, c, i] = await Promise.all([
          store.increment(`rl:global:${w}`, windowMs),
          store.increment(`rl:c:${clientId}:${w}`, windowMs),
          store.increment(`rl:ip:${ip ?? "?"}:${w}`, windowMs),
        ]);
        return g <= ceiling && c <= perClient && i <= perIp;
      } catch {
        return authenticated; // store outage: unauth CLOSED (false), auth OPEN (true)
      }
    },
  };
}

/**
 * Replay nonce cache over the SHARED store: `seen` = `has`, `record` = `set`. This makes the nonce
 * cross-instance correct — a sig recorded by any instance is visible to all (closing SEC's D-STORE
 * gap). RESIDUAL: the seen→record flow is two ops, so two instances could `seen()` the same fresh sig
 * simultaneously before either `record`s it (a single duplicate slips through). Bounded and benign vs.
 * the cross-instance break it replaces; an atomic single-op `checkAndRecord` is the strict follow-up
 * (an endpoint-interface change — flagged for SEC, not in this slice).
 */
export function createSharedReplayCache(store: SharedStore): ReplayCache {
  return {
    seen: (sig) => store.has(`nonce:${sig}`),
    record: (sig, expiresAtMs) => store.set(`nonce:${sig}`, expiresAtMs),
  };
}
