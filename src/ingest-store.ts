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
import type { ProvisionGate } from "./provision.js";

/**
 * The minimal atomic operations a shared store must provide. A Firestore adapter implements
 * `increment` via a transaction (read-add-write) and `claim`/`has` via document existence with a TTL
 * field (Firestore TTL policy reaps expired docs). Keys are opaque strings; values are short-lived.
 */
export interface SharedStore {
  /** Atomically +1 the counter at `key` (creating it; the slot expires after `ttlMs`) → the new total. */
  increment(key: string, ttlMs: number): Promise<number>;
  /**
   * ATOMICALLY claim `key`: true if it was newly created (not present), false if it already existed.
   * Expires at `expiresAtMs`. The Firestore impl is a document `create` (fail-if-exists) — a single
   * atomic op, so two concurrent claims of the same key resolve to exactly one `true` (D-STORE-CAS).
   */
  claim(key: string, expiresAtMs: number): Promise<boolean>;
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
 * Replay nonce cache over the SHARED store: `checkAndRecord` = the store's atomic `claim`. Cross-
 * instance correct AND race-free — two instances claiming the same fresh sig concurrently resolve to
 * exactly one `true` (the other gets `false` → 401). Closes both SEC's cross-instance gap (D-STORE)
 * and the seen→record TOCTOU (D-STORE-CAS).
 */
export function createSharedReplayCache(store: SharedStore): ReplayCache {
  return {
    checkAndRecord: (sig, expiresAtMs) => store.claim(`nonce:${sig}`, expiresAtMs),
  };
}

export interface SharedProvisionGateOptions {
  now: () => number;
  windowMs?: number; // default 1 h
  perIp?: number; // default 5 mints / IP / window
  globalCeiling?: number; // default 1000 mints / window — hard cost cap across all instances
  /**
   * Counter-key namespace (default `"pv"`). Use a distinct prefix to run an INDEPENDENT gate budget —
   * e.g. `"pvc"` for the `GET /provision` challenge endpoint (PW-GET-FLOOD), so challenge-issuance flooding
   * is bounded separately from (and doesn't consume) the mint ceiling.
   */
  keyPrefix?: string;
}

/**
 * RP4 — the `/provision` mint ceiling over the SHARED counter store, so every instance enforces ONE
 * budget (an attacker can't fan out across instances to multiply their mints). Per-IP AND a global
 * ceiling, fixed-window (the window is in the key; each slot self-expires). Unlike the ingest limiter
 * this **fails CLOSED on a store outage** — minting writes to a paid store and is never load-bearing for
 * real telemetry, so when the gate can't be evaluated we simply don't mint (deny). Defaults are
 * deliberately tight: provisioning is a rare first-run event, not steady traffic.
 */
export function createSharedProvisionGate(
  store: SharedStore,
  opts: SharedProvisionGateOptions,
): ProvisionGate {
  const windowMs = opts.windowMs ?? 60 * 60 * 1000;
  const perIp = opts.perIp ?? 5;
  const ceiling = opts.globalCeiling ?? 1000;
  const p = opts.keyPrefix ?? "pv";
  return {
    async allow(ip) {
      const w = Math.floor(opts.now() / windowMs) * windowMs;
      try {
        const [g, i] = await Promise.all([
          store.increment(`${p}:global:${w}`, windowMs),
          store.increment(`${p}:ip:${ip ?? "?"}:${w}`, windowMs),
        ]);
        return g <= ceiling && i <= perIp;
      } catch {
        return false; // store outage → fail CLOSED (never mint on an unverifiable ceiling)
      }
    },
  };
}
