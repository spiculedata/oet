/**
 * Firestore-backed `SharedStore` (HARDEN-PUBLIC s2) — the concrete shared store behind the rate
 * limiter + replay nonce so they're correct across >1 Cloud Function instance.
 *
 * Both ops are atomic via Firestore transactions:
 *  - `claim` (nonce): a single atomic `create` (fail-if-exists, per SEC) → exactly one of two concurrent
 *    identical claims wins (D-STORE-CAS); the other gets ALREADY_EXISTS → false. Doc id = sha256(key)
 *    (Firestore ids forbid '/'). An expired sig is never legitimately re-claimed (freshness §5.4 rejects a
 *    stale `sent_at` BEFORE the nonce), so a lingering expired doc never blocks real traffic; the TTL
 *    policy on `expiresAt` reclaims storage.
 *  - `increment` (limiter): a transaction read-modify-write that resets the counter once its window
 *    has elapsed → one shared budget across instances.
 *
 * Storage hygiene: every doc carries an `expiresAt` Timestamp. Set a Firestore **TTL policy** on that
 * field for each collection so expired nonces/counters self-delete (see deploy/RUNBOOK.md) — TTL only
 * reclaims storage; correctness comes from the in-transaction expiry check, not from the reaper.
 */
import { createHash } from "node:crypto";
import { Timestamp, type Firestore } from "firebase-admin/firestore";
import type { SharedStore } from "oet";

const NONCES = "oet_nonces";
const COUNTERS = "oet_counters";

/** Firestore doc ids can't contain '/'; hash the opaque key to a safe fixed-length id. */
const docId = (key: string): string => createHash("sha256").update(key).digest("hex");

export function createFirestoreSharedStore(db: Firestore): SharedStore {
  return {
    async claim(key, expiresAtMs) {
      // Atomic create-if-absent (SEC-binding): NOT a read-then-write. Two concurrent identical claims
      // both call create(); Firestore lets exactly one succeed, the other throws ALREADY_EXISTS (code 6).
      try {
        await db.collection(NONCES).doc(docId(key)).create({ expiresAt: Timestamp.fromMillis(expiresAtMs) });
        return true; // we created it → fresh
      } catch (e) {
        if ((e as { code?: number }).code === 6) return false; // ALREADY_EXISTS → replay
        throw e;
      }
    },
    async increment(key, ttlMs) {
      const ref = db.collection(COUNTERS).doc(docId(key));
      return db.runTransaction(async (tx) => {
        const snap = await tx.get(ref);
        const now = Date.now();
        const exp = snap.get("expiresAt") as Timestamp | undefined;
        const fresh = exp !== undefined && exp.toMillis() > now;
        const count = (fresh ? ((snap.get("count") as number) ?? 0) : 0) + 1;
        tx.set(ref, {
          count,
          expiresAt: fresh ? exp! : Timestamp.fromMillis(now + ttlMs),
        });
        return count;
      });
    },
  };
}
