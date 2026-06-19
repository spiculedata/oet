/**
 * DK2 (audit #2 A3) — Firestore-backed **revocation deny-list** for the derived-key model.
 *
 * Derived keys can't be deleted (they're recomputable from the root), so per-install revocation is a
 * deny-list of revoked `client_id`s checked at verify. An install is revoked by writing a doc
 * `oet_revoked/<sha256(client_id)>`; the verifier treats a listed id as keyless (→ 401).
 *
 * Fail-closed (DK2): a Firestore fault throws `KeyStoreUnavailableError` → the ingest core returns a
 * retryable **503**, NOT a silent accept — we must never verify an install whose revocation status we
 * can't confirm. Results are cached in-process (TTL) so the hot path doesn't hit Firestore every request;
 * a "not revoked" answer is cached too, so revoking takes effect within one cache TTL.
 */
import { createHash } from "node:crypto";
import { type Firestore } from "firebase-admin/firestore";
import { KeyStoreUnavailableError, type RevocationList } from "oet";

const REVOKED = "oet_revoked";
const docId = (clientId: string): string => createHash("sha256").update(clientId).digest("hex");

export function createFirestoreRevocationList(
  db: Firestore,
  opts: { now?: () => number; ttlMs?: number } = {},
): RevocationList {
  const now = opts.now ?? Date.now;
  const ttlMs = opts.ttlMs ?? 60_000; // 1 min — revocation visible within this window
  const cache = new Map<string, { revoked: boolean; expiresAtMs: number }>();
  return {
    async isRevoked(clientId) {
      const t = now();
      const hit = cache.get(clientId);
      if (hit && hit.expiresAtMs > t) return hit.revoked;
      let revoked: boolean;
      try {
        const snap = await db.collection(REVOKED).doc(docId(clientId)).get();
        revoked = snap.exists;
      } catch (err) {
        // Fail CLOSED: an unconfirmable revocation status must not be treated as "not revoked".
        throw new KeyStoreUnavailableError(`revocation_list_unavailable:${(err as { code?: number }).code ?? "unknown"}`);
      }
      for (const [k, v] of cache) if (v.expiresAtMs <= t) cache.delete(k);
      cache.set(clientId, { revoked, expiresAtMs: t + ttlMs });
      return revoked;
    },
  };
}
