/**
 * A3 (audit #2) — derived per-install keys (PROPOSED; SEC design gate).
 *
 * The GL3 model stores one Secret-Manager secret PER install (`oet-client-<id>`). That doesn't scale to a
 * mass shipped client: millions of secrets to create/store/list/bill, and a Secret-Manager round-trip on
 * every cold key resolve. The alternative proposed here derives each install's HMAC key from a SINGLE
 * server **root key** via HKDF-SHA256 — so there is **nothing per-install to store or fetch**: the
 * verifier recomputes the key on the fly from `(rootKey, client_id, keyVersion)`.
 *
 * SEC RATIFIED the model (audit #2 A3) with four binding conditions, implemented here on the verify side:
 *   · DK1 — the root key is injected via `getRootKey` (real: Secret Manager, verifier-SA-only).
 *   · DK2 — a REQUIRED revocation **deny-list** is checked before deriving; a listed `client_id` resolves
 *           to `undefined` (→ 401); a deny-list outage fails CLOSED as a retryable 503 (KS-OUTAGE).
 *   · DK3 — `keyVersion` is the rotation lever (bump + rotate root ⇒ all derived keys change).
 *   · DK4 — `createDerivedKeyStore` is a drop-in `PerInstallKeyStore`, so a deploy picks ONE model
 *           (derived XOR Secret-Manager-per-install) by which store backs `createPerInstallKeyResolver`.
 * No GCP SDK here; `node:crypto` only. The Secret-Manager root + Firestore deny-list live in `functions/`.
 */
import { hkdfSync } from "node:crypto";
import type { PerInstallKeyStore } from "./ingest-adapter.js";

/** Fixed application salt — the SECRET is the root key; the salt only domain-separates this KDF use. */
const DERIVE_SALT = "oet-derived-key-salt:v1";

/**
 * Derive an install's HMAC secret from the server root key. **Deterministic**: the same
 * `(rootKey, clientId, keyVersion)` always yields the same 256-bit key (base64), so the verifier derives
 * it without any per-install storage. `keyVersion` is bound into the KDF `info` so rotating it (with a new
 * root key) invalidates every previously-derived key — the coarse rotation lever (see design doc for the
 * per-cohort refinement). `rootKey` MUST be a CSPRNG value ≥256 bits, held only in Secret Manager.
 */
export function deriveClientKey(
  clientId: string,
  rootKey: Buffer | string,
  keyVersion = "v1",
): string {
  const root = typeof rootKey === "string" ? Buffer.from(rootKey, "utf8") : rootKey;
  // `info` binds the derivation to OET + the key version + THIS client, so keys can't be transplanted
  // across clients or versions.
  const info = Buffer.from(`oet-client-key:${keyVersion}:${clientId}`, "utf8");
  const derived = hkdfSync("sha256", root, Buffer.from(DERIVE_SALT, "utf8"), info, 32);
  return Buffer.from(derived).toString("base64");
}

// ── DK2: revocation deny-list ────────────────────────────────────────────────
/**
 * The revocation deny-list (DK2). Derived keys can't be deleted (they're recomputable), so per-install
 * revocation is a list of revoked `client_id`s checked at verify. `isRevoked` MUST fail CLOSED: on a
 * backing-store fault it should **throw `KeyStoreUnavailableError`** (→ retryable 503), never silently
 * return `false` — we must not accept an install whose revocation status we can't confirm.
 */
export interface RevocationList {
  isRevoked(clientId: string): boolean | Promise<boolean>;
}

/** In-memory deny-list (tests / single instance). Cross-instance correctness needs the shared store. */
export function createInMemoryRevocationList(
  initial: Iterable<string> = [],
): RevocationList & { revoke(id: string): void; restore(id: string): void } {
  const revoked = new Set(initial);
  return {
    isRevoked: (id) => revoked.has(id),
    revoke: (id) => void revoked.add(id),
    restore: (id) => void revoked.delete(id),
  };
}

export interface DerivedKeyStoreOptions {
  /** Resolve the server root key (real: Secret Manager). MAY be async; should be cheap/cached. DK1. */
  getRootKey: () => string | Buffer | Promise<string | Buffer>;
  /** Rotation lever (DK3) — bound into the derivation. Default `"v1"`. */
  keyVersion?: string;
  /** DK2 — REQUIRED in production; omit only in tests where revocation is out of scope. */
  revocationList?: RevocationList;
}

/**
 * A `PerInstallKeyStore` that **derives** each install's key from the root key instead of fetching a
 * stored secret (DK4 — drop-in replacement for the Secret-Manager-per-install store, so a deploy backs
 * `createPerInstallKeyResolver` with exactly ONE model). `getKey`:
 *   1. DK2 — if the `client_id` is revoked → `undefined` (→ 401, fail closed). A deny-list outage throws
 *      `KeyStoreUnavailableError` (→ 503) rather than accept an unconfirmable install.
 *   2. derive `HKDF(root, …, client_id, keyVersion)` and return it. A root-key fetch fault likewise
 *      surfaces as a retryable 503 (the injected `getRootKey` should throw `KeyStoreUnavailableError`).
 * There is no `client_id`-not-found case: any well-formed id has a derivable key unless revoked.
 */
export function createDerivedKeyStore(opts: DerivedKeyStoreOptions): PerInstallKeyStore {
  const keyVersion = opts.keyVersion ?? "v1";
  return {
    async getKey(clientId) {
      if (opts.revocationList && (await opts.revocationList.isRevoked(clientId))) {
        return undefined; // revoked → no key → 401 (fail closed)
      }
      const root = await opts.getRootKey();
      return deriveClientKey(clientId, root, keyVersion);
    },
  };
}
