/**
 * Per-install key PROVISIONING — pure handler core (GL3 follow-up / C9 enablement; **SEC design gate**).
 *
 * The per-install key model (GL3) needs a way for a *shipped, untrusted* client to OBTAIN its own key on
 * first run — without embedding any global secret. This is that endpoint's pure, injected-deps core:
 * `POST /provision` → mint a fresh `client_id` + HMAC secret, persist it, return it ONCE. Everything
 * non-deterministic or environment-bound (attestation, the abuse gate, randomness, the key store) is
 * INJECTED, so the security policy is fully unit-testable with no GCP SDK.
 *
 * Threat model: this endpoint is reachable by anyone, and minting a key WRITES to a paid store. So the
 * abuse surface is (a) bot/script minting (→ require app **attestation**, fail closed) and (b) cost /
 * flood (→ a per-IP + global **mint ceiling**, fail closed on store outage). The minted secret is
 * returned exactly once over TLS and is NEVER logged (DOMAIN LAW 7).
 *
 * Pipeline (mirrors the ingest contract — opaque bodies, fail-closed):
 *   1. size cap (C2)         oversized body            → 413   (before parse)
 *   2. attestation           no/invalid App Check tok  → 401   (fail CLOSED — the bot gate)
 *   3. abuse gate            per-IP / global ceiling   → 429   (fail CLOSED on gate-store outage)
 *   4. generate + persist    atomic create-if-absent   → 201 { client_id, key }
 *      · id collision (astronomically rare) → bounded regen, else 500
 *      · transient store fault → 503 (retryable; KeyStoreUnavailableError, never an opaque mint)
 *
 * NOTE (SEC): this is the DESIGN made concrete + testable. The real Secret-Manager wiring (atomic
 * createSecret) is intentionally NOT built until SEC ratifies the minting policy below.
 */
import { CLIENT_ID_KEY_PATTERN } from "./ingest-adapter.js";
import { KeyStoreUnavailableError, type SecurityEvent } from "./ingest.js";
import type { PowSolution, PowVerifyResult } from "./provision-pow.js";

/** Tiny cap — a provision request carries no payload of substance (defense-in-depth before parse). */
export const MAX_PROVISION_BODY_BYTES = 4 * 1024;

/** Outcome of an atomic, create-only persist. NEVER returns an existing secret (no exfil-by-guess). */
export type ProvisionPersistResult = "created" | "exists";

/**
 * The persistent provisioner (real: Secret Manager `createSecret` + first version). `create` is
 * **create-if-absent and atomic**: it persists the key for a brand-new `client_id`, returning
 * `"created"`, or `"exists"` if that id is already taken (→ the core regenerates) — it MUST NOT
 * overwrite or reveal an existing key. A **transient** fault (outage/throttle) MUST throw
 * `KeyStoreUnavailableError` (→ retryable 503), never silently fail.
 */
export interface KeyProvisioner {
  create(clientId: string, key: string): Promise<ProvisionPersistResult>;
}

/** Cheap per-IP + global mint ceiling. Fail CLOSED (deny) when the backing store is unavailable. */
export interface ProvisionGate {
  allow(ip: string | undefined): boolean | Promise<boolean>;
}

export interface ProvisionDeps {
  now(): number;
  /** App attestation (real: Firebase App Check `verifyToken`). True only on a genuine verify; fail closed. */
  verifyAttestation(token: string): boolean | Promise<boolean>;
  /** Per-IP + global mint ceiling (cost/flood cap). */
  gate: ProvisionGate;
  /** Mint a random `client_id` matching CLIENT_ID_KEY_PATTERN (real: 128-bit random, url-safe). */
  generateClientId(): string;
  /** Mint a strong random secret (real: ≥256-bit, base64). Returned once; never logged. Stored mode only. */
  generateKey(): string;
  /**
   * Persist the minted key (stored model — Secret Manager per install). Required UNLESS `deriveKey` is set
   * (the derived model stores nothing). Atomic create-if-absent; see `KeyProvisioner`.
   */
  keyProvisioner?: KeyProvisioner;
  /**
   * DK4 — **derived** key model (A3): given a fresh random `client_id`, return its key DERIVED from the
   * server root key (real: `deriveClientKey`). When present, provisioning **stores nothing** (the verifier
   * re-derives) — no `keyProvisioner`/`createSecret`, and a 128-bit-random id needs no create-if-absent
   * collision check (SEC-accepted). Mutually exclusive with the stored model.
   */
  deriveKey?: (clientId: string) => string | Promise<string>;
  /** Max distinct id attempts before giving up on a (vanishingly unlikely) collision storm. Default 5. */
  maxIdAttempts?: number;
  /**
   * A4 / PW4 — proof-of-work gate. When present, a valid solved challenge is REQUIRED to mint (desktop
   * first-run bar). Returns `{ok:true, challengeId}` on a good solution, else `{ok:false}`. Omit to
   * disable PoW (mobile/App-Check-strong path). Pure: see `verifyPowChallenge`.
   */
  verifyProofOfWork?: (solution: PowSolution) => PowVerifyResult | Promise<PowVerifyResult>;
  /**
   * A4 / PW2 — single-use: consume a solved challenge's id in the shared store, atomically. Returns true
   * if newly consumed, false if already used (a replayed solution). Required when `verifyProofOfWork` is
   * set; on a store fault it should THROW (→ the wrapper surfaces an opaque 500, never a silent accept).
   */
  consumeChallenge?: (challengeId: string) => boolean | Promise<boolean>;
  /**
   * A4 / Steam entitlement — when present, a valid server-verified ownership token is REQUIRED to mint
   * (Steam channel). True only on a confirmed ownership; fail closed (missing/invalid/throws → reject).
   * Real impl: `createSteamEntitlementVerifier` (Steam Web API, server-side, secret never logged).
   */
  verifyEntitlement?: (entitlementToken: string) => boolean | Promise<boolean>;
  /** PII-free security-event sink (F5) — outcome/status/coarse reason only; never the key/ip/token. */
  onSecurityEvent?: (event: SecurityEvent) => void;
}

export interface ProvisionRequest {
  rawBody: string;
  ip?: string;
  /** App Check / attestation token from the request header. */
  attestationToken?: string;
  /** A4 / PW — the solved challenge `{challenge, sig, nonce}` from the request body (PoW mode). */
  pow?: PowSolution;
  /** A4 / Steam — the ownership/session token from the request (entitlement mode). */
  entitlementToken?: string;
}

export interface ProvisionResponse {
  status: number;
  /** 201 returns the freshly-minted credentials ONCE; failures are opaque (no detail leaked). */
  body: { client_id: string; key: string } | { error: string };
}

function fail(status: number, code: string): ProvisionResponse {
  return { status, body: { error: code } };
}

/**
 * Pure provisioning handler. Returns a minted `{ client_id, key }` on success (201) or an opaque
 * failure. Mirrors the ingest fail-closed posture: attestation and the abuse gate both deny by default.
 */
export async function handleProvision(
  req: ProvisionRequest,
  deps: ProvisionDeps,
): Promise<ProvisionResponse> {
  const reject = (status: number, code: string, reason: string): ProvisionResponse => {
    deps.onSecurityEvent?.({ outcome: "rejected", status, reason });
    return fail(status, code);
  };

  // 1. size cap before parse — a provision body is tiny; an oversized one is never parsed.
  if (Buffer.byteLength(req.rawBody, "utf8") > MAX_PROVISION_BODY_BYTES) {
    return reject(413, "payload_too_large", "size_cap");
  }

  // 2. attestation FIRST — only a genuine app install may mint. Fail CLOSED (no token, bad token, or a
  // verifier that throws → 401). This is the gate that stops scripted/bulk minting.
  const token = req.attestationToken;
  if (token === undefined) return reject(401, "unauthorized", "attestation_missing");
  let attested: boolean;
  try {
    attested = await deps.verifyAttestation(token);
  } catch {
    attested = false; // an attestation-service error must NOT grant a mint (fail closed)
  }
  if (!attested) return reject(401, "unauthorized", "attestation_failed");

  // 3. abuse gate — per-IP + global mint ceiling (cost cap). Fail CLOSED on a gate-store outage.
  let allowed: boolean;
  try {
    allowed = await deps.gate.allow(req.ip);
  } catch {
    allowed = false;
  }
  if (!allowed) return reject(429, "rate_limited", "mint_ceiling");

  // 3b. A4 / PW4 — proof-of-work, AFTER attestation + the ceiling (cheap, ~1 hash; not spent on a flood
  // the ceiling already shed). When configured it's REQUIRED. We verify here but DON'T consume the
  // challenge yet — a later entitlement failure must not burn the single-use challenge (consume is below).
  let powChallengeId: string | undefined;
  if (deps.verifyProofOfWork) {
    if (req.pow === undefined) return reject(401, "unauthorized", "proof_required");
    const pow = await deps.verifyProofOfWork(req.pow);
    if (!pow.ok) return reject(401, "unauthorized", `proof_${pow.reason}`);
    powChallengeId = pow.challengeId;
  }

  // 3c. A4 / Steam entitlement — server-side proof of ownership (Owner-required on the Steam channel).
  // LAST of the cheap gates (it makes an external API call) and BEFORE consume. Fail CLOSED: missing
  // token, a false result, or a verifier that throws → 401 (never a client-trusted flag).
  if (deps.verifyEntitlement) {
    if (req.entitlementToken === undefined) return reject(401, "unauthorized", "entitlement_required");
    let entitled: boolean;
    try {
      entitled = await deps.verifyEntitlement(req.entitlementToken);
    } catch {
      entitled = false;
    }
    if (!entitled) return reject(401, "unauthorized", "entitlement_failed");
  }

  // 3d. PW2 — now that EVERY proof passed, consume the challenge single-use (one solved challenge mints at
  // most once). consume throws on a store fault → bubbles to the wrapper's opaque 500 (never silent accept).
  if (powChallengeId !== undefined && deps.consumeChallenge && !(await deps.consumeChallenge(powChallengeId))) {
    return reject(401, "unauthorized", "proof_replay");
  }

  // 4a. DK4 — DERIVED model (A3): issue a fresh random `client_id` and return its DERIVED key. Nothing is
  // stored (the verifier re-derives), so there's no `createSecret` (A8's orphan case disappears) and no
  // create-if-absent collision loop — a 128-bit-random id collision is astronomically rare (SEC-accepted).
  if (deps.deriveKey) {
    const clientId = deps.generateClientId();
    if (!CLIENT_ID_KEY_PATTERN.test(clientId)) return reject(500, "internal", "id_invalid"); // generator guard
    let key: string;
    try {
      key = await deps.deriveKey(clientId);
    } catch (err) {
      if (err instanceof KeyStoreUnavailableError) return fail(503, "unavailable"); // root-key fault → retryable
      throw err; // unexpected → bubble to the wrapper's opaque 500
    }
    deps.onSecurityEvent?.({ outcome: "minted", status: 201, reason: "key_minted" }); // A2 audit trail
    return { status: 201, body: { client_id: clientId, key } }; // returned ONCE; never logged
  }

  // 4b. STORED model: generate a fresh id + key and persist create-if-absent. Regenerate on the
  // (astronomically rare) id collision; a transient store fault → retryable 503 (never an opaque/dup mint).
  const keyProvisioner = deps.keyProvisioner;
  if (!keyProvisioner) return reject(500, "internal", "no_key_model"); // misconfig: neither model set
  const maxAttempts = deps.maxIdAttempts ?? 5;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const clientId = deps.generateClientId();
    // Guard the generator's output too — a bad id must never reach the store / be issued.
    if (!CLIENT_ID_KEY_PATTERN.test(clientId)) continue;
    const key = deps.generateKey();
    let result: ProvisionPersistResult;
    try {
      result = await keyProvisioner.create(clientId, key);
    } catch (err) {
      if (err instanceof KeyStoreUnavailableError) return fail(503, "unavailable"); // retryable; not an auth event
      throw err; // unexpected → bubble to the wrapper's opaque 500
    }
    if (result === "created") {
      // A2: PII-free credential-issuance audit trail — record THAT a mint succeeded, never WHICH
      // (no client_id/key/ip/token), so ops can alert on issuance spikes without the endpoint logging PII.
      deps.onSecurityEvent?.({ outcome: "minted", status: 201, reason: "key_minted" });
      return { status: 201, body: { client_id: clientId, key } }; // returned ONCE; never logged
    }
    // result === "exists" → id already taken → try a fresh id
  }
  // Exhausted attempts (a collision storm, or a broken generator emitting bad/duplicate ids) → 500.
  return reject(500, "internal", "id_exhausted");
}
