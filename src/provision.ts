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
  /** Mint a strong random secret (real: ≥256-bit, base64). Returned once; never logged. */
  generateKey(): string;
  keyProvisioner: KeyProvisioner;
  /** Max distinct id attempts before giving up on a (vanishingly unlikely) collision storm. Default 5. */
  maxIdAttempts?: number;
  /** PII-free security-event sink (F5) — outcome/status/coarse reason only; never the key/ip/token. */
  onSecurityEvent?: (event: SecurityEvent) => void;
}

export interface ProvisionRequest {
  rawBody: string;
  ip?: string;
  /** App Check / attestation token from the request header. */
  attestationToken?: string;
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

  // 4. generate a fresh id + key and persist create-if-absent. Regenerate on the (astronomically rare)
  // id collision; a transient store fault surfaces as a retryable 503 (never an opaque/duplicate mint).
  const maxAttempts = deps.maxIdAttempts ?? 5;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const clientId = deps.generateClientId();
    // Guard the generator's output too — a bad id must never reach the store / be issued.
    if (!CLIENT_ID_KEY_PATTERN.test(clientId)) continue;
    const key = deps.generateKey();
    let result: ProvisionPersistResult;
    try {
      result = await deps.keyProvisioner.create(clientId, key);
    } catch (err) {
      if (err instanceof KeyStoreUnavailableError) return fail(503, "unavailable"); // retryable; not an auth event
      throw err; // unexpected → bubble to the wrapper's opaque 500
    }
    if (result === "created") {
      return { status: 201, body: { client_id: clientId, key } }; // returned ONCE; never logged
    }
    // result === "exists" → id already taken → try a fresh id
  }
  // Exhausted attempts (a collision storm, or a broken generator emitting bad/duplicate ids) → 500.
  return reject(500, "internal", "id_exhausted");
}
