/**
 * Ingestion endpoint — pure handler core (Spec §5–§7; SEC design gate APPROVED).
 *
 * `/ingest` is a PUBLIC write endpoint, so the threat model is metric-poisoning + cost-inflation.
 * This module is the pure, unit-testable control flow. Everything non-deterministic or
 * environment-bound — HMAC/App Check verification, rate limiting, the replay nonce cache, geo
 * derivation, the clock, and the BigQuery write — is INJECTED via `IngestDeps`, so the security
 * logic is fully assertable with mocks and imports no crypto, no `canonical.ts`, no GCP SDK. A thin
 * Cloud Function adapter wires the real implementations (Secret Manager, `canonicalEnvelope` +
 * `timingSafeEqual`, a store-backed limiter/nonce cache, a coarse-geo provider, a BQ client).
 *
 * Pipeline (the SEC-approved order) → response contract (§6, opaque bodies):
 *   1. size cap (C2)   raw bytes > 256 KiB           → 413   (BEFORE JSON.parse)
 *   2. parse + EP1     not JSON / not an object      → 400   (before auth)
 *   3. authenticity    HMAC (C5) or App Check        → 401   (fail CLOSED)
 *      replay          sig seen in window (HMAC)     → 401   (nonce cache, SEC Q3 — in this slice)
 *   4. rate limit (C3) per client_id + per IP        → 429
 *   5. consent (C4/D1) consent !== true ⇒ drop-all   → 202   (opaque; absent/false indistinguishable)
 *   6. validate        shape/field/allowlist         → 400 / 413 / 202(all-dropped)
 *   7. enrich (EC1)    server ts µs + coarse geo; raw IP NEVER stored/logged
 *   8. map (EC2)       toGa4Rows over ONLY accepted events
 *   9. write           bqInsert(rows)
 *  10. → 202           {"ok":true}
 */

import { validateEnvelope } from "./validate.js";
import { toGa4Rows, type Ga4Row, type Ga4Geo } from "./ga4.js";
import type { OetEnvelope } from "./envelope.js";

/** §2.1 / C2: reject bodies larger than 256 KiB before parsing. */
export const MAX_BODY_BYTES = 256 * 1024;
/**
 * §5.4 replay-freshness window (v0.1.1), asymmetric: a signed `sent_at` may be up to PAST_WINDOW old
 * (clock drift + transit) but only FUTURE_SKEW ahead (a future timestamp is almost always a forged/
 * replayed envelope). The nonce is retained until `sent_at + PAST_WINDOW`, so its coverage exactly
 * matches the fresh band — no clock-ahead gap.
 */
export const PAST_WINDOW_MS = 5 * 60 * 1000;
export const FUTURE_SKEW_MS = 1 * 60 * 1000;
/** @deprecated kept as an alias of PAST_WINDOW_MS for existing callers. */
export const REPLAY_WINDOW_MS = PAST_WINDOW_MS;

/** validateEnvelope reasons that map to 400 (vs the opaque 202 "all-dropped" classes). */
const ENVELOPE_400_REASONS = new Set([
  "malformed_envelope",
  "invalid_client_id",
  "invalid_platform",
  "invalid_app_version",
  "invalid_user_id",
  "invalid_sent_at",
  "batch_empty",
]);

export interface RateLimiter {
  /**
   * @returns true if allowed, false if over limit. Enforces per-client_id AND per-IP buckets.
   * `authenticated` lets the impl apply the SEC policy: unauth fails CLOSED on store outage,
   * auth MAY fail open but only behind a global ceiling (§5.4). May be async (a SHARED store —
   * Firestore/Redis — is required for correctness across >1 instance; D-STORE).
   */
  allow(clientId: string, ip: string | undefined, authenticated: boolean): boolean | Promise<boolean>;
}

export interface ReplayCache {
  /**
   * ATOMICALLY check-and-record a signature in ONE operation (no seen→record TOCTOU): returns true if
   * the sig was NOT already present — it is now recorded, expiring at `expiresAtMs` — and false if it
   * was already present (a replay). The single op means two concurrent identical sigs (across instances
   * on a shared store) can never both pass: exactly one is accepted (D-STORE-CAS / F-DSTORE-RACE).
   * Expiry is anchored to `sent_at + PAST_WINDOW` (§5.4 — matches the fresh band, no clock-ahead gap).
   * May be async (a shared Firestore/Redis store).
   */
  checkAndRecord(sig: string, expiresAtMs: number): boolean | Promise<boolean>;
}

export interface IpRateGate {
  /**
   * Cheap, NO-I/O, per-IP first-line flood shed (SEC F2). Runs BEFORE parse/HMAC/nonce so a flood —
   * authenticated or not — is dropped at the door before it can spend CPU on parsing/crypto or touch
   * the (shared) nonce store. Per-instance/in-memory is fine: it's defense-in-depth in front of the
   * authoritative shared rate limiter, not a replacement for it.
   */
  allow(ip: string | undefined): boolean;
}

/**
 * A PII-FREE structured security event (SEC F5). Carries ONLY the outcome, the HTTP status, and a
 * COARSE reason category — NEVER client_id, user_id, IP, the sig/secret, or any body content. Lets
 * ops alert on auth-failure / flood / replay spikes without the telemetry endpoint itself logging PII.
 */
export interface SecurityEvent {
  outcome: "rejected";
  status: number;
  /** Coarse category: size_cap · ip_flood · rate_limited · auth_failed · stale · future · replay. */
  reason: string;
}

export interface IngestDeps {
  /** Server-authoritative wall clock, epoch milliseconds. */
  now(): number;
  /** Optional cheap pre-auth per-IP flood gate (F2). When omitted, no pre-gate runs. */
  ipRateGate?: IpRateGate;
  /** Optional PII-free security-event sink (F5). Fired on 413/429/401 outcomes. */
  onSecurityEvent?: (event: SecurityEvent) => void;
  /** Permitted event names (§3); unknown names are dropped. */
  allowlist: ReadonlySet<string>;
  /** Recompute the §5.2 canonical HMAC and constant-time compare against body.sig (adapter owns the secret). */
  verifyHmac(body: Record<string, unknown>): boolean;
  /** Verify a Firebase App Check token (§5.3). */
  verifyAppCheck(token: string): boolean;
  rateLimiter: RateLimiter;
  replayCache: ReplayCache;
  /** Coarse geo from IP, country-only by default (EC1). Returns null when none/suppressed. Raw IP never leaves here. */
  deriveGeo(ip: string | undefined): Ga4Geo | null;
  /** Write GA4-shaped rows to the destination (mock/emulator until Owner GO). */
  bqInsert(rows: Ga4Row[]): void | Promise<void>;
}

export interface IngestRequest {
  /** The unparsed request body — needed for the byte cap (C2) before any parse. */
  rawBody: string;
  /** Source IP for rate limiting + geo. Never stored or logged. */
  ip?: string;
  /** App Check token from the request header (§5.3), if the client uses App Check instead of HMAC. */
  appCheckToken?: string;
}

export interface IngestResponse {
  status: number;
  /** Minimal, opaque body (§6) — never leaks which event/client/secret caused an outcome. */
  body: { ok: true } | { error: string };
}

const OK_202: IngestResponse = { status: 202, body: { ok: true } };
function fail(status: number, code: string): IngestResponse {
  return { status, body: { error: code } };
}

export async function handleIngest(
  req: IngestRequest,
  deps: IngestDeps,
): Promise<IngestResponse> {
  // F5: emit a PII-free security event, then return the opaque failure. Reason is a coarse category.
  const reject = (status: number, code: string, reason: string): IngestResponse => {
    deps.onSecurityEvent?.({ outcome: "rejected", status, reason });
    return fail(status, code);
  };

  // 0. F2 — cheap pre-auth per-IP flood gate, FIRST: shed a flood before any parse/HMAC/nonce work.
  if (deps.ipRateGate && !deps.ipRateGate.allow(req.ip)) {
    return reject(429, "rate_limited", "ip_flood");
  }

  // 1. C2 — size cap BEFORE parse (an oversized body is never parsed into objects).
  if (Buffer.byteLength(req.rawBody, "utf8") > MAX_BODY_BYTES) {
    return reject(413, "payload_too_large", "size_cap");
  }

  // 2. parse + EP1 — must be a JSON object (not array/scalar), checked before auth.
  let parsed: unknown;
  try {
    parsed = JSON.parse(req.rawBody);
  } catch {
    return fail(400, "bad_request");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return fail(400, "bad_request");
  }
  const body = parsed as Record<string, unknown>;

  // 3. authenticity — fail CLOSED. App Check if a token is present, else HMAC + replay nonce.
  let authenticated: boolean;
  if (req.appCheckToken !== undefined) {
    authenticated = deps.verifyAppCheck(req.appCheckToken);
    if (!authenticated) return reject(401, "unauthorized", "auth_failed");
  } else {
    const sig = body.sig;
    if (typeof sig !== "string" || !deps.verifyHmac(body)) {
      return reject(401, "unauthorized", "auth_failed");
    }
    // Replay FRESHNESS (§5.4) + nonce, on the signed `sent_at`. F-FRESH-FAILCLOSED (SEC): a missing/
    // malformed sent_at FAILS CLOSED here (400) — never skipped. The control must be self-contained:
    // delegating the missing case to validate's 400 would become a live replay hole if a v0.1↔v0.1.1
    // transition mode relaxed validate's requirement.
    const sentAtMs = typeof body.sent_at === "string" ? Date.parse(body.sent_at) : NaN;
    if (Number.isNaN(sentAtMs)) return fail(400, "bad_request");
    const age = deps.now() - sentAtMs; // +past / −future
    if (age > PAST_WINDOW_MS || age < -FUTURE_SKEW_MS) {
      return reject(401, "unauthorized", age > PAST_WINDOW_MS ? "stale" : "future");
    }
    // Nonce: one atomic check-and-record. false ⇒ this sig was already seen in the fresh band ⇒ replay.
    if (!(await deps.replayCache.checkAndRecord(sig, sentAtMs + PAST_WINDOW_MS))) {
      return reject(401, "unauthorized", "replay");
    }
    authenticated = true;
  }

  // 4. C3 — rate limit per client_id + per IP (policy/fail-open-closed lives in the limiter).
  const clientId = typeof body.client_id === "string" ? body.client_id : "";
  if (!(await deps.rateLimiter.allow(clientId, req.ip, authenticated))) {
    return reject(429, "rate_limited", "rate_limited");
  }

  // 5. C4 + D1 — consent gate BEFORE shape validation, so consent:false / absent / odd all return
  // the same opaque 202 and can't be distinguished from each other or from a shape error.
  if (body.consent !== true) return OK_202;

  // 6. validate — shape, §2.3 field rules, §2.1 batch bounds, allowlist.
  const result = validateEnvelope(body, deps.allowlist);
  if (result.accepted.length === 0) {
    if (result.rejected.includes("batch_too_large")) return reject(413, "payload_too_large", "batch_cap");
    if (result.rejected.some((r) => ENVELOPE_400_REASONS.has(r))) return fail(400, "bad_request");
    // All events dropped by field-rule/allowlist → opaque 202 (C4): a misconfigured client
    // can't tell an allowed event from a dropped one.
    return OK_202;
  }

  // 7. enrich (EC1) — authoritative server timestamp (µs) + coarse geo. Raw IP is never stored.
  const ctx = {
    eventTimestampMicros: deps.now() * 1000,
    geo: deps.deriveGeo(req.ip),
  };

  // 8. map (EC2) — only the accepted events become rows. body is a validated envelope here.
  const rows = toGa4Rows(body as unknown as OetEnvelope, result.accepted, ctx);

  // 9. write.
  await deps.bqInsert(rows);

  // 10.
  return OK_202;
}
