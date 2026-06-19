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
  /** true if this signature is still recorded (i.e. not yet past its expiry). May be async (shared store). */
  seen(sig: string): boolean | Promise<boolean>;
  /**
   * Record a signature, expiring at `expiresAtMs` (epoch ms). The endpoint anchors this to
   * `sent_at + PAST_WINDOW` so a nonce lives exactly as long as the envelope could still be fresh —
   * not a flat window from receive time (§5.4, closes the clock-ahead gap). May be async (shared store).
   */
  record(sig: string, expiresAtMs: number): void | Promise<void>;
}

export interface IngestDeps {
  /** Server-authoritative wall clock, epoch milliseconds. */
  now(): number;
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
  // 1. C2 — size cap BEFORE parse (an oversized body is never parsed into objects).
  if (Buffer.byteLength(req.rawBody, "utf8") > MAX_BODY_BYTES) {
    return fail(413, "payload_too_large");
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
    if (!authenticated) return fail(401, "unauthorized");
  } else {
    const sig = body.sig;
    if (typeof sig !== "string" || !deps.verifyHmac(body)) {
      return fail(401, "unauthorized");
    }
    // Replay FRESHNESS (§5.4) + nonce, on the signed `sent_at`. F-FRESH-FAILCLOSED (SEC): a missing/
    // malformed sent_at FAILS CLOSED here (400) — never skipped. The control must be self-contained:
    // delegating the missing case to validate's 400 would become a live replay hole if a v0.1↔v0.1.1
    // transition mode relaxed validate's requirement.
    const sentAtMs = typeof body.sent_at === "string" ? Date.parse(body.sent_at) : NaN;
    if (Number.isNaN(sentAtMs)) return fail(400, "bad_request");
    const age = deps.now() - sentAtMs; // +past / −future
    if (age > PAST_WINDOW_MS || age < -FUTURE_SKEW_MS) return fail(401, "unauthorized");
    // Nonce: identical sig within the fresh band → replay. Anchor expiry to sent_at + PAST_WINDOW.
    if (await deps.replayCache.seen(sig)) return fail(401, "unauthorized");
    await deps.replayCache.record(sig, sentAtMs + PAST_WINDOW_MS);
    authenticated = true;
  }

  // 4. C3 — rate limit per client_id + per IP (policy/fail-open-closed lives in the limiter).
  const clientId = typeof body.client_id === "string" ? body.client_id : "";
  if (!(await deps.rateLimiter.allow(clientId, req.ip, authenticated))) {
    return fail(429, "rate_limited");
  }

  // 5. C4 + D1 — consent gate BEFORE shape validation, so consent:false / absent / odd all return
  // the same opaque 202 and can't be distinguished from each other or from a shape error.
  if (body.consent !== true) return OK_202;

  // 6. validate — shape, §2.3 field rules, §2.1 batch bounds, allowlist.
  const result = validateEnvelope(body, deps.allowlist);
  if (result.accepted.length === 0) {
    if (result.rejected.includes("batch_too_large")) return fail(413, "payload_too_large");
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
