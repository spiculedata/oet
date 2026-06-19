/**
 * Envelope validation + the server-side security gates.
 *
 * This is the heart of OET's security posture (it's a PUBLIC write endpoint):
 *   1. shape       — reject malformed envelopes (wrong types)            → 400
 *   2. field rules — enforce the §2.3 contract (lengths, charsets, caps)
 *        · envelope-level violations (client_id / platform / app_version) → 400
 *        · per-event violations are DROPPED + COUNTED (one bad event must
 *          not sink a 1000-event batch — mirrors the §3 allowlist drop and
 *          the "all dropped ⇒ still 202" opacity model)                  → 202
 *   3. batch bounds — §2.1: 1..1000 events                  → 400 (empty) / 413 (too large)
 *   4. consent     — drop everything if consent !== true                 → 202
 *   5. allowlist   — drop events whose `name` isn't explicitly allowed   → 202
 *
 * The 256 KiB BODY size cap (§2.1 / SEC C2) is a size-BEFORE-parse check and is the
 * ingestion endpoint's responsibility — you cannot measure the raw body after it's
 * already parsed into an object. This module is the pure, unit-testable core; HMAC
 * verification, rate limiting, geo enrichment, and the BigQuery write live in src/ingest.ts.
 *
 * Reason taxonomy (for metrics + endpoint status mapping; NEVER leaked to the client, §6):
 *   malformed_envelope            top-level shape/type wrong              → 400
 *   invalid_client_id             §2.3 client_id rule                     → 400
 *   invalid_platform              §2.3/§2.4 platform token rule           → 400
 *   invalid_app_version           §2.3 app_version length rule            → 400
 *   batch_empty                   §2.1 events array empty                 → 400
 *   batch_too_large               §2.1 > MAX_EVENTS_PER_BATCH events      → 413
 *   consent_not_granted           §4.2 consent !== true                   → 202 (drop-all)
 *   event_invalid:<name>:<rule>   §2.3 per-event field rule              → 202 (drop+count)
 *   event_not_allowlisted:<name>  §3 unknown event name                  → 202 (drop+count)
 */

import { REGISTERED_PLATFORMS } from "./envelope.js";
import type { OetEnvelope, OetEvent } from "./envelope.js";

// ── §2.1 / §2.3 limits (single source of truth, spec-traceable) ──────────────
export const MAX_EVENTS_PER_BATCH = 1000;
export const MAX_CLIENT_ID_LEN = 128;
export const MAX_APP_VERSION_LEN = 64;
export const MAX_EVENT_NAME_LEN = 64;
export const MAX_PARAM_KEYS = 25;
export const MAX_PARAM_KEY_LEN = 40;
/** §2.3 (v0.1.1, N1): cap a string param VALUE to bound per-row cost. Non-strings are length-free. */
export const MAX_PARAM_VALUE_LEN = 1024;

/** §2.3: client_id is 1–128 chars from [A-Za-z0-9._-]. */
const CLIENT_ID_RE = /^[A-Za-z0-9._-]+$/;
/** §2.3: event name + param keys are snake_case `[a-z][a-z0-9_]*`. */
const SNAKE_CASE_RE = /^[a-z][a-z0-9_]*$/;
/** ISO-8601 with an explicit timezone (Z or ±hh:mm). */
const ISO8601_TZ_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export interface ValidationResult {
  ok: boolean;
  /** Events that passed field rules + the allowlist and will be written. */
  accepted: OetEvent[];
  /** Reasons events/envelope were rejected (for metrics, never for the client). */
  rejected: string[];
}

function isParamValue(v: unknown): boolean {
  return (
    v === null ||
    typeof v === "string" ||
    typeof v === "number" ||
    typeof v === "boolean"
  );
}

/** Structural TYPE guard — does this even match the contract's types? (value rules are separate.) */
function isEvent(e: unknown): e is OetEvent {
  if (typeof e !== "object" || e === null) return false;
  const ev = e as Record<string, unknown>;
  if (typeof ev.name !== "string" || typeof ev.ts !== "string") return false;
  if (ev.params !== undefined) {
    if (typeof ev.params !== "object" || ev.params === null) return false;
    if (Array.isArray(ev.params)) return false;
    for (const val of Object.values(ev.params as Record<string, unknown>)) {
      if (!isParamValue(val)) return false;
    }
  }
  return true;
}

export function isEnvelope(x: unknown): x is OetEnvelope {
  if (typeof x !== "object" || x === null) return false;
  const e = x as Record<string, unknown>;
  // NOTE (D1, SEC-ruled): `consent` is deliberately NOT part of the shape guard. §4.2 says
  // "consent false/ABSENT ⇒ nothing retained", which is the drop-all 202 path. If the guard
  // required consent to be a boolean, an absent/odd-typed consent would fall out as
  // `malformed_envelope` (400) — letting a prober distinguish "missing consent" (400) from
  // "consent:false" (202). Excluding it routes ALL non-true consent through the 202 path below.
  return (
    typeof e.client_id === "string" &&
    (e.user_id === null || typeof e.user_id === "string") &&
    typeof e.platform === "string" &&
    typeof e.app_version === "string" &&
    typeof e.sent_at === "string" &&
    Array.isArray(e.events) &&
    e.events.every(isEvent)
  );
}

/**
 * §2.3 envelope-level field rules. These fields are single-valued and required, so a
 * bad value means the envelope itself is non-conformant (→ 400). Returns a reject reason
 * or null if all pass.
 */
function checkEnvelopeFields(env: OetEnvelope): string | null {
  if (env.client_id.length < 1 || env.client_id.length > MAX_CLIENT_ID_LEN)
    return "invalid_client_id";
  if (!CLIENT_ID_RE.test(env.client_id)) return "invalid_client_id";
  // §2.4 / SEC C6: platform is a stored, non-allowlisted dimension → strict registered-set
  // membership, not a format check. A well-formed-but-unregistered token would poison the
  // platform breakdown (DOMAIN LAW 3/4).
  if (!REGISTERED_PLATFORMS.has(env.platform)) return "invalid_platform";
  if (env.app_version.length < 1 || env.app_version.length > MAX_APP_VERSION_LEN)
    return "invalid_app_version";
  // §5.5: sent_at must be a real ISO-8601+tz instant. A malformed time is a bad envelope (400);
  // a well-formed-but-stale/future time is the endpoint's freshness concern (401), not here.
  if (!ISO8601_TZ_RE.test(env.sent_at) || Number.isNaN(Date.parse(env.sent_at)))
    return "invalid_sent_at";
  return null;
}

/**
 * §2.3 per-event field rules (run on structurally-valid events). Returns a short rule
 * tag if the event violates a rule, or null if it passes. A failing event is dropped +
 * counted, never written — it does not fail the whole batch.
 */
function checkEventFields(ev: OetEvent): string | null {
  if (ev.name.length < 1 || ev.name.length > MAX_EVENT_NAME_LEN)
    return "name_length";
  if (!SNAKE_CASE_RE.test(ev.name)) return "name_charset";
  if (!ISO8601_TZ_RE.test(ev.ts) || Number.isNaN(Date.parse(ev.ts)))
    return "ts_format";
  if (ev.params !== undefined) {
    const keys = Object.keys(ev.params);
    if (keys.length > MAX_PARAM_KEYS) return "param_count";
    for (const k of keys) {
      if (k.length < 1 || k.length > MAX_PARAM_KEY_LEN) return "param_key_length";
      if (!SNAKE_CASE_RE.test(k)) return "param_key_charset";
      const v = ev.params[k];
      if (typeof v === "string" && v.length > MAX_PARAM_VALUE_LEN)
        return "param_value_length";
    }
  }
  return null;
}

/**
 * Validate an envelope and filter its events against the field rules + allowlist.
 * @param env       parsed request body (untrusted)
 * @param allowlist set of permitted event names
 */
export function validateEnvelope(
  env: unknown,
  allowlist: ReadonlySet<string>,
): ValidationResult {
  if (!isEnvelope(env)) {
    return { ok: false, accepted: [], rejected: ["malformed_envelope"] };
  }

  // §2.3 envelope-level field rules → 400 if any required scalar field is non-conformant.
  const envFieldError = checkEnvelopeFields(env);
  if (envFieldError !== null) {
    return { ok: false, accepted: [], rejected: [envFieldError] };
  }

  // §2.1 batch bounds. Empty ⇒ malformed (400); over-cap ⇒ too large (413).
  if (env.events.length < 1) {
    return { ok: false, accepted: [], rejected: ["batch_empty"] };
  }
  if (env.events.length > MAX_EVENTS_PER_BATCH) {
    return { ok: false, accepted: [], rejected: ["batch_too_large"] };
  }

  // DOMAIN LAW: opt-in consent. Anything other than exactly `true` — false, absent, or a
  // non-boolean — retains nothing and returns the opaque 202 path (D1). `consent` is typed
  // boolean but may be absent/odd at runtime since the shape guard intentionally skips it.
  if ((env.consent as unknown) !== true) {
    return { ok: false, accepted: [], rejected: ["consent_not_granted"] };
  }

  // Per-event: field rules then the allowlist. Both DROP + COUNT (never fail the batch).
  const accepted: OetEvent[] = [];
  const rejected: string[] = [];
  for (const ev of env.events) {
    const fieldError = checkEventFields(ev);
    if (fieldError !== null) {
      rejected.push(`event_invalid:${ev.name}:${fieldError}`);
      continue;
    }
    // DOMAIN LAW: server-side allowlist. Unknown event names are dropped, not stored.
    if (allowlist.has(ev.name)) {
      accepted.push(ev);
    } else {
      rejected.push(`event_not_allowlisted:${ev.name}`);
    }
  }

  return { ok: accepted.length > 0, accepted, rejected };
}
