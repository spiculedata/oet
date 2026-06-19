/**
 * Canonical payload serialization for HMAC signing/verification (Spec v0.1 §5.2).
 *
 * The emitter and the server MUST agree byte-for-byte on the message that is HMAC'd, or every
 * signature mismatches. §5.2 defines the canonical payload as the UTF-8 JSON of the envelope:
 *   · with the `sig` field removed,
 *   · keys sorted lexicographically at EVERY level,
 *   · no insignificant whitespace.
 *
 * This module is the single shared definition both sides import (the reference impl is JS↔JS).
 * It is pure: it builds the string by hand rather than relying on `JSON.stringify` key order
 * (V8 reorders integer-like keys), so the output is deterministic regardless of input key order.
 * The actual HMAC + constant-time compare live in the endpoint (C5) — this only builds the message.
 */

/**
 * Deterministically serialize any JSON value: object keys sorted lexicographically at every level,
 * arrays kept in order, no whitespace. Matches `JSON.stringify` for scalars (incl. string escaping
 * and number formatting); non-finite numbers serialize to `null`, as `JSON.stringify` does.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return Number.isFinite(value) ? JSON.stringify(value) : "null";
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v) => canonicalize(v)).join(",") + "]";
      }
      const obj = value as Record<string, unknown>;
      const parts: string[] = [];
      for (const key of Object.keys(obj).sort()) {
        const v = obj[key];
        if (v === undefined) continue; // mirror JSON.stringify: drop undefined-valued keys
        parts.push(JSON.stringify(key) + ":" + canonicalize(v));
      }
      return "{" + parts.join(",") + "}";
    }
    default:
      // undefined / function / symbol / bigint cannot appear in a parsed JSON envelope.
      return "null";
  }
}

/**
 * The §5.2 canonical payload that is HMAC'd: the envelope with its `sig` field removed, then
 * canonicalized. Accepts the raw parsed request body (untrusted) — authenticity is verified
 * BEFORE validation (§7), so this must not assume a well-formed envelope.
 */
export function canonicalEnvelope(envelope: Record<string, unknown>): string {
  const withoutSig: Record<string, unknown> = { ...envelope };
  delete withoutSig.sig;
  return canonicalize(withoutSig);
}
