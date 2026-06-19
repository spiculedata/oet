/**
 * QA HMAC canonicalization cross-check — Spec v0.1 §10 Q4.
 *
 * DEV's canonical.test.ts proves the canonical STRING is deterministic (key-sorted, sig-stripped,
 * whitespace-free, order-independent). This suite closes §10 Q4's literal ask — "cross-check
 * emitter-side and server-side produce identical SIGNATURES" — by adding the real crypto layer the
 * string tests don't exercise: an actual HMAC-SHA256 sign→verify round-trip with a constant-time
 * compare (modelling endpoint C5), driven through `canonicalEnvelope`.
 *
 * The whole §5.2 scheme rests on three properties this suite asserts end-to-end at the SIGNATURE level:
 *   1. an emitter signing and a server independently re-deriving agree byte-for-byte → verifies,
 *      regardless of key order, with `sig` excluded from the signed message;
 *   2. tampering ANY signed field flips the signature → rejected (the integrity guarantee);
 *   3. reordering object keys does NOT change the signature, but reordering `events` (an array) DOES —
 *      the canonical form normalizes exactly what it should and nothing more.
 *
 * Uses node:crypto directly so the test is independent of any production signing code (which lives in
 * the endpoint slice). If the endpoint's HMAC ever diverges from §5.2, this stays the reference oracle.
 */
import { describe, it, expect } from "vitest";
import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalEnvelope } from "./canonical.js";

const SECRET = "app-secret-provisioned-out-of-band";

/** §5.2: sig = "hmac-sha256:" + base64( HMAC-SHA256( key=secret, msg=canonical(envelope-without-sig) ) ). */
function sign(envelope: Record<string, unknown>, secret: string): string {
  const mac = createHmac("sha256", secret).update(canonicalEnvelope(envelope), "utf8").digest("base64");
  return "hmac-sha256:" + mac;
}

/** Server-side verify: recompute over the received envelope (canonicalEnvelope strips sig) + constant-time compare (C5). */
function verify(envelope: Record<string, unknown>, secret: string): boolean {
  const presented = String(envelope.sig ?? "");
  const expected = sign(envelope, secret);
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

const baseEnvelope = {
  client_id: "win-3f2a9c7e",
  user_id: null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  events: [
    { name: "app_open", ts: "2026-06-18T00:00:00Z", params: { source: "win", n: 3 } },
    { name: "purchase", ts: "2026-06-18T00:00:01Z", params: { amount: 4 } },
  ],
};

describe("Q4 — emitter↔server signature cross-check (§5.2)", () => {
  it("a server independently verifies an emitter's signature (round-trip)", () => {
    // EMITTER: signs the envelope (no sig yet), then attaches the sig.
    const emitterSig = sign(baseEnvelope, SECRET);
    const onTheWire = { ...baseEnvelope, sig: emitterSig };
    // SERVER: receives the wire envelope, strips sig, recomputes, constant-time compares.
    expect(verify(onTheWire, SECRET)).toBe(true);
    expect(emitterSig).toMatch(/^hmac-sha256:[A-Za-z0-9+/]+=*$/); // §5.2 format
  });

  it("verifies even when emitter and server build the object with DIFFERENT key order", () => {
    const emitterSig = sign(baseEnvelope, SECRET);
    // Server reconstructs the same logical envelope with top-level + nested keys in a different order.
    const serverView = {
      sig: emitterSig,
      events: [
        { params: { n: 3, source: "win" }, ts: "2026-06-18T00:00:00Z", name: "app_open" },
        { params: { amount: 4 }, name: "purchase", ts: "2026-06-18T00:00:01Z" },
      ],
      consent: true,
      app_version: "2.2.0+27",
      platform: "windows",
      user_id: null,
      client_id: "win-3f2a9c7e",
    };
    expect(verify(serverView, SECRET)).toBe(true);
  });

  it("the signed message excludes sig — attaching sig does not invalidate it", () => {
    const sig = sign(baseEnvelope, SECRET);
    // Signing again WITH the sig present yields the same message (canonicalEnvelope strips it).
    expect(sign({ ...baseEnvelope, sig }, SECRET)).toBe(sig);
  });
});

describe("Q4 — tamper detection (the integrity guarantee)", () => {
  const sig = sign(baseEnvelope, SECRET);

  it("rejects a flipped consent flag", () => {
    expect(verify({ ...baseEnvelope, consent: false, sig }, SECRET)).toBe(false);
  });

  it("rejects a mutated event param value", () => {
    const tampered = { ...baseEnvelope, events: [{ ...baseEnvelope.events[0]!, params: { source: "win", n: 9999 } }, baseEnvelope.events[1]!], sig };
    expect(verify(tampered, SECRET)).toBe(false);
  });

  it("rejects an added event (batch padding)", () => {
    const padded = { ...baseEnvelope, events: [...baseEnvelope.events, { name: "app_open", ts: "2026-06-18T00:00:02Z" }], sig };
    expect(verify(padded, SECRET)).toBe(false);
  });

  it("rejects a signature made with a different secret", () => {
    const foreignSig = sign(baseEnvelope, "some-other-secret");
    expect(verify({ ...baseEnvelope, sig: foreignSig }, SECRET)).toBe(false);
  });
});

describe("Q4 — normalizes keys, preserves array order", () => {
  it("reordering OBJECT keys keeps the signature valid", () => {
    const sig = sign(baseEnvelope, SECRET);
    const reorderedKeys = { consent: true, client_id: "win-3f2a9c7e", platform: "windows", user_id: null, app_version: "2.2.0+27", events: baseEnvelope.events, sig };
    expect(verify(reorderedKeys, SECRET)).toBe(true);
  });

  it("reordering the EVENTS array breaks the signature (arrays are ordered, §5.2)", () => {
    const sig = sign(baseEnvelope, SECRET);
    const swapped = { ...baseEnvelope, events: [baseEnvelope.events[1]!, baseEnvelope.events[0]!], sig };
    expect(verify(swapped, SECRET)).toBe(false);
  });
});
