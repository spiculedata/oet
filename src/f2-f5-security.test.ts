/**
 * QA — SEC F2 (pre-auth IP flood gate ordering) + F5 (PII-free security events), end-to-end.
 *
 * F2 acceptance: a flood is shed at the IP gate BEFORE any parse/HMAC/nonce work. F5 acceptance: the
 * security events fired on 413/429/401 carry ONLY a coarse {outcome,status,reason} — NEVER client_id,
 * user_id, IP, the sig/secret, or body content (DOMAIN LAW 1/7). DEV covers the basics; this makes both
 * invariants exhaustive: F2 proves nothing downstream is touched, F5 sweeps EVERY reject path and asserts
 * the serialized log line (what actually reaches Cloud Logging) contains none of the fixture's PII values.
 */
import { describe, it, expect, vi } from "vitest";
import { handleIngest, PAST_WINDOW_MS, FUTURE_SKEW_MS, type IngestDeps, type IngestRequest, type SecurityEvent } from "./ingest.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW = 1_700_000_000_000;
const PII = { clientId: "win-SECRET-CLIENT", userId: "u-SECRET-USER", ip: "203.0.113.7", sig: "hmac-sha256:SECRETSIG" };
const base = {
  client_id: PII.clientId, user_id: PII.userId, platform: "windows", app_version: "2.2.0+27",
  consent: true, sent_at: new Date(NOW).toISOString(),
  events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }], sig: PII.sig,
};
function deps(over: Partial<IngestDeps> = {}): IngestDeps {
  return {
    now: () => NOW, allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: () => true, verifyAppCheck: () => true,
    rateLimiter: { allow: () => true }, replayCache: { checkAndRecord: () => true },
    deriveGeo: () => null, bqInsert: vi.fn(), ...over,
  };
}
const req = (body: unknown): IngestRequest => ({ rawBody: JSON.stringify(body), ip: PII.ip });

describe("F2 — pre-auth IP gate runs FIRST (sheds before parse/HMAC/nonce)", () => {
  it("a blocked IP → 429 and verifyHmac / checkAndRecord / bqInsert are NEVER touched", async () => {
    const verifyHmac = vi.fn(() => true);
    const checkAndRecord = vi.fn(() => true);
    const bqInsert = vi.fn();
    const r = await handleIngest(req(base), deps({
      ipRateGate: { allow: () => false }, verifyHmac, replayCache: { checkAndRecord }, bqInsert,
    }));
    expect(r.status).toBe(429);
    expect(verifyHmac).not.toHaveBeenCalled();   // no crypto spent on a flood
    expect(checkAndRecord).not.toHaveBeenCalled(); // no (shared) nonce write spent on a flood
    expect(bqInsert).not.toHaveBeenCalled();
  });
  it("even an oversized body is shed by the IP gate before the size-cap check", async () => {
    const r = await handleIngest({ rawBody: "x".repeat(256 * 1024 + 1), ip: PII.ip }, deps({ ipRateGate: { allow: () => false } }));
    expect(r.status).toBe(429); // ip_flood (gate is step 0), not 413
  });
});

describe("F5 — security events are PII-free across EVERY reject path", () => {
  // Drive each reject path and collect the emitted SecurityEvent + its serialized log line.
  async function emit(over: Partial<IngestDeps>, body: unknown = base, raw?: string): Promise<SecurityEvent[]> {
    const events: SecurityEvent[] = [];
    const d = deps({ onSecurityEvent: (e) => events.push(e), ...over });
    await handleIngest(raw !== undefined ? { rawBody: raw, ip: PII.ip } : req(body), d);
    return events;
  }
  const cases: [string, () => Promise<SecurityEvent[]>][] = [
    ["ip_flood (429)", () => emit({ ipRateGate: { allow: () => false } })],
    ["size_cap (413)", () => emit({}, undefined, "x".repeat(256 * 1024 + 1))],
    ["auth_failed (401)", () => emit({ verifyHmac: () => false })],
    ["rate_limited (429)", () => emit({ rateLimiter: { allow: () => false } })],
    ["stale (401)", () => emit({}, { ...base, sent_at: new Date(NOW - PAST_WINDOW_MS - 1000).toISOString() })],
    ["future (401)", () => emit({}, { ...base, sent_at: new Date(NOW + FUTURE_SKEW_MS + 1000).toISOString() })],
    ["replay (401)", () => emit({ replayCache: { checkAndRecord: () => false } })],
  ];

  it.each(cases)("%s emits exactly {outcome,status,reason} and leaks NO PII", async (_label, run) => {
    const events = await run();
    expect(events).toHaveLength(1);
    const e = events[0]!;
    expect(Object.keys(e).sort()).toEqual(["outcome", "reason", "status"]); // ONLY these 3 fields
    expect(e.outcome).toBe("rejected");
    // The serialized log line (what hits Cloud Logging) must contain none of the fixture's PII/secret.
    const line = JSON.stringify({ severity: "WARNING", component: "oet-ingest", ...e });
    for (const secret of Object.values(PII)) expect(line).not.toContain(secret);
  });

  it("the reason is a coarse category, never a raw identifier", async () => {
    const allowed = new Set(["ip_flood", "size_cap", "batch_cap", "rate_limited", "auth_failed", "stale", "future", "replay"]);
    for (const [, run] of cases) {
      const [e] = await run();
      expect(allowed.has(e!.reason), `reason ${e!.reason} is a known coarse category`).toBe(true);
    }
  });
});
