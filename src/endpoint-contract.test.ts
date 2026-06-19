/**
 * QA endpoint contract suite — handleIngest security-ordering + opacity (Spec §5–§7).
 *
 * DEV's ingest.test.ts already asserts each pipeline stage and the happy path. This QA suite adds the
 * ORDERING and OPACITY invariants a per-stage test can miss — the properties that, if they regressed,
 * would still leave every existing test green while opening a real hole:
 *   · a request that fails authenticity must touch NOTHING downstream — no rate-limit token, and crucially
 *     no replay-nonce record (a forged sig must not be able to poison the cache / pre-block a victim's sig);
 *   · consent opacity is TOTAL — a no-consent request with a malformed body must still return the exact
 *     same opaque 202 as a well-formed one, so shape errors can't be used to probe consent state;
 *   · the App Check path now enforces §5.4 freshness + a token-keyed replay nonce too (A1/F4, audit #2).
 *
 * Mirrors DEV's mock-deps harness so the two suites stay comparable.
 */
import { describe, it, expect, vi } from "vitest";
import { handleIngest, PAST_WINDOW_MS, FUTURE_SKEW_MS, type IngestDeps, type IngestRequest } from "./ingest.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const NOW_MS = 1_700_000_000_000;
const validEnvelope = {
  client_id: "win-3f2a",
  user_id: null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: "2023-11-14T22:13:20.000Z",
  events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }],
  sig: "hmac-sha256:abc",
};

function makeDeps(overrides: Partial<IngestDeps> = {}): IngestDeps {
  return {
    now: () => NOW_MS,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: () => true,
    verifyAppCheck: () => true,
    rateLimiter: { allow: () => true },
    replayCache: { checkAndRecord: () => true },
    deriveGeo: () => ({ country: "US", region: null }),
    bqInsert: vi.fn(),
    ...overrides,
  };
}
function req(body: unknown, extra: Partial<IngestRequest> = {}): IngestRequest {
  return { rawBody: JSON.stringify(body), ip: "203.0.113.7", ...extra };
}

describe("endpoint — failed auth touches nothing downstream", () => {
  it("a forged sig (HMAC fail) does NOT touch the replay nonce, rate-limit, or write", async () => {
    const checkAndRecord = vi.fn(() => true);
    const allow = vi.fn(() => true);
    const bqInsert = vi.fn();
    const r = await handleIngest(
      req(validEnvelope),
      makeDeps({ verifyHmac: () => false, replayCache: { checkAndRecord }, rateLimiter: { allow }, bqInsert }),
    );
    expect(r.status).toBe(401);
    // The security-critical one: a forged request must not be able to seed/poison the nonce cache.
    expect(checkAndRecord).not.toHaveBeenCalled();
    expect(allow).not.toHaveBeenCalled(); // auth precedes rate limiting
    expect(bqInsert).not.toHaveBeenCalled();
  });

  it("the size cap (413) precedes authenticity — verifyHmac is never consulted", async () => {
    const verifyHmac = vi.fn(() => true);
    const oversized = JSON.stringify({ ...validEnvelope, pad: "x".repeat(256 * 1024) });
    const r = await handleIngest({ rawBody: oversized, ip: "203.0.113.7" }, makeDeps({ verifyHmac }));
    expect(r.status).toBe(413);
    expect(verifyHmac).not.toHaveBeenCalled();
  });
});

describe("endpoint — consent opacity is total (C4/D1)", () => {
  it("no-consent + MALFORMED body still returns 202, identical to no-consent + valid body", async () => {
    const bqInsert = vi.fn();
    // consent:false AND missing client_id (a 400-class shape error). Consent is checked BEFORE
    // validation, so the shape error must never surface — both return the same opaque 202.
    const malformed = await handleIngest(
      req({ ...validEnvelope, consent: false, client_id: undefined }),
      makeDeps({ bqInsert }),
    );
    const wellFormed = await handleIngest(req({ ...validEnvelope, consent: false }), makeDeps({ bqInsert }));
    expect(malformed).toEqual(wellFormed);
    expect(malformed.status).toBe(202);
    expect(bqInsert).not.toHaveBeenCalled();
  });

  it("a non-boolean consent ('true' string) is treated as non-consent → 202, no write", async () => {
    const bqInsert = vi.fn();
    const r = await handleIngest(req({ ...validEnvelope, consent: "true" }), makeDeps({ bqInsert }));
    expect(r.status).toBe(202);
    expect(bqInsert).not.toHaveBeenCalled();
  });
});

describe("endpoint — App Check path freshness + nonce (A1/F4 — SEC audit #2)", () => {
  it("[A1/F4] the App Check path NOW records a replay nonce keyed on the token (gap closed)", async () => {
    const checkAndRecord = vi.fn(() => true);
    const r = await handleIngest(
      req(validEnvelope, { appCheckToken: "tok" }),
      makeDeps({ verifyAppCheck: () => true, replayCache: { checkAndRecord } }),
    );
    expect(r.status).toBe(202);
    // The fix: App Check is now replay-protected in the CORE — the nonce is the App Check token itself,
    // expiry anchored to sent_at + PAST_WINDOW (one token ⇒ one envelope in the fresh band).
    expect(checkAndRecord).toHaveBeenCalledWith("ac:tok", Date.parse(validEnvelope.sent_at) + PAST_WINDOW_MS);
  });

  it("[A1/F4] a replayed App Check envelope (nonce already seen) → 401", async () => {
    const r = await handleIngest(
      req(validEnvelope, { appCheckToken: "tok" }),
      makeDeps({ verifyAppCheck: () => true, replayCache: { checkAndRecord: () => false } }),
    );
    expect(r.status).toBe(401);
  });

  it("[A1/F4] a stale / future sent_at on the App Check path → 401 (freshness now enforced on both paths)", async () => {
    const stale = { ...validEnvelope, sent_at: new Date(NOW_MS - (PAST_WINDOW_MS + 60_000)).toISOString() };
    const future = { ...validEnvelope, sent_at: new Date(NOW_MS + (FUTURE_SKEW_MS + 60_000)).toISOString() };
    expect((await handleIngest(req(stale, { appCheckToken: "tok" }), makeDeps({ verifyAppCheck: () => true }))).status).toBe(401);
    expect((await handleIngest(req(future, { appCheckToken: "tok" }), makeDeps({ verifyAppCheck: () => true }))).status).toBe(401);
  });

  it("[A1/F4] a missing sent_at on the App Check path fails CLOSED → 400 (never skipped)", async () => {
    const r = await handleIngest(
      req({ ...validEnvelope, sent_at: undefined }, { appCheckToken: "tok" }),
      makeDeps({ verifyAppCheck: () => true }),
    );
    expect(r.status).toBe(400);
  });
});
