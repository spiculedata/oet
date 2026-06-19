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
 *   · the App Check path does not consult the body-sig replay cache (pins SEC AD3 for the 4c adapter).
 *
 * Mirrors DEV's mock-deps harness so the two suites stay comparable.
 */
import { describe, it, expect, vi } from "vitest";
import { handleIngest, type IngestDeps, type IngestRequest } from "./ingest.js";
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
    replayCache: { seen: () => false, record: () => {} },
    deriveGeo: () => ({ country: "US", region: null }),
    bqInsert: vi.fn(),
    ...overrides,
  };
}
function req(body: unknown, extra: Partial<IngestRequest> = {}): IngestRequest {
  return { rawBody: JSON.stringify(body), ip: "203.0.113.7", ...extra };
}

describe("endpoint — failed auth touches nothing downstream", () => {
  it("a forged sig (HMAC fail) does NOT record a replay nonce, rate-limit, or write", async () => {
    const record = vi.fn();
    const seen = vi.fn(() => false);
    const allow = vi.fn(() => true);
    const bqInsert = vi.fn();
    const r = await handleIngest(
      req(validEnvelope),
      makeDeps({ verifyHmac: () => false, replayCache: { seen, record }, rateLimiter: { allow }, bqInsert }),
    );
    expect(r.status).toBe(401);
    // The security-critical one: a forged request must not be able to seed/poison the nonce cache.
    expect(record).not.toHaveBeenCalled();
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

describe("endpoint — App Check path & the replay-nonce gap (SEC AD3)", () => {
  it("[AD3] the App Check path does NOT consult the body-sig replay cache (adapter must add its own)", async () => {
    const seen = vi.fn(() => false);
    const record = vi.fn();
    const r = await handleIngest(
      req(validEnvelope, { appCheckToken: "tok" }),
      makeDeps({ verifyAppCheck: () => true, replayCache: { seen, record } }),
    );
    expect(r.status).toBe(202);
    // Documents the gap SEC flagged for 4c: App Check has no body nonce, so this path is replay-checked
    // only by whatever the adapter adds (AD3) — not here.
    expect(seen).not.toHaveBeenCalled();
    expect(record).not.toHaveBeenCalled();
  });
});
