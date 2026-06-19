/**
 * QA adapter contract suite — the real `IngestDeps` implementations + HTTP wrapper (slice 4c).
 *
 * Additive to DEV's ingest-adapter.test.ts. Asserts the behavioral + data-integrity properties QA owns
 * across the AD-conditions, end-to-end through the HTTP handler where it matters:
 *   · AD2 HMAC verify accepts a genuine signature and fails CLOSED on tamper / wrong / missing secret;
 *   · AD5 geo is country-only by default, region only when configured AND not suppressed, raw IP never out;
 *   · AD6 bounded retry; and a write failure surfaces as an OPAQUE 500 through the HTTP wrapper;
 *   · AD1 transport byte-cap; 429 carries Retry-After; opaque bodies;
 *   · limiter functional correctness (per-client/per-IP/ceiling/window-reset/fail-open-closed).
 *
 * Findings pinned as living tests (see [F-…] tags): F-LIMITER-EVICT (SEC's blocking finding) is now FIXED
 * by DEV (`aa56d75`) and proven here via the `bucketCount()` seam; F-WRITE-DEDUP remains a non-blocking
 * data-integrity gap. This suite is QA's acceptance evidence for the 4c gate; the formal QA verdict still
 * follows SEC's re-confirm of the limiter fix (pipeline order).
 */
import { describe, it, expect, vi } from "vitest";
import { createHmac } from "node:crypto";
import {
  makeHmacVerifier,
  createInMemoryRateLimiter,
  createCoarseGeo,
  makeBqInsert,
  createIngestHttpHandler,
  canonicalEnvelope,
  type AdapterDeps,
} from "./index.js";
import { DEFAULT_ALLOWLIST } from "./index.js";

const SECRET = "shared-app-secret";
const envelope = {
  client_id: "win-3f2a",
  user_id: null,
  platform: "windows",
  app_version: "2.2.0+27",
  consent: true,
  sent_at: "2023-11-14T22:13:20.000Z",
  events: [{ name: "app_open", ts: "2026-06-18T00:00:00Z" }],
};
function sign(body: Record<string, unknown>, secret: string): string {
  return "hmac-sha256:" + createHmac("sha256", secret).update(canonicalEnvelope(body)).digest("base64");
}

describe("AD2 — makeHmacVerifier (constant-time, fail-closed)", () => {
  const verify = makeHmacVerifier(() => SECRET);
  it("accepts a genuinely-signed body", async () => {
    expect(await verify({ ...envelope, sig: sign(envelope, SECRET) })).toBe(true);
  });
  it("rejects a tampered body (signature no longer matches)", async () => {
    const sig = sign(envelope, SECRET);
    expect(await verify({ ...envelope, consent: false, sig })).toBe(false);
  });
  it("rejects a signature made with the wrong secret", async () => {
    expect(await verify({ ...envelope, sig: sign(envelope, "other") })).toBe(false);
  });
  it("fails CLOSED when no secret resolves", async () => {
    const noSecret = makeHmacVerifier(() => undefined);
    expect(await noSecret({ ...envelope, sig: sign(envelope, SECRET) })).toBe(false);
  });
  it("rejects a missing/non-string sig", async () => {
    expect(await verify({ ...envelope })).toBe(false);
  });
});

describe("AD5 — createCoarseGeo (country-only default; raw IP never returned)", () => {
  it("returns country-only when no region lookup is configured", () => {
    const geo = createCoarseGeo({ lookupCountry: () => "US" })("203.0.113.7");
    expect(geo).toEqual({ country: "US", region: null });
  });
  it("returns null for no IP and for unknown country", () => {
    expect(createCoarseGeo({ lookupCountry: () => "US" })(undefined)).toBeNull();
    expect(createCoarseGeo({ lookupCountry: () => null })("203.0.113.7")).toBeNull();
  });
  it("includes region only when configured AND not suppressed (k-anon floor)", () => {
    const withRegion = createCoarseGeo({ lookupCountry: () => "US", lookupRegion: () => "CA" });
    expect(withRegion("203.0.113.7")).toEqual({ country: "US", region: "CA" });
    const suppressed = createCoarseGeo({ lookupCountry: () => "US", lookupRegion: () => "WY", regionSuppressed: () => true });
    expect(suppressed("203.0.113.7")).toEqual({ country: "US", region: null });
  });
  it("never returns a raw-IP key (only country/region) — DOMAIN LAW 1", () => {
    const geo = createCoarseGeo({ lookupCountry: () => "US" })("203.0.113.7");
    expect(Object.keys(geo ?? {}).sort()).toEqual(["country", "region"]);
  });
});

describe("AD6 — makeBqInsert bounded retry", () => {
  it("succeeds without retry on a healthy writer", async () => {
    const insertRows = vi.fn(async () => {});
    await makeBqInsert({ insertRows })([]);
    expect(insertRows).toHaveBeenCalledTimes(1);
  });
  it("retries a transient failure then succeeds", async () => {
    let n = 0;
    const insertRows = vi.fn(async () => { if (n++ === 0) throw new Error("transient"); });
    await makeBqInsert({ insertRows }, { retries: 2 })([]);
    expect(insertRows).toHaveBeenCalledTimes(2);
  });
  it("throws after exhausting retries (retries+1 attempts)", async () => {
    const insertRows = vi.fn(async () => { throw new Error("down"); });
    await expect(makeBqInsert({ insertRows }, { retries: 2 })([])).rejects.toThrow("down");
    expect(insertRows).toHaveBeenCalledTimes(3);
  });

  // [F-WRITE-DEDUP — QA finding, non-blocking → DEV/adapter] makeBqInsert retries the SAME rows. If
  // writer.insertRows writes some rows then throws (a partial failure), the retry RE-INSERTS them →
  // duplicate events in BQ = metric poisoning (against the spirit of "never fabricate data"). Rows carry
  // no insertId, so BQ streaming best-effort dedup can't kick in. This test DOCUMENTS the double-write;
  // recommend the writer set a per-row insertId (stable hash) so retry is idempotent.
  it("[F-WRITE-DEDUP] documents that a partial-write-then-throw causes a duplicate re-insert on retry", async () => {
    const written: string[] = [];
    let attempt = 0;
    const insertRows = vi.fn(async (rows: { event_name: string }[]) => {
      written.push(...rows.map((r) => r.event_name));
      if (attempt++ === 0) throw new Error("partial"); // wrote, THEN failed
    });
    await makeBqInsert({ insertRows }, { retries: 1 })([{ event_name: "app_open" } as never]);
    expect(written).toEqual(["app_open", "app_open"]); // ← written twice (the data-integrity gap)
  });
});

function httpDeps(over: Partial<AdapterDeps> = {}): AdapterDeps {
  return {
    now: () => 1_700_000_000_000,
    allowlist: DEFAULT_ALLOWLIST,
    verifyHmac: () => true,
    rateLimiter: { allow: () => true },
    replayCache: { checkAndRecord: () => true },
    deriveGeo: () => ({ country: "US", region: null }),
    bqInsert: vi.fn(),
    ...over,
  };
}
const wire = (body: unknown, headers: Record<string, string | undefined> = {}) => ({
  headers,
  rawBody: JSON.stringify(body),
  ip: "203.0.113.7",
});

describe("AD1 / HTTP wrapper — createIngestHttpHandler", () => {
  it("202 {ok:true} on the happy path, json content-type", async () => {
    const h = createIngestHttpHandler(httpDeps());
    const r = await h(wire({ ...envelope, sig: "hmac-sha256:x" }));
    expect(r.status).toBe(202);
    expect(JSON.parse(r.body)).toEqual({ ok: true });
    expect(r.headers["content-type"]).toBe("application/json");
  });
  it("413 on an oversized body before anything else (AD1)", async () => {
    const h = createIngestHttpHandler(httpDeps({ verifyHmac: vi.fn(() => true) }));
    const r = await h({ headers: {}, rawBody: "x".repeat(256 * 1024 + 1) });
    expect(r.status).toBe(413);
  });
  it("429 carries a Retry-After header", async () => {
    const h = createIngestHttpHandler(httpDeps({ rateLimiter: { allow: () => false } }));
    const r = await h(wire({ ...envelope, sig: "hmac-sha256:x" }));
    expect(r.status).toBe(429);
    expect(r.headers["retry-after"]).toBeDefined();
  });
  it("maps a write failure to an OPAQUE 500 (no detail leaked, §6)", async () => {
    const bqInsert = vi.fn(async () => { throw new Error("bq exploded with secret detail"); });
    const h = createIngestHttpHandler(httpDeps({ bqInsert }));
    const r = await h(wire({ ...envelope, sig: "hmac-sha256:x" }));
    expect(r.status).toBe(500);
    expect(r.body).not.toMatch(/secret detail/);
    expect(JSON.parse(r.body)).toEqual({ error: "internal" });
  });
  it("AD3: async App-Check token is pre-verified; invalid token → 401", async () => {
    const h = createIngestHttpHandler(
      httpDeps({ verifyHmac: () => false, verifyAppCheckToken: async () => false }),
    );
    const r = await h(wire(envelope, { "x-firebase-appcheck": "bad" }));
    expect(r.status).toBe(401);
  });
});

describe("C3/AD4 — limiter functional behavior", () => {
  it("allows under the per-client limit, denies over it", () => {
    const rl = createInMemoryRateLimiter({ now: () => 0, perClient: 2 });
    expect(rl.allow("c1", "ip1", true)).toBe(true);
    expect(rl.allow("c1", "ip1", true)).toBe(true);
    expect(rl.allow("c1", "ip1", true)).toBe(false); // 3rd over perClient=2
  });
  it("resets after the window elapses", () => {
    let t = 0;
    const rl = createInMemoryRateLimiter({ now: () => t, perClient: 1, windowMs: 1000 });
    expect(rl.allow("c1", "ip1", true)).toBe(true);
    expect(rl.allow("c1", "ip1", true)).toBe(false);
    t = 1000; // window elapsed
    expect(rl.allow("c1", "ip1", true)).toBe(true);
  });
  it("fails CLOSED for unauth and OPEN-under-ceiling for auth on store outage", () => {
    const rl = createInMemoryRateLimiter({ now: () => 0, storeAvailable: () => false, globalCeiling: 2 });
    expect(rl.allow("c1", "ip1", false)).toBe(false); // unauth → closed
    expect(rl.allow("c1", "ip1", true)).toBe(true); // auth → open…
    expect(rl.allow("c1", "ip1", true)).toBe(true);
    expect(rl.allow("c1", "ip1", true)).toBe(false); // …but under the global ceiling=2
  });

  // [F-LIMITER-EVICT — SEC blocking finding, FIXED by DEV @ aa56d75] The buckets Map used to grow
  // unbounded on forgeable client_id/IP = memory-DoS, and was untestable through {allow} — which is why
  // no test caught it. DEV's fix sweeps dead buckets ≤1×/window AND exposes `bucketCount()` (the
  // observability seam QA required). This is the regression that proves the bound holds — and that it has
  // teeth: against the pre-fix limiter (no sweep) bucketCount would stay ~2000, failing this assertion.
  it("[F-LIMITER-EVICT] sweeps expired buckets so memory stays bounded under key rotation", () => {
    let t = 0;
    const rl = createInMemoryRateLimiter({ now: () => t, windowMs: 1000 });
    for (let i = 0; i < 2000; i++) rl.allow(`c${i}`, `ip${i}`, true); // 2000 distinct keys → ~4000 buckets
    expect(rl.bucketCount()).toBeGreaterThan(1000); // before any window elapses, they accumulate…
    t = 3000; // ≥2 windows later
    rl.allow("trigger", "trigger", true); // a later call triggers the sweep
    expect(rl.bucketCount()).toBeLessThan(50); // …then expired buckets are evicted (not ~4000)
  });
});
